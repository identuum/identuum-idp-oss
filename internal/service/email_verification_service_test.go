package service

// email_verification_service_test.go — unit tests for the OSS
// EmailVerificationService. Covered:
//
//   - resend: anti-enumeration (unknown email → no error, no events);
//   - resend: matching unverified user → token persisted + audit emitted;
//   - resend: already-verified user skipped silently;
//   - verify: bad / expired / consumed token → ErrEmailVerificationInvalidToken;
//   - verify: success → email_verified flipped + audit emitted;
//   - verify: idempotent on already-verified user;
//   - verify: replay attempt finds used_at != nil → rejected;
//   - secrets safety: raw token never in audit metadata.

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/crypto"
	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// ---------- fakes ----------

type fakeEmailVerificationRepo struct {
	rows       map[string]*domain.EmailVerification
	markCalled int
	mu         sync.Mutex
}

func newFakeEmailVerificationRepo() *fakeEmailVerificationRepo {
	return &fakeEmailVerificationRepo{rows: make(map[string]*domain.EmailVerification)}
}

func (r *fakeEmailVerificationRepo) Create(_ context.Context, ev *domain.EmailVerification) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	cp := *ev
	r.rows[ev.TokenHash] = &cp
	return nil
}
func (r *fakeEmailVerificationRepo) GetByTokenHash(_ context.Context, hash string) (*domain.EmailVerification, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	row, ok := r.rows[hash]
	if !ok {
		return nil, nil
	}
	return row, nil
}
func (r *fakeEmailVerificationRepo) MarkAsUsed(_ context.Context, hash string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.markCalled++
	row, ok := r.rows[hash]
	if !ok {
		return domain.ErrEmailVerificationAlreadyUsed
	}
	// P3-1/P3-2 class: mirror the real compare-and-set. Production carries
	// `AND used_at IS NULL`, so a row already burned matches zero rows and the
	// caller LOSES. A fake that overwrote used_at could never surface the race
	// its own service comment promises to prevent.
	if row.UsedAt != nil {
		return domain.ErrEmailVerificationAlreadyUsed
	}
	now := time.Now()
	row.UsedAt = &now
	return nil
}
func (r *fakeEmailVerificationRepo) DeleteExpired(context.Context) (int64, error) { return 0, nil }

// fakeVerificationNotifier is a capture stub for the
// EmailVerificationNotifier seam. Integrity note (audit finding T2):
// this seam is now REALLY wired in production — internal/runtime
// buildDeps injects service.SMTPNotifier when IDENTUUM_IDP_SMTP_* is
// configured, or the honest UnconfiguredEmailNotifier when not (never
// nil). The capture assertions below therefore describe live runtime
// behavior, and TestResendVerification_UnconfiguredNotifierIsHonest
// covers the other real runtime state.
type fakeVerificationNotifier struct {
	sends      int
	lastUserID uuid.UUID
	lastToken  string
}

func (n *fakeVerificationNotifier) SendVerificationEmail(_ context.Context, user *domain.User, raw string) error {
	n.sends++
	if user != nil {
		n.lastUserID = user.ID
	}
	n.lastToken = raw
	return nil
}

// ---------- tests ----------

func TestResendVerification_UnknownEmailIsNoOp(t *testing.T) {
	users := newFakeUserRepo()
	verifs := newFakeEmailVerificationRepo()
	rec := &fakeAuditRecorder{}
	svc := NewEmailVerificationService(users, verifs, nil, rec, EmailVerificationServiceOptions{})

	require.NoError(t, svc.ResendVerification(context.Background(), "absent@example.test"))
	assert.Empty(t, verifs.rows)
	assert.Empty(t, rec.snapshot())
}

// (c) With a wired notifier (as production now is when SMTP is
// configured) a resend REALLY invokes the send with the right
// recipient and the raw 64-hex token.
func TestResendVerification_MatchingUnverifiedPersists(t *testing.T) {
	user := newPasswordResetUser(t, "fresh@example.test")
	user.EmailVerified = false
	users := newFakeUserRepo(user)
	verifs := newFakeEmailVerificationRepo()
	notifier := &fakeVerificationNotifier{}
	rec := &fakeAuditRecorder{}
	svc := NewEmailVerificationService(users, verifs, notifier, rec, EmailVerificationServiceOptions{})

	require.NoError(t, svc.ResendVerification(context.Background(), "fresh@example.test"))
	require.Len(t, verifs.rows, 1)
	for _, row := range verifs.rows {
		assert.Equal(t, user.ID, row.UserID)
		assert.True(t, row.ExpiresAt.After(time.Now()))
	}
	require.Equal(t, 1, notifier.sends)
	assert.Equal(t, user.ID, notifier.lastUserID)
	// Token must be 64 hex chars.
	assert.Len(t, notifier.lastToken, 64)

	events := rec.snapshot()
	require.Len(t, events, 1)
	assert.Equal(t, string(domain.AuditEmailVerificationResent), events[0].Action)
	// Raw token must NEVER appear in audit metadata.
	for _, e := range events {
		for k, v := range e.Metadata {
			if s, ok := v.(string); ok {
				assert.False(t, strings.Contains(s, notifier.lastToken),
					"metadata key %q must not contain raw token", k)
			}
		}
	}
}

func TestResendVerification_AlreadyVerifiedSkipped(t *testing.T) {
	user := newPasswordResetUser(t, "verified@example.test")
	user.EmailVerified = true
	users := newFakeUserRepo(user)
	verifs := newFakeEmailVerificationRepo()
	rec := &fakeAuditRecorder{}
	svc := NewEmailVerificationService(users, verifs, nil, rec, EmailVerificationServiceOptions{})

	require.NoError(t, svc.ResendVerification(context.Background(), "verified@example.test"))
	assert.Empty(t, verifs.rows)
	assert.Empty(t, rec.snapshot())
}

func TestVerifyEmail_BadTokenIsInvalid(t *testing.T) {
	users := newFakeUserRepo()
	verifs := newFakeEmailVerificationRepo()
	svc := NewEmailVerificationService(users, verifs, nil, audit.NoopService{}, EmailVerificationServiceOptions{})

	err := svc.VerifyEmail(context.Background(), "nope", "", "")
	assert.ErrorIs(t, err, ErrEmailVerificationInvalidToken)
}

func TestVerifyEmail_EmptyTokenIsInvalid(t *testing.T) {
	svc := NewEmailVerificationService(newFakeUserRepo(), newFakeEmailVerificationRepo(), nil, audit.NoopService{}, EmailVerificationServiceOptions{})
	err := svc.VerifyEmail(context.Background(), "", "", "")
	assert.ErrorIs(t, err, ErrEmailVerificationInvalidToken)
}

func TestVerifyEmail_ExpiredIsInvalid(t *testing.T) {
	user := newPasswordResetUser(t, "stale@example.test")
	users := newFakeUserRepo(user)
	verifs := newFakeEmailVerificationRepo()
	raw, err := crypto.GenerateRandomString(32)
	require.NoError(t, err)
	hash := crypto.HashToken(raw)
	verifs.rows[hash] = &domain.EmailVerification{
		UserID:    user.ID,
		TokenHash: hash,
		ExpiresAt: time.Now().Add(-time.Hour),
	}
	svc := NewEmailVerificationService(users, verifs, nil, audit.NoopService{}, EmailVerificationServiceOptions{})

	verifyErr := svc.VerifyEmail(context.Background(), raw, "", "")
	assert.ErrorIs(t, verifyErr, ErrEmailVerificationInvalidToken)
}

func TestVerifyEmail_ConsumedTokenIsInvalid(t *testing.T) {
	user := newPasswordResetUser(t, "consumed@example.test")
	users := newFakeUserRepo(user)
	verifs := newFakeEmailVerificationRepo()
	raw, err := crypto.GenerateRandomString(32)
	require.NoError(t, err)
	hash := crypto.HashToken(raw)
	usedAt := time.Now()
	verifs.rows[hash] = &domain.EmailVerification{
		UserID:    user.ID,
		TokenHash: hash,
		ExpiresAt: time.Now().Add(time.Hour),
		UsedAt:    &usedAt,
	}
	svc := NewEmailVerificationService(users, verifs, nil, audit.NoopService{}, EmailVerificationServiceOptions{})

	verifyErr := svc.VerifyEmail(context.Background(), raw, "", "")
	assert.ErrorIs(t, verifyErr, ErrEmailVerificationInvalidToken)
}

func TestVerifyEmail_HappyPathFlipsFlag(t *testing.T) {
	user := newPasswordResetUser(t, "verify@example.test")
	user.EmailVerified = false
	users := newFakeUserRepo(user)
	verifs := newFakeEmailVerificationRepo()
	rec := &fakeAuditRecorder{}
	raw, err := crypto.GenerateRandomString(32)
	require.NoError(t, err)
	hash := crypto.HashToken(raw)
	verifs.rows[hash] = &domain.EmailVerification{
		UserID:    user.ID,
		TokenHash: hash,
		ExpiresAt: time.Now().Add(time.Hour),
	}
	svc := NewEmailVerificationService(users, verifs, nil, rec, EmailVerificationServiceOptions{})

	require.NoError(t, svc.VerifyEmail(context.Background(), raw, "10.0.0.1", "ua"))

	assert.Equal(t, 1, verifs.markCalled, "MarkAsUsed must run before EmailVerified update")
	require.Equal(t, 1, users.updates)
	require.NotNil(t, users.lastOpts.EmailVerified)
	assert.True(t, *users.lastOpts.EmailVerified)

	events := rec.snapshot()
	require.Len(t, events, 1)
	assert.Equal(t, string(domain.AuditEmailVerified), events[0].Action)
}

func TestVerifyEmail_IdempotentOnAlreadyVerified(t *testing.T) {
	user := newPasswordResetUser(t, "already@example.test")
	user.EmailVerified = true
	users := newFakeUserRepo(user)
	verifs := newFakeEmailVerificationRepo()
	rec := &fakeAuditRecorder{}
	raw, err := crypto.GenerateRandomString(32)
	require.NoError(t, err)
	hash := crypto.HashToken(raw)
	verifs.rows[hash] = &domain.EmailVerification{
		UserID:    user.ID,
		TokenHash: hash,
		ExpiresAt: time.Now().Add(time.Hour),
	}
	svc := NewEmailVerificationService(users, verifs, nil, rec, EmailVerificationServiceOptions{})

	require.NoError(t, svc.VerifyEmail(context.Background(), raw, "", ""))
	// Already verified → no Update, no audit event.
	assert.Equal(t, 0, users.updates)
	assert.Empty(t, rec.snapshot())
}

func TestVerifyEmail_DeletedUserRejected(t *testing.T) {
	user := newPasswordResetUser(t, "deleted@example.test")
	t0 := time.Now()
	user.DeletedAt = &t0
	users := newFakeUserRepo(user)
	verifs := newFakeEmailVerificationRepo()
	raw, err := crypto.GenerateRandomString(32)
	require.NoError(t, err)
	hash := crypto.HashToken(raw)
	verifs.rows[hash] = &domain.EmailVerification{
		UserID:    user.ID,
		TokenHash: hash,
		ExpiresAt: time.Now().Add(time.Hour),
	}
	svc := NewEmailVerificationService(users, verifs, nil, audit.NoopService{}, EmailVerificationServiceOptions{})
	verifyErr := svc.VerifyEmail(context.Background(), raw, "", "")
	assert.ErrorIs(t, verifyErr, ErrEmailVerificationInvalidToken)
}

func TestIssueInitialVerification_PersistsAndReturnsRawToken(t *testing.T) {
	user := newPasswordResetUser(t, "issue@example.test")
	users := newFakeUserRepo(user)
	verifs := newFakeEmailVerificationRepo()
	notifier := &fakeVerificationNotifier{}
	svc := NewEmailVerificationService(users, verifs, notifier, audit.NoopService{}, EmailVerificationServiceOptions{})

	raw, err := svc.IssueInitialVerification(context.Background(), user)
	require.NoError(t, err)
	assert.Len(t, raw, 64)
	require.Len(t, verifs.rows, 1)
	require.Equal(t, 1, notifier.sends)
	assert.Equal(t, raw, notifier.lastToken)
}

func TestIssueInitialVerification_AlreadyVerifiedReturnsEmpty(t *testing.T) {
	user := newPasswordResetUser(t, "skip@example.test")
	user.EmailVerified = true
	svc := NewEmailVerificationService(newFakeUserRepo(user), newFakeEmailVerificationRepo(), nil, audit.NoopService{}, EmailVerificationServiceOptions{})
	raw, err := svc.IssueInitialVerification(context.Background(), user)
	require.NoError(t, err)
	assert.Empty(t, raw)
}
