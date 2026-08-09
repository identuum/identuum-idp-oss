package service

// password_reset_service_test.go — unit tests for the OSS
// PasswordResetService. Covered:
//
//   - request: anti-enumeration (unknown email → no error, no audit);
//   - request: matching user → token persisted, hash matches SHA-256,
//     audit event emitted, raw token never appears in metadata;
//   - request: banned / deleted users silently skipped;
//   - reset: bad token → ErrPasswordResetInvalidToken;
//   - reset: expired token → ErrPasswordResetInvalidToken;
//   - reset: already-used token → ErrPasswordResetInvalidToken (replay);
//   - reset: weak password → ErrPasswordResetWeakPassword;
//   - reset: success → password updated, sessions revoked, audit emitted;
//   - reset: missing user → ErrPasswordResetInvalidToken;
//   - secrets safety: raw token never in audit metadata.

import (
	"context"
	"errors"
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
	"github.com/identuum/identuum-idp-oss/internal/repository"
)

// ---------- fakes ----------

type fakeUserRepo struct {
	byID      map[uuid.UUID]*domain.User
	byEmail   map[string][]*domain.User
	updates   int
	lastOpts  repository.UpdateUserOptions
	updateErr error
}

func newFakeUserRepo(users ...*domain.User) *fakeUserRepo {
	r := &fakeUserRepo{byID: make(map[uuid.UUID]*domain.User), byEmail: make(map[string][]*domain.User)}
	for _, u := range users {
		r.byID[u.ID] = u
		r.byEmail[strings.ToLower(u.Email)] = append(r.byEmail[strings.ToLower(u.Email)], u)
	}
	return r
}

func (r *fakeUserRepo) GetByID(_ context.Context, id uuid.UUID) (*domain.User, error) {
	if u, ok := r.byID[id]; ok {
		return u, nil
	}
	return nil, domain.ErrUserNotFound
}

func (r *fakeUserRepo) GetByIDWithOrg(_ context.Context, id uuid.UUID) (*domain.User, error) {
	if u, ok := r.byID[id]; ok {
		return u, nil
	}
	return nil, domain.ErrUserNotFound
}

func (r *fakeUserRepo) FindUsersByEmail(_ context.Context, email string) ([]*domain.User, error) {
	return r.byEmail[strings.ToLower(email)], nil
}

func (r *fakeUserRepo) Update(_ context.Context, id, _ uuid.UUID, opts repository.UpdateUserOptions) (*domain.User, error) {
	r.updates++
	r.lastOpts = opts
	if r.updateErr != nil {
		return nil, r.updateErr
	}
	u := r.byID[id]
	if u == nil {
		return nil, domain.ErrUserNotFound
	}
	if opts.Password != nil {
		u.PasswordHash = "$argon2id$test$" + *opts.Password
	}
	if opts.EmailVerified != nil {
		u.EmailVerified = *opts.EmailVerified
	}
	if opts.ActivationTokenHash != nil {
		s := *opts.ActivationTokenHash
		if s == "" {
			u.ActivationTokenHash = nil
		} else {
			u.ActivationTokenHash = &s
		}
	}
	if opts.ActivationTokenExpiresAt != nil {
		t := *opts.ActivationTokenExpiresAt
		u.ActivationTokenExpiresAt = &t
	}
	return u, nil
}

// ConsumeActivationToken models the P0-10 atomic claim: clears the activation
// token + sets password/email_verified ONLY while the hash still matches.
func (r *fakeUserRepo) ConsumeActivationToken(_ context.Context, activationTokenHash, newPasswordHash string) (*domain.User, bool, error) {
	for _, u := range r.byID {
		if u.ActivationTokenHash != nil && *u.ActivationTokenHash == activationTokenHash {
			u.ActivationTokenHash = nil
			u.PasswordHash = newPasswordHash
			u.EmailVerified = true
			cp := *u
			return &cp, true, nil
		}
	}
	return nil, false, nil // not claimable (already consumed / unknown)
}

// FindByActivationTokenHash is implemented for cross-test reuse by
// the activation tests in this package; the password-reset paths
// don't call it.
func (r *fakeUserRepo) FindByActivationTokenHash(_ context.Context, hash string) (*domain.User, error) {
	for _, u := range r.byID {
		if u.ActivationTokenHash != nil && *u.ActivationTokenHash == hash {
			return u, nil
		}
	}
	return nil, nil
}

// ListByOrganization filters the fake's rows by org — added for the
// activation-resend path, which enumerates an org's users to find the
// pending org_admin.
func (r *fakeUserRepo) ListByOrganization(_ context.Context, orgID uuid.UUID, _ repository.ListUserOptions) ([]*domain.User, int, error) {
	out := make([]*domain.User, 0)
	for _, u := range r.byID {
		if u != nil && u.OrganizationID == orgID {
			out = append(out, u)
		}
	}
	return out, len(out), nil
}

// Create / FindByEmail-not-tested stubs intentionally minimal —
// the activation + claim tests reuse the same fake.
func (r *fakeUserRepo) Create(_ context.Context, u *domain.User) (*domain.User, error) {
	if r.byID == nil {
		r.byID = make(map[uuid.UUID]*domain.User)
	}
	if u.ID == uuid.Nil {
		u.ID = uuid.New()
	}
	r.byID[u.ID] = u
	if r.byEmail == nil {
		r.byEmail = make(map[string][]*domain.User)
	}
	r.byEmail[strings.ToLower(u.Email)] = append(r.byEmail[strings.ToLower(u.Email)], u)
	return u, nil
}

// fakePasswordResetRepo
type fakePasswordResetRepo struct {
	rows       map[string]*domain.PasswordReset
	createErr  error
	markErr    error
	markCalled int
}

func newFakePasswordResetRepo() *fakePasswordResetRepo {
	return &fakePasswordResetRepo{rows: make(map[string]*domain.PasswordReset)}
}

func (r *fakePasswordResetRepo) Create(_ context.Context, reset *domain.PasswordReset) error {
	if r.createErr != nil {
		return r.createErr
	}
	cp := *reset
	r.rows[reset.TokenHash] = &cp
	return nil
}

func (r *fakePasswordResetRepo) GetByTokenHash(_ context.Context, hash string) (*domain.PasswordReset, error) {
	row, ok := r.rows[hash]
	if !ok {
		return nil, nil
	}
	return row, nil
}

func (r *fakePasswordResetRepo) MarkAsUsed(_ context.Context, hash string) error {
	r.markCalled++
	if r.markErr != nil {
		return r.markErr
	}
	if row, ok := r.rows[hash]; ok {
		now := time.Now().UTC()
		row.UsedAt = &now
	}
	return nil
}

// ClaimPasswordReset models the P0-9 atomic claim: marks the token used ONLY
// while unused + unexpired, returning the user_id + ok. (The fake does not write
// the user password — the real password write is covered by the integration
// test.)
func (r *fakePasswordResetRepo) ClaimPasswordReset(_ context.Context, hash, _ string) (uuid.UUID, bool, error) {
	r.markCalled++
	if r.markErr != nil {
		return uuid.Nil, false, r.markErr
	}
	row, ok := r.rows[hash]
	now := time.Now().UTC()
	if !ok || row.UsedAt != nil || !row.ExpiresAt.After(now) {
		return uuid.Nil, false, nil // already used / expired / unknown
	}
	row.UsedAt = &now
	return row.UserID, true, nil
}

func (r *fakePasswordResetRepo) DeleteExpired(context.Context) (int64, error) { return 0, nil }

// fake session revoker
type fakeSessionRevoker struct {
	revokes int
	userIDs []uuid.UUID
	reasons []string
	mu      sync.Mutex
}

func (r *fakeSessionRevoker) RevokeByUserID(_ context.Context, id uuid.UUID, reason string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.revokes++
	r.userIDs = append(r.userIDs, id)
	r.reasons = append(r.reasons, reason)
	return nil
}

// fake refresh-token revoker — mirrors fakeSessionRevoker but for
// the parallel passwordResetRefreshTokenRevoker seam.
type fakeRefreshTokenRevoker struct {
	mu      sync.Mutex
	calls   int
	userIDs []uuid.UUID
	count   int64
	err     error
}

func (r *fakeRefreshTokenRevoker) RevokeAllForUser(_ context.Context, id uuid.UUID) (int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	r.userIDs = append(r.userIDs, id)
	return r.count, r.err
}

// fake notifier
type fakePasswordResetNotifier struct {
	sends      int
	lastLink   string
	failNext   bool
	lastUserID uuid.UUID
}

func (n *fakePasswordResetNotifier) SendPasswordResetEmail(_ context.Context, user *domain.User, resetLink string) error {
	n.sends++
	n.lastLink = resetLink
	if user != nil {
		n.lastUserID = user.ID
	}
	if n.failNext {
		n.failNext = false
		return errors.New("smtp")
	}
	return nil
}

// audit recorder
type fakeAuditRecorder struct {
	mu     sync.Mutex
	events []audit.Event
}

func (r *fakeAuditRecorder) Record(_ context.Context, e audit.Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
	return nil
}

func (r *fakeAuditRecorder) snapshot() []audit.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]audit.Event, len(r.events))
	copy(out, r.events)
	return out
}

// ---------- fixtures ----------

func newPasswordResetUser(t *testing.T, email string) *domain.User {
	t.Helper()
	id, err := uuid.NewV7()
	require.NoError(t, err)
	return &domain.User{
		ID:             id,
		Email:          email,
		OrganizationID: uuid.New(),
		Role:           domain.RoleOrgUser,
		AuthSource:     domain.AuthSourceLocal,
	}
}

// ---------- tests ----------

func TestRequestPasswordReset_UnknownEmailIsNoOp(t *testing.T) {
	users := newFakeUserRepo()
	resets := newFakePasswordResetRepo()
	rec := &fakeAuditRecorder{}
	svc := NewPasswordResetService(PasswordResetServiceConfig{Users: users, Resets: resets, Audit: rec})

	err := svc.RequestPasswordReset(context.Background(), "unknown@example.test", "10.0.0.1", "test-agent")
	assert.NoError(t, err)
	assert.Empty(t, resets.rows, "no rows persisted")
	assert.Empty(t, rec.snapshot(), "no audit event for unknown email")
}

func TestRequestPasswordReset_EmptyEmailIsNoOp(t *testing.T) {
	users := newFakeUserRepo()
	resets := newFakePasswordResetRepo()
	rec := &fakeAuditRecorder{}
	svc := NewPasswordResetService(PasswordResetServiceConfig{Users: users, Resets: resets, Audit: rec})

	require.NoError(t, svc.RequestPasswordReset(context.Background(), "", "", ""))
	require.NoError(t, svc.RequestPasswordReset(context.Background(), "   ", "", ""))
	assert.Empty(t, resets.rows)
	assert.Empty(t, rec.snapshot())
}

func TestRequestPasswordReset_MatchingUserPersistsHash(t *testing.T) {
	user := newPasswordResetUser(t, "match@example.test")
	users := newFakeUserRepo(user)
	resets := newFakePasswordResetRepo()
	notifier := &fakePasswordResetNotifier{}
	rec := &fakeAuditRecorder{}
	svc := NewPasswordResetService(PasswordResetServiceConfig{
		Users:              users,
		Resets:             resets,
		Notifier:           notifier,
		Audit:              rec,
		HumanFacingBaseURL: "https://ui.example.test",
	})

	require.NoError(t, svc.RequestPasswordReset(context.Background(), "match@example.test", "ip", "ua"))
	require.Len(t, resets.rows, 1)
	for hash, row := range resets.rows {
		assert.Equal(t, hash, row.TokenHash)
		// hash must be hex SHA-256 (64 chars)
		assert.Len(t, hash, 64)
		assert.Equal(t, user.ID, row.UserID)
	}
	require.Equal(t, 1, notifier.sends)
	assert.Equal(t, user.ID, notifier.lastUserID)
	assert.Contains(t, notifier.lastLink, "https://ui.example.test/reset-password?token=")
	// Token in URL must be 64 hex chars (32-byte hex)
	parts := strings.Split(notifier.lastLink, "?token=")
	require.Len(t, parts, 2)
	assert.Len(t, parts[1], 64)

	events := rec.snapshot()
	require.Len(t, events, 1)
	assert.Equal(t, string(domain.AuditUserPasswordResetRequested), events[0].Action)
	assert.Equal(t, user.ID, events[0].SubjectID)

	// Raw token MUST NOT appear in any audit metadata value.
	rawToken := parts[1]
	for _, e := range events {
		for k, v := range e.Metadata {
			if s, ok := v.(string); ok {
				assert.NotEqual(t, rawToken, s, "metadata key %q must not carry raw token", k)
				assert.False(t, strings.Contains(s, rawToken), "metadata key %q must not contain raw token", k)
			}
		}
	}
}

func TestRequestPasswordReset_BannedAndDeletedSkipped(t *testing.T) {
	banned := newPasswordResetUser(t, "banned@example.test")
	banned.Banned = true
	deletedTS := time.Now()
	deleted := newPasswordResetUser(t, "banned@example.test")
	deleted.DeletedAt = &deletedTS
	users := newFakeUserRepo(banned, deleted)
	resets := newFakePasswordResetRepo()
	notifier := &fakePasswordResetNotifier{}
	rec := &fakeAuditRecorder{}
	svc := NewPasswordResetService(PasswordResetServiceConfig{
		Users:    users,
		Resets:   resets,
		Notifier: notifier,
		Audit:    rec,
	})

	require.NoError(t, svc.RequestPasswordReset(context.Background(), "banned@example.test", "", ""))
	assert.Empty(t, resets.rows)
	assert.Equal(t, 0, notifier.sends)
	assert.Empty(t, rec.snapshot())
}

func TestResetPassword_BadTokenIsInvalid(t *testing.T) {
	users := newFakeUserRepo()
	resets := newFakePasswordResetRepo()
	svc := NewPasswordResetService(PasswordResetServiceConfig{Users: users, Resets: resets, Audit: audit.NoopService{}})

	err := svc.ResetPassword(context.Background(), ResetPasswordInput{Token: "no-such-token", NewPassword: "Longenough-pw-1!"})
	assert.ErrorIs(t, err, ErrPasswordResetInvalidToken)
}

func TestResetPassword_WeakPasswordRejected(t *testing.T) {
	users := newFakeUserRepo()
	resets := newFakePasswordResetRepo()
	svc := NewPasswordResetService(PasswordResetServiceConfig{
		Users:             users,
		Resets:            resets,
		Audit:             audit.NoopService{},
		MinPasswordLength: 8,
	})

	err := svc.ResetPassword(context.Background(), ResetPasswordInput{Token: "tok", NewPassword: "short"})
	assert.ErrorIs(t, err, ErrPasswordResetWeakPassword)
}

func TestResetPassword_ExpiredIsInvalid(t *testing.T) {
	user := newPasswordResetUser(t, "exp@example.test")
	users := newFakeUserRepo(user)
	resets := newFakePasswordResetRepo()
	rawToken, err := crypto.GenerateRandomString(32)
	require.NoError(t, err)
	hash := crypto.HashToken(rawToken)
	resets.rows[hash] = &domain.PasswordReset{
		UserID:    user.ID,
		TokenHash: hash,
		ExpiresAt: time.Now().Add(-time.Hour), // already expired
		CreatedAt: time.Now().Add(-2 * time.Hour),
	}
	svc := NewPasswordResetService(PasswordResetServiceConfig{Users: users, Resets: resets, Audit: audit.NoopService{}})

	resetErr := svc.ResetPassword(context.Background(), ResetPasswordInput{Token: rawToken, NewPassword: "Longenough-pw-1!"})
	assert.ErrorIs(t, resetErr, ErrPasswordResetInvalidToken)
}

func TestResetPassword_ReplayAfterUsedIsInvalid(t *testing.T) {
	user := newPasswordResetUser(t, "replay@example.test")
	users := newFakeUserRepo(user)
	resets := newFakePasswordResetRepo()
	rawToken, err := crypto.GenerateRandomString(32)
	require.NoError(t, err)
	hash := crypto.HashToken(rawToken)
	usedAt := time.Now().Add(-time.Minute)
	resets.rows[hash] = &domain.PasswordReset{
		UserID:    user.ID,
		TokenHash: hash,
		ExpiresAt: time.Now().Add(time.Hour),
		CreatedAt: time.Now().Add(-time.Minute),
		UsedAt:    &usedAt,
	}
	svc := NewPasswordResetService(PasswordResetServiceConfig{Users: users, Resets: resets, Audit: audit.NoopService{}})
	resetErr := svc.ResetPassword(context.Background(), ResetPasswordInput{Token: rawToken, NewPassword: "Longenough-pw-1!"})
	assert.ErrorIs(t, resetErr, ErrPasswordResetInvalidToken)
}

func TestResetPassword_HappyPathRevokesSessionsAndAudits(t *testing.T) {
	user := newPasswordResetUser(t, "happy@example.test")
	users := newFakeUserRepo(user)
	resets := newFakePasswordResetRepo()
	rev := &fakeSessionRevoker{}
	rec := &fakeAuditRecorder{}
	rawToken, err := crypto.GenerateRandomString(32)
	require.NoError(t, err)
	hash := crypto.HashToken(rawToken)
	resets.rows[hash] = &domain.PasswordReset{
		UserID:    user.ID,
		TokenHash: hash,
		ExpiresAt: time.Now().Add(time.Hour),
		CreatedAt: time.Now(),
	}
	svc := NewPasswordResetService(PasswordResetServiceConfig{Users: users, Resets: resets, Sessions: rev, Audit: rec})
	require.NoError(t, svc.ResetPassword(context.Background(), ResetPasswordInput{Token: rawToken, NewPassword: "Longenough-pw-1!"}))

	// P0-9: the token consume + password write are now one atomic claim
	// (ClaimPasswordReset). markCalled tracks that claim; the password write
	// itself is bound into the same transaction and verified by the integration
	// concurrency test.
	assert.Equal(t, 1, resets.markCalled, "the atomic claim must run exactly once")
	require.Equal(t, 1, rev.revokes)
	assert.Equal(t, "password_reset", rev.reasons[0])
	assert.Equal(t, user.ID, rev.userIDs[0])

	events := rec.snapshot()
	require.Len(t, events, 1)
	assert.Equal(t, string(domain.AuditUserPasswordResetCompleted), events[0].Action)
	assert.Equal(t, user.ID, events[0].SubjectID)
}

// P0-9 ordering: a policy-invalid password is rejected BEFORE the token is
// consumed, so a valid reset link is never burned by a bad attempt — and a
// retry with a valid password still works.
func TestResetPassword_PolicyInvalidDoesNotBurnToken(t *testing.T) {
	user := newPasswordResetUser(t, "noburn@example.test")
	users := newFakeUserRepo(user)
	resets := newFakePasswordResetRepo()
	rawToken, err := crypto.GenerateRandomString(32)
	require.NoError(t, err)
	hash := crypto.HashToken(rawToken)
	resets.rows[hash] = &domain.PasswordReset{
		UserID:    user.ID,
		TokenHash: hash,
		ExpiresAt: time.Now().Add(time.Hour),
		CreatedAt: time.Now(),
	}
	svc := NewPasswordResetService(PasswordResetServiceConfig{Users: users, Resets: resets, Audit: audit.NoopService{}})

	// Long enough to pass the length floor, but no complexity → policy reject.
	weakErr := svc.ResetPassword(context.Background(), ResetPasswordInput{Token: rawToken, NewPassword: "aaaaaaaaaaaaaaaa"})
	require.ErrorIs(t, weakErr, ErrPasswordResetWeakPassword)
	require.Equal(t, 0, resets.markCalled, "a policy-invalid password must NOT consume the token")
	require.Nil(t, resets.rows[hash].UsedAt, "the reset link must remain unused after a policy-invalid attempt")

	// Retry with a valid password succeeds and consumes the (still-valid) token.
	require.NoError(t, svc.ResetPassword(context.Background(), ResetPasswordInput{Token: rawToken, NewPassword: "Longenough-pw-1!"}))
	require.Equal(t, 1, resets.markCalled)
	require.NotNil(t, resets.rows[hash].UsedAt, "a successful reset must consume the token")
}

func TestResetPassword_MissingUserIsInvalid(t *testing.T) {
	users := newFakeUserRepo()
	resets := newFakePasswordResetRepo()
	rawToken, err := crypto.GenerateRandomString(32)
	require.NoError(t, err)
	hash := crypto.HashToken(rawToken)
	resets.rows[hash] = &domain.PasswordReset{
		UserID:    uuid.New(),
		TokenHash: hash,
		ExpiresAt: time.Now().Add(time.Hour),
		CreatedAt: time.Now(),
	}
	svc := NewPasswordResetService(PasswordResetServiceConfig{Users: users, Resets: resets, Audit: audit.NoopService{}})
	resetErr := svc.ResetPassword(context.Background(), ResetPasswordInput{Token: rawToken, NewPassword: "Longenough-pw-1!"})
	assert.ErrorIs(t, resetErr, ErrPasswordResetInvalidToken)
}

func TestResetPassword_InvokesRefreshTokenRevokerWhenWired(t *testing.T) {
	user := newPasswordResetUser(t, "refresh@example.test")
	users := newFakeUserRepo(user)
	resets := newFakePasswordResetRepo()
	rev := &fakeSessionRevoker{}
	refreshRev := &fakeRefreshTokenRevoker{count: 3}
	rec := &fakeAuditRecorder{}
	rawToken, err := crypto.GenerateRandomString(32)
	require.NoError(t, err)
	hash := crypto.HashToken(rawToken)
	resets.rows[hash] = &domain.PasswordReset{
		UserID:    user.ID,
		TokenHash: hash,
		ExpiresAt: time.Now().Add(time.Hour),
		CreatedAt: time.Now(),
	}
	svc := NewPasswordResetService(PasswordResetServiceConfig{Users: users, Resets: resets, Sessions: rev, Audit: rec}).
		WithRefreshTokenRevoker(refreshRev)
	require.NoError(t, svc.ResetPassword(context.Background(), ResetPasswordInput{Token: rawToken, NewPassword: "Longenough-pw-1!"}))

	require.Equal(t, 1, rev.revokes, "session revoker still fires")
	require.Equal(t, 1, refreshRev.calls, "refresh-token revoker fires exactly once on success")
	require.Equal(t, user.ID, refreshRev.userIDs[0])
	for _, e := range rec.snapshot() {
		for _, v := range e.Metadata {
			if s, ok := v.(string); ok {
				assert.NotContains(t, s, rawToken, "audit metadata leaked raw reset token")
				assert.NotContains(t, s, hash, "audit metadata leaked reset token hash")
			}
		}
	}
}

func TestResetPassword_RefreshTokenRevokerErrorIsSurfaced(t *testing.T) {
	user := newPasswordResetUser(t, "besteffort@example.test")
	users := newFakeUserRepo(user)
	resets := newFakePasswordResetRepo()
	rev := &fakeSessionRevoker{}
	refreshRev := &fakeRefreshTokenRevoker{err: errors.New("simulated outage")}
	rec := &fakeAuditRecorder{}
	rawToken, err := crypto.GenerateRandomString(32)
	require.NoError(t, err)
	hash := crypto.HashToken(rawToken)
	resets.rows[hash] = &domain.PasswordReset{
		UserID:    user.ID,
		TokenHash: hash,
		ExpiresAt: time.Now().Add(time.Hour),
		CreatedAt: time.Now(),
	}
	svc := NewPasswordResetService(PasswordResetServiceConfig{Users: users, Resets: resets, Sessions: rev, Audit: rec}).
		WithRefreshTokenRevoker(refreshRev)
	// P0-9: a revocation failure is now SURFACED (not swallowed) so the reset
	// never reports plain success while pre-existing tokens may survive. The
	// password change itself has already committed, so the completion audit
	// event still fires.
	resetErr := svc.ResetPassword(context.Background(), ResetPasswordInput{Token: rawToken, NewPassword: "Longenough-pw-1!"})
	require.ErrorIs(t, resetErr, ErrPasswordResetRevocationFailed,
		"a refresh-token revocation outage must be surfaced, not swallowed")
	require.Equal(t, 1, refreshRev.calls, "refresh-token revoker still attempted once on outage")
	events := rec.snapshot()
	var auditFound bool
	for _, e := range events {
		if e.Action == string(domain.AuditUserPasswordResetCompleted) {
			auditFound = true
		}
	}
	assert.True(t, auditFound, "completion audit event must still fire on a surfaced revoke failure")
}

func TestResetPassword_NoRefreshTokenRevokerWhenUnwired(t *testing.T) {
	user := newPasswordResetUser(t, "nowire@example.test")
	users := newFakeUserRepo(user)
	resets := newFakePasswordResetRepo()
	rev := &fakeSessionRevoker{}
	rec := &fakeAuditRecorder{}
	rawToken, err := crypto.GenerateRandomString(32)
	require.NoError(t, err)
	hash := crypto.HashToken(rawToken)
	resets.rows[hash] = &domain.PasswordReset{
		UserID:    user.ID,
		TokenHash: hash,
		ExpiresAt: time.Now().Add(time.Hour),
		CreatedAt: time.Now(),
	}
	// Deliberately do NOT call WithRefreshTokenRevoker: deployments
	// that have not wired RefreshTokenService must keep their
	// pre-this-slice session-only behaviour.
	svc := NewPasswordResetService(PasswordResetServiceConfig{Users: users, Resets: resets, Sessions: rev, Audit: rec})
	require.NoError(t, svc.ResetPassword(context.Background(), ResetPasswordInput{Token: rawToken, NewPassword: "Longenough-pw-1!"}))
	require.Equal(t, 1, rev.revokes, "session revoker still fires when refresh revoker absent")
}

func TestSetHumanFacingBaseURL_RuntimeUpdate(t *testing.T) {
	svc := NewPasswordResetService(PasswordResetServiceConfig{
		Users:  newFakeUserRepo(),
		Resets: newFakePasswordResetRepo(),
		Audit:  audit.NoopService{},
	})
	svc.SetHumanFacingBaseURL("https://later.example.test/")
	assert.Equal(t, "https://later.example.test", svc.BaseURL())
}
