package service

// OSS-0912-C2 (owner Q1 (a), Q2 (b), Q-C2-2 (a)): email_verified in tokens
// means the mailbox was proven. The verification email records the proof
// (email_link) and activates only an account that is not waiting for an
// invite or activation link; resends and the signed-in send skip only a
// proven mailbox; the id_token claim reads the proof.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/crypto"
	"github.com/identuum/identuum-idp-oss/internal/domain"
)

func c2Via(s string) *string { return &s }

// c2Now is the fixed clock the service runs on in these tests.
var c2Now = time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)

func c2Opts() EmailVerificationServiceOptions {
	return EmailVerificationServiceOptions{Now: func() time.Time { return c2Now }}
}

func c2Link(t *testing.T, verifs *fakeEmailVerificationRepo, user *domain.User) string {
	t.Helper()
	raw, err := crypto.GenerateRandomString(32)
	require.NoError(t, err)
	hash := crypto.HashToken(raw)
	verifs.rows[hash] = &domain.EmailVerification{UserID: user.ID, TokenHash: hash, AddressHash: domain.EmailAddressHash(user.Email), ExpiresAt: c2Now.Add(time.Hour)}
	return raw
}

func TestVerifyEmail_AdminActivatedUserRecordsTheProof(t *testing.T) {
	user := newPasswordResetUser(t, "admin-linked@example.test")
	user.EmailVerified = true
	user.EmailVerifiedVia = c2Via(domain.EmailVerifiedViaAdminLink)
	users := newFakeUserRepo(user)
	verifs := newFakeEmailVerificationRepo()
	rec := &fakeAuditRecorder{}
	svc := NewEmailVerificationService(users, verifs, nil, rec, c2Opts())

	require.NoError(t, svc.VerifyEmail(context.Background(), c2Link(t, verifs, user), "", ""))
	require.Equal(t, 1, users.updates, "an administrator's link proves nothing, so the email link must be recorded")
	require.NotNil(t, users.lastOpts.EmailVerifiedVia)
	assert.Equal(t, domain.EmailVerifiedViaEmailLink, *users.lastOpts.EmailVerifiedVia)
	assert.True(t, user.MailboxProven())
	assert.True(t, user.EmailVerified)
	require.Len(t, rec.snapshot(), 1)
}

func TestVerifyEmail_PendingInviteeStaysPending(t *testing.T) {
	user := newPasswordResetUser(t, "pending@example.test")
	user.EmailVerified = false
	pending := "invite-hash"
	user.ActivationTokenHash = &pending
	users := newFakeUserRepo(user)
	verifs := newFakeEmailVerificationRepo()
	svc := NewEmailVerificationService(users, verifs, nil, audit.NoopService{}, c2Opts())

	require.NoError(t, svc.VerifyEmail(context.Background(), c2Link(t, verifs, user), "", ""))
	require.Equal(t, 1, users.updates)
	assert.Nil(t, users.lastOpts.EmailVerified, "a pending invitee is activated by its invite link, not by the email")
	require.NotNil(t, users.lastOpts.EmailVerifiedVia)
	assert.Equal(t, domain.EmailVerifiedViaEmailLink, *users.lastOpts.EmailVerifiedVia)
	assert.False(t, user.EmailVerified)
	assert.NotNil(t, user.ActivationTokenHash, "the invite stays usable")
}

func TestVerifyEmail_SelfRegisteredUserIsActivatedAndProven(t *testing.T) {
	user := newPasswordResetUser(t, "self@example.test")
	user.EmailVerified = false
	users := newFakeUserRepo(user)
	verifs := newFakeEmailVerificationRepo()
	svc := NewEmailVerificationService(users, verifs, nil, audit.NoopService{}, c2Opts())

	require.NoError(t, svc.VerifyEmail(context.Background(), c2Link(t, verifs, user), "", ""))
	require.NotNil(t, users.lastOpts.EmailVerified)
	assert.True(t, *users.lastOpts.EmailVerified)
	require.NotNil(t, users.lastOpts.EmailVerifiedVia)
	assert.Equal(t, domain.EmailVerifiedViaEmailLink, *users.lastOpts.EmailVerifiedVia)
}

func TestVerifyEmail_ProvenMailboxIsANoOp(t *testing.T) {
	for _, via := range []string{domain.EmailVerifiedViaEmailLink, domain.EmailVerifiedViaUpstreamIDP, domain.EmailVerifiedViaLegacy} {
		user := newPasswordResetUser(t, "proven-"+via+"@example.test")
		user.EmailVerified = true
		user.EmailVerifiedVia = c2Via(via)
		users := newFakeUserRepo(user)
		verifs := newFakeEmailVerificationRepo()
		svc := NewEmailVerificationService(users, verifs, nil, audit.NoopService{}, c2Opts())
		require.NoError(t, svc.VerifyEmail(context.Background(), c2Link(t, verifs, user), "", ""))
		assert.Equal(t, 0, users.updates, "via %s", via)
	}
}

func TestResendVerification_SkipsOnlyAProvenMailbox(t *testing.T) {
	for _, c := range []struct {
		via      *string
		wantSent bool
	}{
		{nil, true},
		{c2Via(domain.EmailVerifiedViaAdminLink), true},
		{c2Via(domain.EmailVerifiedViaAdminSet), true},
		{c2Via(domain.EmailVerifiedViaSetup), true},
		{c2Via(domain.EmailVerifiedViaEmailLink), false},
		{c2Via(domain.EmailVerifiedViaLegacy), false},
	} {
		user := newPasswordResetUser(t, "resend@example.test")
		user.EmailVerified = true
		user.EmailVerifiedVia = c.via
		verifs := newFakeEmailVerificationRepo()
		notifier := &fakeVerificationNotifier{}
		svc := NewEmailVerificationService(newFakeUserRepo(user), verifs, notifier, audit.NoopService{}, c2Opts())
		require.NoError(t, svc.ResendVerification(context.Background(), "resend@example.test"))
		assert.Equal(t, c.wantSent, notifier.sends == 1, "via %v", c.via)
	}
}

// failingVerificationNotifier answers every send with err.
type failingVerificationNotifier struct{ err error }

func (n failingVerificationNotifier) SendVerificationEmail(context.Context, *domain.User, string) error {
	return n.err
}

func TestSendOwnVerification(t *testing.T) {
	ctx := context.Background()
	newUser := func(via *string) *domain.User {
		u := newPasswordResetUser(t, "own@example.test")
		u.EmailVerified = true
		u.EmailVerifiedVia = via
		return u
	}

	t.Run("sent", func(t *testing.T) {
		user := newUser(c2Via(domain.EmailVerifiedViaAdminLink))
		verifs := newFakeEmailVerificationRepo()
		notifier := &fakeVerificationNotifier{}
		rec := &fakeAuditRecorder{}
		svc := NewEmailVerificationService(newFakeUserRepo(user), verifs, notifier, rec, c2Opts())
		require.NoError(t, svc.SendOwnVerification(ctx, user.ID))
		assert.Equal(t, 1, notifier.sends)
		assert.Equal(t, user.ID, notifier.lastUserID)
		require.Len(t, verifs.rows, 1)
		events := rec.snapshot()
		require.Len(t, events, 1)
		assert.Equal(t, string(domain.AuditEmailVerificationResent), events[0].Action)
	})
	t.Run("already proven", func(t *testing.T) {
		user := newUser(c2Via(domain.EmailVerifiedViaEmailLink))
		verifs := newFakeEmailVerificationRepo()
		notifier := &fakeVerificationNotifier{}
		svc := NewEmailVerificationService(newFakeUserRepo(user), verifs, notifier, audit.NoopService{}, c2Opts())
		assert.ErrorIs(t, svc.SendOwnVerification(ctx, user.ID), ErrEmailAlreadyProven)
		assert.Equal(t, 0, notifier.sends)
		assert.Empty(t, verifs.rows)
	})
	t.Run("no delivery", func(t *testing.T) {
		for name, n := range map[string]EmailVerificationNotifier{
			"nil notifier":  nil,
			"unconfigured":  UnconfiguredEmailNotifier{},
			"wrapped error": failingVerificationNotifier{err: errors.Join(errors.New("smtp"), ErrEmailDeliveryNotConfigured)},
		} {
			user := newUser(nil)
			svc := NewEmailVerificationService(newFakeUserRepo(user), newFakeEmailVerificationRepo(), n, audit.NoopService{}, c2Opts())
			assert.ErrorIs(t, svc.SendOwnVerification(ctx, user.ID), ErrEmailDeliveryNotConfigured, name)
		}
	})
	t.Run("send failure", func(t *testing.T) {
		user := newUser(nil)
		svc := NewEmailVerificationService(newFakeUserRepo(user), newFakeEmailVerificationRepo(), failingVerificationNotifier{err: errors.New("smtp down")}, audit.NoopService{}, c2Opts())
		err := svc.SendOwnVerification(ctx, user.ID)
		assert.ErrorIs(t, err, ErrEmailDeliveryFailed)
		assert.NotErrorIs(t, err, ErrEmailDeliveryNotConfigured)
	})
	t.Run("unknown user", func(t *testing.T) {
		svc := NewEmailVerificationService(newFakeUserRepo(), newFakeEmailVerificationRepo(), &fakeVerificationNotifier{}, audit.NoopService{}, c2Opts())
		assert.ErrorIs(t, svc.SendOwnVerification(ctx, newPasswordResetUser(t, "x@example.test").ID), domain.ErrUserNotFound)
	})
}

// RULE: EMAIL-VERIFIED-PROVEN-1
func TestIDToken_EmailVerifiedClaimReadsTheProof(t *testing.T) {
	svc, _ := newIDTokenSvc(t)
	session := newIDTokenSession()
	for _, c := range []struct {
		via  *string
		want bool
	}{
		{nil, false},
		{c2Via(domain.EmailVerifiedViaAdminLink), false},
		{c2Via(domain.EmailVerifiedViaAdminSet), false},
		{c2Via(domain.EmailVerifiedViaSetup), false},
		{c2Via(domain.EmailVerifiedViaEmailLink), true},
		{c2Via(domain.EmailVerifiedViaUpstreamIDP), true},
		{c2Via(domain.EmailVerifiedViaLegacy), true},
	} {
		for _, claim := range []string{"email", "email_verified"} {
			user := newIDTokenUser()
			user.EmailVerified = true
			user.EmailVerifiedVia = c.via
			resp, err := svc.Issue(context.Background(), IDTokenInput{
				User: user, Session: session, Audience: "cli-1", Nonce: "n", Scope: "openid", Claims: []string{claim},
			})
			require.NoError(t, err)
			claims, _ := parseIDToken(t, resp.IDToken)
			assert.Equal(t, c.want, claims["email_verified"], "claim %s via %v", claim, c.via)
		}
	}
}
