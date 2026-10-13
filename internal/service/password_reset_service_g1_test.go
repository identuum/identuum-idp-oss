package service

// G1 (owner Q-G1 (a), 2026-10-13): the self-service reset sends no link to a
// member who cannot use a local password, and the completion re-checks.
//
//   - an org_user in an idp_only organization (IsLocalCredentialFlowAllowed
//     denies) gets no row, no mail, no audit; the request still returns nil
//     (the handler answers 200, no account oracle);
//   - a federated-only member (PasswordHash == domain.NoPasswordSentinel) gets
//     the same;
//   - a link issued while the organization allowed local passwords is refused
//     at completion once the organization is idp_only, WITHOUT claiming the row.
//
// Control: a local org_user in a permissive organization still gets one row and
// one mail. Tokens are never printed.

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/identuum/identuum-idp-oss/internal/crypto"
	"github.com/identuum/identuum-idp-oss/internal/domain"
)

func g1Policy(p string) *string { return &p }

// g1Now is the service's clock; the links these tests store expire an hour
// after the real time, so they are live on it.
var g1Now = time.Date(2026, 10, 13, 9, 0, 0, 0, time.UTC)

func g1Service(users *fakeUserRepo, resets *fakePasswordResetRepo, n *fakePasswordResetNotifier, rec *fakeAuditRecorder) *PasswordResetService {
	return NewPasswordResetService(PasswordResetServiceConfig{
		Users:              users,
		Resets:             resets,
		Notifier:           n,
		Audit:              rec,
		HumanFacingBaseURL: "https://ui.example.test",
		Now:                func() time.Time { return g1Now },
	})
}

// Red at 3e1fa09: issueResets skipped only nil, deleted and banned users, and
// ResetPassword checked deleted and banned only.
// RULE: RESET-LOCAL-ONLY-1
func TestResetPassword_LocalPasswordsOnly(t *testing.T) {
	t.Run("idp_only org_user gets no link", func(t *testing.T) {
		user := newPasswordResetUser(t, "idponly@example.test")
		user.EmailVerified = true
		user.OrgAuthPolicy = g1Policy(domain.AuthPolicyIDPOnly)
		user.PasswordHash = domain.NoPasswordSentinel
		users, resets := newFakeUserRepo(user), newFakePasswordResetRepo()
		n, rec := &fakePasswordResetNotifier{}, &fakeAuditRecorder{}

		require.NoError(t, g1Service(users, resets, n, rec).RequestPasswordReset(context.Background(), user.Email, "ip", "ua"))
		assert.Empty(t, resets.rows, "an idp_only org_user must get no reset row")
		assert.Equal(t, 0, n.sends, "an idp_only org_user must get no reset mail")
		assert.Empty(t, rec.snapshot(), "an idp_only org_user must leave no reset audit event")
	})

	// The organization is permissive, so only the sentinel can stop it.
	t.Run("federated-only member gets no link", func(t *testing.T) {
		user := newPasswordResetUser(t, "federated@example.test")
		user.EmailVerified = true
		user.AuthSource = domain.AuthSourceIDJag
		user.PasswordHash = domain.NoPasswordSentinel
		users, resets := newFakeUserRepo(user), newFakePasswordResetRepo()
		n, rec := &fakePasswordResetNotifier{}, &fakeAuditRecorder{}

		require.NoError(t, g1Service(users, resets, n, rec).RequestPasswordReset(context.Background(), user.Email, "ip", "ua"))
		assert.Empty(t, resets.rows, "a federated-only member must get no reset row")
		assert.Equal(t, 0, n.sends, "a federated-only member must get no reset mail")
		assert.Empty(t, rec.snapshot(), "a federated-only member must leave no reset audit event")
	})

	t.Run("policy rechecked at completion", func(t *testing.T) {
		user := newPasswordResetUser(t, "flipped@example.test")
		user.EmailVerified = true
		user.PasswordHash = "$argon2id$test$old"
		users, resets := newFakeUserRepo(user), newFakePasswordResetRepo()
		rawToken, err := crypto.GenerateRandomString(32)
		require.NoError(t, err)
		hash := crypto.HashToken(rawToken)
		resets.rows[hash] = &domain.PasswordReset{
			UserID:    user.ID,
			TokenHash: hash,
			ExpiresAt: time.Now().Add(time.Hour),
			CreatedAt: time.Now(),
		}
		// The organization turns idp_only after the link was issued.
		user.OrgAuthPolicy = g1Policy(domain.AuthPolicyIDPOnly)

		svc := g1Service(users, resets, &fakePasswordResetNotifier{}, &fakeAuditRecorder{})
		resetErr := svc.ResetPassword(context.Background(), ResetPasswordInput{Token: rawToken, NewPassword: "Longenough-pw-1!"})
		assert.ErrorIs(t, resetErr, ErrPasswordResetInvalidToken, "completion must refuse an idp_only org_user")
		assert.Equal(t, 0, resets.markCalled, "the row must not be claimed when the policy refuses")
		assert.Nil(t, resets.rows[hash].UsedAt, "the row must stay unused")
	})
}

// Control (green before and after): a local org_user in a permissive org.
func TestRequestPasswordReset_LocalMixedOrgUserStillGetsLink(t *testing.T) {
	user := newPasswordResetUser(t, "local@example.test")
	user.EmailVerified = true
	user.PasswordHash = "$argon2id$test$old"
	user.OrgAuthPolicy = g1Policy(domain.AuthPolicyPermissive)
	users, resets := newFakeUserRepo(user), newFakePasswordResetRepo()
	n, rec := &fakePasswordResetNotifier{}, &fakeAuditRecorder{}

	require.NoError(t, g1Service(users, resets, n, rec).RequestPasswordReset(context.Background(), user.Email, "ip", "ua"))
	assert.Len(t, resets.rows, 1)
	assert.Equal(t, 1, n.sends)
	assert.Len(t, rec.snapshot(), 1)
}
