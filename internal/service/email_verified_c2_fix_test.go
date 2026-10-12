package service

// OSS-0912-C2-FIX (review OSS-0912-C2-REVIEW R1, R3, R4): a verification link
// proves only the address it was mailed to; a failed send is audited as a
// failure; the site_admin's reserved address is never mailed.

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/crypto"
	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// R1: a link mailed to an earlier address, or a row that names no address,
// is refused and records nothing.
func TestVerifyEmail_LinkForAnotherAddressIsRefused(t *testing.T) {
	for name, address := range map[string]string{
		"earlier address": "old@example.test",
		"no address":      "",
	} {
		user := newPasswordResetUser(t, "new@example.test")
		user.EmailVerified = true
		user.EmailVerifiedVia = c2Via(domain.EmailVerifiedViaAdminSet)
		users := newFakeUserRepo(user)
		verifs := newFakeEmailVerificationRepo()
		rec := &fakeAuditRecorder{}
		svc := NewEmailVerificationService(users, verifs, nil, rec, c2Opts())
		raw := c2Link(t, verifs, user)
		row := verifs.rows[crypto.HashToken(raw)]
		row.AddressHash = ""
		if address != "" {
			row.AddressHash = domain.EmailAddressHash(address)
		}

		err := svc.VerifyEmail(context.Background(), raw, "", "")
		assert.ErrorIs(t, err, ErrEmailVerificationAddressChanged, name)
		assert.Equal(t, 0, users.updates, "%s: nothing may be recorded", name)
		assert.False(t, user.MailboxProven(), name)
		assert.Empty(t, rec.snapshot(), name)
		// OSS-0912-C2-FIX-2: a link refused for the address is not spent.
		assert.Nil(t, row.UsedAt, "%s: the refused link stays unused", name)
	}
}

// R1: the address comparison ignores case and surrounding space, as the
// address is stored lower-case.
func TestEmailAddressHash_Normalizes(t *testing.T) {
	assert.Equal(t, domain.EmailAddressHash("a@example.test"), domain.EmailAddressHash("  A@Example.TEST "))
	assert.NotEqual(t, domain.EmailAddressHash("a@example.test"), domain.EmailAddressHash("b@example.test"))
	assert.Len(t, domain.EmailAddressHash("a@example.test"), 64)
}

// R1: every row the service writes names the address it was mailed to.
func TestIssuedRowsCarryTheAddress(t *testing.T) {
	ctx := context.Background()
	user := newPasswordResetUser(t, "Mixed@Example.test")
	user.EmailVerified = true
	verifs := newFakeEmailVerificationRepo()
	svc := NewEmailVerificationService(newFakeUserRepo(user), verifs, &fakeVerificationNotifier{}, audit.NoopService{}, c2Opts())

	require.NoError(t, svc.SendOwnVerification(ctx, user.ID))
	_, err := svc.IssueInitialVerification(ctx, user)
	require.NoError(t, err)
	require.Len(t, verifs.rows, 2)
	for _, row := range verifs.rows {
		assert.Equal(t, domain.EmailAddressHash(user.Email), row.AddressHash)
	}
}

// R3: a send the notifier refused is audited as a failure, never a success.
func TestSendOwnVerification_FailedSendIsAuditedAsFailure(t *testing.T) {
	for name, n := range map[string]EmailVerificationNotifier{
		"send failure": failingVerificationNotifier{err: errors.New("smtp down")},
		"unconfigured": UnconfiguredEmailNotifier{},
	} {
		user := newPasswordResetUser(t, "fail@example.test")
		rec := &fakeAuditRecorder{}
		svc := NewEmailVerificationService(newFakeUserRepo(user), newFakeEmailVerificationRepo(), n, rec, c2Opts())
		require.Error(t, svc.SendOwnVerification(context.Background(), user.ID), name)
		events := rec.snapshot()
		require.Len(t, events, 1, name)
		assert.Equal(t, string(domain.AuditEmailVerificationResent), events[0].Action, name)
		assert.Equal(t, "failure", events[0].Outcome, name)
	}
}

// R4: the site_admin's address is the reserved sign-in name, not a mailbox.
func TestSendOwnVerification_SiteAdminIsRefused(t *testing.T) {
	user := newPasswordResetUser(t, domain.SiteAdminEmail)
	user.Role = domain.RoleSiteAdmin
	user.EmailVerifiedVia = c2Via(domain.EmailVerifiedViaSetup)
	verifs := newFakeEmailVerificationRepo()
	notifier := &fakeVerificationNotifier{}
	rec := &fakeAuditRecorder{}
	svc := NewEmailVerificationService(newFakeUserRepo(user), verifs, notifier, rec, c2Opts())

	assert.ErrorIs(t, svc.SendOwnVerification(context.Background(), user.ID), ErrEmailVerificationNotAvailable)
	assert.Equal(t, 0, notifier.sends)
	assert.Empty(t, verifs.rows)
	assert.Empty(t, rec.snapshot())
}

// OSS-0912-C2-FIX-2 (review F2): the public resend skips the site_admin
// even when its mailbox is not proven, with the same nil answer.
func TestResendVerification_SiteAdminIsSkipped(t *testing.T) {
	user := newPasswordResetUser(t, domain.SiteAdminEmail)
	user.Role = domain.RoleSiteAdmin
	user.EmailVerifiedVia = nil
	require.False(t, user.MailboxProven())
	verifs := newFakeEmailVerificationRepo()
	notifier := &fakeVerificationNotifier{}
	rec := &fakeAuditRecorder{}
	svc := NewEmailVerificationService(newFakeUserRepo(user), verifs, notifier, rec, c2Opts())

	assert.NoError(t, svc.ResendVerification(context.Background(), domain.SiteAdminEmail))
	assert.Equal(t, 0, notifier.sends)
	assert.Empty(t, verifs.rows)
	assert.Empty(t, rec.snapshot())
}
