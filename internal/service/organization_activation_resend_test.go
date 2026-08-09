package service

// Unit tests for OrganizationActivationService.ResendActivationToken —
// the resend seam that re-issues a fresh activation token for a pending
// org's org_admin, invalidating the old one, and dispatches it via the
// notifier (or, in OSS, echoes it back to the caller).

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// (a) + send seam: resend mints a fresh token, persists it on the
// org_admin, and invokes the notifier (the send seam).
func TestResendActivationToken_ReissuesAndDispatches(t *testing.T) {
	_, users, orgs, _, admin, org := newActivationFixture(t) // org.Active == false (pending)
	notifier := &fakeActivationNotifier{}
	svc := NewOrganizationActivationService(OrganizationActivationServiceConfig{
		Users: users, Orgs: orgs, OrgsAdmin: orgs, Notifier: notifier, Audit: audit.NoopService{},
	})

	raw, expiresAt, email, err := svc.ResendActivationToken(context.Background(), org.ID)
	require.NoError(t, err)
	assert.Len(t, raw, 64, "fresh 32-byte random token (hex) — NOT a UUIDv7")
	assert.Equal(t, admin.Email, email)
	assert.True(t, expiresAt.After(time.Now()))

	// The send seam ran with the freshly-minted raw token.
	assert.Equal(t, 1, notifier.sends)
	assert.Equal(t, raw, notifier.lastToken)
	assert.Equal(t, admin.ID, notifier.lastUserID)

	// The fresh hash is stamped on the org_admin row.
	require.NotNil(t, admin.ActivationTokenHash)
	assert.Len(t, *admin.ActivationTokenHash, 64)
}

// (d) token: a resend AFTER an initial issue mints a DIFFERENT token and
// overwrites the stored hash, so the old token can no longer validate.
func TestResendActivationToken_InvalidatesOldToken(t *testing.T) {
	_, users, orgs, _, admin, org := newActivationFixture(t)
	svc := NewOrganizationActivationService(OrganizationActivationServiceConfig{
		Users: users, Orgs: orgs, OrgsAdmin: orgs, Audit: audit.NoopService{},
	})

	tok1, _, err := svc.IssueActivationToken(context.Background(), admin)
	require.NoError(t, err)
	hash1 := *admin.ActivationTokenHash

	tok2, _, _, err := svc.ResendActivationToken(context.Background(), org.ID)
	require.NoError(t, err)

	assert.NotEqual(t, tok1, tok2, "resend must mint a new token")
	assert.NotEqual(t, hash1, *admin.ActivationTokenHash, "old hash overwritten → old token invalidated")

	// The old token no longer validates (its hash is gone).
	_, err = svc.ValidateActivationToken(context.Background(), tok1)
	assert.ErrorIs(t, err, ErrOrganizationActivationInvalidToken)
	// The new token validates.
	res, err := svc.ValidateActivationToken(context.Background(), tok2)
	require.NoError(t, err)
	assert.Equal(t, org.ID, res.OrgID)
}

// (c) guard: an already-active org cannot be resent — 409 sentinel.
func TestResendActivationToken_AlreadyActive_Conflict(t *testing.T) {
	_, users, orgs, _, _, org := newActivationFixture(t)
	org.Active = true
	svc := NewOrganizationActivationService(OrganizationActivationServiceConfig{
		Users: users, Orgs: orgs, OrgsAdmin: orgs, Audit: audit.NoopService{},
	})
	_, _, _, err := svc.ResendActivationToken(context.Background(), org.ID)
	assert.ErrorIs(t, err, ErrOrganizationAlreadyActive)
}

// (c) guard: a missing org is a not-found, not a silent success.
func TestResendActivationToken_MissingOrg_NotFound(t *testing.T) {
	svc, _, _, _, _, _ := newActivationFixture(t)
	_, _, _, err := svc.ResendActivationToken(context.Background(), uuid.New())
	assert.ErrorIs(t, err, domain.ErrOrganizationNotFound)
}

// (c) guard: a pending org with no org_admin has nothing to resend.
func TestResendActivationToken_NoOrgAdmin_Sentinel(t *testing.T) {
	orgID := uuid.New()
	org := &domain.Organization{ID: orgID, Name: "NoAdmin", Active: false}
	// only an org_user in the org — no org_admin recipient
	user := &domain.User{ID: uuid.New(), OrganizationID: orgID, Email: "u@noadmin.test", Role: domain.RoleOrgUser}
	users := newFakeUserRepo(user)
	orgs := newFakeOrgRepo(org)
	svc := NewOrganizationActivationService(OrganizationActivationServiceConfig{
		Users: users, Orgs: orgs, OrgsAdmin: orgs, Audit: audit.NoopService{},
	})
	_, _, _, err := svc.ResendActivationToken(context.Background(), orgID)
	assert.ErrorIs(t, err, ErrOrganizationActivationNoAdmin)
}

// A soft-deleted org_admin is not a valid recipient.
func TestResendActivationToken_DeletedAdminSkipped(t *testing.T) {
	orgID := uuid.New()
	org := &domain.Organization{ID: orgID, Name: "DeletedAdmin", Active: false}
	deletedAt := time.Now().UTC()
	admin := &domain.User{ID: uuid.New(), OrganizationID: orgID, Email: "gone@x.test", Role: domain.RoleOrgAdmin, DeletedAt: &deletedAt}
	users := newFakeUserRepo(admin)
	orgs := newFakeOrgRepo(org)
	svc := NewOrganizationActivationService(OrganizationActivationServiceConfig{
		Users: users, Orgs: orgs, OrgsAdmin: orgs, Audit: audit.NoopService{},
	})
	_, _, _, err := svc.ResendActivationToken(context.Background(), orgID)
	assert.ErrorIs(t, err, ErrOrganizationActivationNoAdmin)
}
