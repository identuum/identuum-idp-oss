package service

// claim_issue_test.go — OSS-CLAIM (owner ruling D-022, plus rulings a, b and
// c of 2026-10-01): a site_admin issues an organization claim link while the
// organization is operational and has no active org_admin; a re-issue retires
// every earlier link for that organization; consume re-checks both under the
// claim lock. The wire (validate {valid}, consume {success}) is unchanged.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// claimAdminsOver counts the fake's live org_admins of an organization, the
// predicate CountOrgAdminsByOrganization evaluates in production.
type claimAdminsOver struct{ users *fakeUserRepo }

func (c claimAdminsOver) CountOrgAdminsByOrganization(_ context.Context, orgID uuid.UUID) (int, error) {
	n := 0
	for _, u := range c.users.byID {
		if u.OrganizationID == orgID && u.Role == domain.RoleOrgAdmin && u.DeletedAt == nil && !u.Banned {
			n++
		}
	}
	return n, nil
}

type fakeClaimNotifier struct {
	to  []string
	err error
}

func (f *fakeClaimNotifier) SendClaimEmail(_ context.Context, to, _, _ string, _ time.Time) error {
	f.to = append(f.to, to)
	return f.err
}

func seedOrgAdmin(users *fakeUserRepo, orgID uuid.UUID, email string) {
	id := uuid.New()
	u := &domain.User{ID: id, Email: email, OrganizationID: orgID, Role: domain.RoleOrgAdmin}
	users.byID[id] = u
	users.byEmail[email] = append(users.byEmail[email], u)
}

func consumeAs(svc *ClaimService, raw, email string) *ConsumeClaimResult {
	r, _ := svc.ConsumeClaim(context.Background(), ConsumeClaimInput{Token: raw, Email: email, Password: "longenoughpassword"})
	return r
}

func TestConsumeClaim_ActiveOrgWithoutAdminSucceeds(t *testing.T) {
	svc, _, _, users, _, org := newClaimFixture(t)
	org.Active = true
	raw, _, err := svc.GenerateClaimToken(context.Background(), org.ID, "")
	require.NoError(t, err)
	r := consumeAs(svc, raw, "first@example.test")
	require.NotNil(t, r)
	assert.True(t, r.Success, "an operational organization with no admin is what a claim is for")
	require.Len(t, users.byEmail["first@example.test"], 1)
}

// Ruling a: an organization that gained an admin after the link was issued
// refuses the consume, opaquely, and burns the stale link.
func TestConsumeClaim_OrgThatGainedAnAdminBurns(t *testing.T) {
	svc, claims, _, users, _, org := newClaimFixture(t)
	org.Active = true
	raw, _, err := svc.GenerateClaimToken(context.Background(), org.ID, "")
	require.NoError(t, err)
	seedOrgAdmin(users, org.ID, "someone-else@example.test")
	r := consumeAs(svc, raw, "late@example.test")
	require.NotNil(t, r)
	assert.False(t, r.Success)
	assert.Empty(t, users.byEmail["late@example.test"], "no second org_admin")
	assert.Empty(t, claims.byHash, "the stale link is burned")
}

// Ruling c: a deactivated or deleted organization refuses, and burns.
func TestConsumeClaim_InactiveOrgBurnsToken(t *testing.T) {
	for _, deleted := range []bool{false, true} {
		svc, claims, _, users, _, org := newClaimFixture(t)
		raw, _, err := svc.GenerateClaimToken(context.Background(), org.ID, "")
		require.NoError(t, err)
		org.Active = deleted // a deleted org fails even while active
		if deleted {
			now := time.Now()
			org.DeletedAt = &now
		}
		r := consumeAs(svc, raw, "alice@example.test")
		require.NotNil(t, r)
		assert.False(t, r.Success, "deleted=%v", deleted)
		assert.Empty(t, users.byEmail["alice@example.test"], "deleted=%v", deleted)
		assert.Empty(t, claims.byHash, "deleted=%v: the link is burned", deleted)
	}
}

func issue(svc *ClaimService, orgID uuid.UUID, email string) (*IssuedClaim, error) {
	return svc.IssueClaim(context.Background(), IssueClaimInput{
		OrganizationID: orgID, Email: email,
		Actor: &domain.Principal{UserID: uuid.New(), Email: "site@example.test", Role: domain.RoleSiteAdmin},
	})
}

func TestIssueClaim_EligibilityAndRetirement(t *testing.T) {
	svc, claims, _, users, rec, org := newClaimFixture(t)
	org.Active = true

	first, err := issue(svc, org.ID, "")
	require.NoError(t, err)
	assert.False(t, first.EmailBound)
	assert.Equal(t, 64, len(first.Token))
	assert.True(t, first.ExpiresAt.After(time.Now()))

	// Ruling b: a re-issue retires every earlier link for the organization.
	second, err := issue(svc, org.ID, "Owner@Example.test")
	require.NoError(t, err)
	assert.True(t, second.EmailBound)
	assert.Len(t, claims.byHash, 1, "only the newest link survives")
	v, _ := svc.ValidateClaim(context.Background(), first.Token)
	assert.False(t, v.Valid, "the retired link validates {valid:false}")
	assert.False(t, consumeAs(svc, first.Token, "x@example.test").Success, "and consumes {success:false}")
	v, _ = svc.ValidateClaim(context.Background(), second.Token)
	assert.True(t, v.Valid)
	assert.Equal(t, "owner@example.test", v.TargetEmail)

	var gen []map[string]any
	for _, e := range rec.snapshot() {
		if e.Action == domain.AuditClaimGenerated {
			gen = append(gen, e.Metadata)
			assert.Equal(t, "site@example.test", e.ActorEmail, "the issuing site_admin is the actor")
			assert.Equal(t, org.ID, e.OrganizationID)
		}
		for k, val := range e.Metadata {
			s, _ := val.(string)
			assert.False(t, strings.Contains(s, first.Token) || strings.Contains(s, second.Token), "metadata %q carries no token", k)
		}
	}
	require.Len(t, gen, 2)
	assert.EqualValues(t, 0, gen[0]["retired_claims"])
	assert.EqualValues(t, 1, gen[1]["retired_claims"])

	// Ruling a: an organization with an active org_admin is not claimable.
	seedOrgAdmin(users, org.ID, "admin@example.test")
	_, err = issue(svc, org.ID, "")
	assert.True(t, errors.Is(err, ErrClaimOrgNotClaimable))
	assert.Len(t, claims.byHash, 1, "a refused issue retires nothing")
}

func TestIssueClaim_InactiveOrDeletedOrgNotClaimable(t *testing.T) {
	svc, claims, _, _, _, org := newClaimFixture(t)
	org.Active = false
	_, err := issue(svc, org.ID, "")
	assert.True(t, errors.Is(err, ErrClaimOrgNotClaimable))
	org.Active = true
	now := time.Now()
	org.DeletedAt = &now
	_, err = issue(svc, org.ID, "")
	assert.True(t, errors.Is(err, ErrClaimOrgNotClaimable))
	assert.Empty(t, claims.byHash)
	_, err = issue(svc, uuid.New(), "")
	assert.True(t, errors.Is(err, domain.ErrOrganizationNotFound))
}

func TestIssueClaim_MailsABoundLinkAndAMailFailureDoesNotFailTheIssue(t *testing.T) {
	svc, claims, _, _, _, org := newClaimFixture(t)
	org.Active = true
	n := &fakeClaimNotifier{err: errors.New("smtp down")}
	svc.notifier = n
	_, err := issue(svc, org.ID, "")
	require.NoError(t, err)
	assert.Empty(t, n.to, "an unbound link is not mailed")
	got, err := issue(svc, org.ID, "owner@example.test")
	require.NoError(t, err, "a failed mail does not fail the issue")
	assert.Equal(t, []string{"owner@example.test"}, n.to)
	v, _ := svc.ValidateClaim(context.Background(), got.Token)
	assert.True(t, v.Valid)
	assert.Len(t, claims.byHash, 1)
}
