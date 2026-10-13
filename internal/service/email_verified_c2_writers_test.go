package service

// OSS-0912-C2: every writer of a user row says how the mailbox was proven,
// or that it was not (owner Q1 (a), Q3 (a), Q-C2-1 (a)).

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/repository"
)

func viaOf(u *domain.User) string {
	if u == nil || u.EmailVerifiedVia == nil {
		return ""
	}
	return *u.EmailVerifiedVia
}

func TestUserServiceCreate_RecordsHowTheAddressWasVouched(t *testing.T) {
	svc := NewUserService(nil, newUserRepo())
	admin, err := svc.Create(context.Background(), CreateUserOptions{
		OrganizationID: uuid.New(), Email: "admin-set@example.com", Password: "Strong-Password-1!", Role: domain.RoleOrgUser,
	})
	require.NoError(t, err)
	assert.True(t, admin.EmailVerified, "D-017: an admin-created user is activated")
	assert.Equal(t, domain.EmailVerifiedViaAdminSet, viaOf(admin), "an administrator's word proves no mailbox")

	self, err := svc.Create(context.Background(), CreateUserOptions{
		OrganizationID: uuid.New(), Email: "self@example.com", Password: "Strong-Password-1!", Role: domain.RoleOrgUser, Unverified: true,
	})
	require.NoError(t, err)
	assert.False(t, self.EmailVerified)
	assert.Equal(t, "", viaOf(self), "a self-registrant is never proven at creation")
}

// c2RecordingUserRepo records the last update's options.
type c2RecordingUserRepo struct {
	*inMemoryUserRepo
	last repository.UpdateUserOptions
}

func (r *c2RecordingUserRepo) Update(ctx context.Context, id, orgID uuid.UUID, opts repository.UpdateUserOptions) (*domain.User, error) {
	r.last = opts
	return r.inMemoryUserRepo.Update(ctx, id, orgID, opts)
}

func TestUserServiceUpdate_AdminSettingIsLabelledNotProven(t *testing.T) {
	repo := &c2RecordingUserRepo{inMemoryUserRepo: newUserRepo()}
	svc := NewUserService(nil, repo)
	u, err := svc.Create(context.Background(), CreateUserOptions{
		OrganizationID: uuid.New(), Email: "edit@example.com", Password: "Strong-Password-1!", Role: domain.RoleOrgUser,
	})
	require.NoError(t, err)
	yes, no := true, false

	_, err = svc.Update(context.Background(), u.ID, u.OrganizationID, UpdateUserOptions{EmailVerified: &yes})
	require.NoError(t, err)
	require.NotNil(t, repo.last.EmailVerifiedVia)
	assert.Equal(t, domain.EmailVerifiedViaAdminSet, *repo.last.EmailVerifiedVia)
	assert.True(t, repo.last.KeepProvenEmailVerifiedVia, "setting true keeps a mailbox already proven")

	_, err = svc.Update(context.Background(), u.ID, u.OrganizationID, UpdateUserOptions{EmailVerified: &no})
	require.NoError(t, err)
	require.NotNil(t, repo.last.EmailVerifiedVia)
	assert.Equal(t, "", *repo.last.EmailVerifiedVia, "setting false clears the proof")
	assert.False(t, repo.last.KeepProvenEmailVerifiedVia)

	name := "Renamed"
	_, err = svc.Update(context.Background(), u.ID, u.OrganizationID, UpdateUserOptions{Name: &name})
	require.NoError(t, err)
	assert.Nil(t, repo.last.EmailVerifiedVia, "an unrelated edit leaves the proof alone")
}

func TestConsumeClaim_OrgAdminIsActivatedByAnAdministratorsLink(t *testing.T) {
	svc, _, _, users, _, org := newClaimFixture(t)
	raw, _, err := svc.GenerateClaimToken(context.Background(), org.ID, "")
	require.NoError(t, err)
	_, err = svc.ConsumeClaim(context.Background(), ConsumeClaimInput{Token: raw, Email: "claimer@example.test", Name: "C", Password: "longenoughpassword"})
	require.NoError(t, err)
	require.Len(t, users.byEmail["claimer@example.test"], 1)
	created := users.byEmail["claimer@example.test"][0]
	assert.True(t, created.EmailVerified)
	assert.Equal(t, domain.EmailVerifiedViaAdminLink, viaOf(created), "the site_admin also holds the claim link")
}

func TestOIDCCallback_JIT_RecordsTheProvidersProof(t *testing.T) {
	h := newCallbackHarness(t)
	u, err := h.callWithClaims(t, nil)
	require.NoError(t, err)
	assert.True(t, u.EmailVerified)
	assert.Equal(t, domain.EmailVerifiedViaUpstreamIDP, viaOf(u))
}

func TestOIDCCallback_LinkRecordsTheProofOnly(t *testing.T) {
	for _, c := range []struct {
		name      string
		activated bool
		via       *string
		wantVia   string
	}{
		{"unactivated local user", false, nil, domain.EmailVerifiedViaUpstreamIDP},
		{"admin-activated local user", true, c2Via(domain.EmailVerifiedViaAdminLink), domain.EmailVerifiedViaUpstreamIDP},
		{"already proven by email", true, c2Via(domain.EmailVerifiedViaEmailLink), domain.EmailVerifiedViaEmailLink},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := newCallbackHarness(t)
			id := uuid.New()
			h.users.byID[id] = &domain.User{ID: id, OrganizationID: h.orgID, Email: "alice@example.com", Role: domain.RoleOrgUser,
				AuthSource: domain.AuthSourceLocal, EmailVerified: c.activated, EmailVerifiedVia: c.via}
			u, err := h.callWithClaims(t, nil)
			require.NoError(t, err)
			assert.Equal(t, id, u.ID)
			assert.Equal(t, c.wantVia, viaOf(h.users.byID[id]))
			assert.Equal(t, c.activated, h.users.byID[id].EmailVerified, "Q-C2-1: a link never changes activation")
		})
	}
}

// defaultExternalID is the issuer|sub the harness's validClaims produce.
func (h *callbackHarness) defaultExternalID() string {
	return h.srv.URL + "|upstream-user-123"
}

// sessionsMinted counts the sessions the callback created.
func (h *callbackHarness) sessionsMinted() int {
	h.sessionRepo.mu.Lock()
	defer h.sessionRepo.mu.Unlock()
	return len(h.sessionRepo.byID)
}

// assertNoUpstreamLink checks that the row was not written by the callback:
// the ExternalID, the link flag, the auth source and the proof are unchanged.
func assertNoUpstreamLink(t *testing.T, got *domain.User, wantExt *string) {
	t.Helper()
	assert.Equal(t, wantExt, got.ExternalID, "no ExternalID is written")
	assert.Equal(t, wantExt != nil, got.OIDCLinked, "the link flag is unchanged")
	assert.Equal(t, domain.AuthSourceLocal, got.AuthSource, "the auth source is unchanged")
	assert.Nil(t, got.EmailVerifiedVia, "no proof is recorded")
	assert.False(t, got.EmailVerified, "the row stays unverified")
}

// O19: an invitee who has not accepted the invitation is not signed in, or
// linked, through the upstream provider, on either match path.
func TestOIDCCallback_PendingInviteeIsNotSignedInUpstream(t *testing.T) {
	for _, c := range []struct {
		name   string
		linked bool // true: the row already carries this ExternalID (path 1); false: email match (path 2)
	}{
		{"email match of a pending invitee", false},
		{"external-id match of a linked pending invitee", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := newCallbackHarness(t)
			id := uuid.New()
			hash := "invite-hash"
			exp := time.Now().Add(72 * time.Hour)
			u := &domain.User{ID: id, OrganizationID: h.orgID, Email: "alice@example.com", Role: domain.RoleOrgUser,
				AuthSource: domain.AuthSourceLocal, ActivationTokenHash: &hash, ActivationTokenExpiresAt: &exp}
			var wantExt *string
			if c.linked {
				ext := h.defaultExternalID()
				u.ExternalID, u.OIDCLinked, wantExt = &ext, true, &ext
			}
			h.users.byID[id] = u
			require.True(t, IsInvitePending(u), "premise: the row is a pending invite")

			_, err := h.callWithClaims(t, nil)
			assert.ErrorIs(t, err, ErrCallbackForbidden, "O19: a pending invitee accepts the invitation first")
			assert.ErrorIs(t, err, ErrCallbackInvitePending, "O19: the refusal names the pending invitation")
			assert.Zero(t, h.sessionsMinted(), "no session for a pending invitee")
			got := h.users.byID[id]
			assert.NotNil(t, got.ActivationTokenHash, "the invite stays pending")
			assertNoUpstreamLink(t, got, wantExt)
			assert.Len(t, h.users.byID, 1, "no user is created")
		})
	}
}

// callbackRegStates answers UserState from a fixed map (D-021).
type callbackRegStates map[uuid.UUID]string

func (m callbackRegStates) UserState(_ context.Context, userID uuid.UUID) (string, bool, error) {
	return m[userID], false, nil
}

// O19: a self-registrant held for approval is not signed in, or linked,
// through the upstream provider, on either match path.
func TestOIDCCallback_PendingApprovalIsNotSignedInUpstream(t *testing.T) {
	for _, c := range []struct {
		name   string
		linked bool
	}{
		{"email match of a registrant held for approval", false},
		{"external-id match of a linked registrant held for approval", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := newCallbackHarness(t)
			id := uuid.New()
			u := &domain.User{ID: id, OrganizationID: h.orgID, Email: "alice@example.com", Role: domain.RoleOrgUser,
				AuthSource: domain.AuthSourceLocal}
			var wantExt *string
			if c.linked {
				ext := h.defaultExternalID()
				u.ExternalID, u.OIDCLinked, wantExt = &ext, true, &ext
			}
			h.users.byID[id] = u
			h.svc.WithRegistrationStates(callbackRegStates{id: domain.RegistrationStatePendingApproval})

			_, err := h.callWithClaims(t, nil)
			assert.ErrorIs(t, err, ErrCallbackForbidden, "O19: a registrant waits for an administrator's approval")
			assert.ErrorIs(t, err, ErrCallbackRegistrationPending, "O19: the refusal names the pending approval")
			assert.Zero(t, h.sessionsMinted(), "no session for a registrant held for approval")
			assertNoUpstreamLink(t, h.users.byID[id], wantExt)
			assert.Len(t, h.users.byID, 1, "no user is created")
		})
	}
}

// failingRegStates cannot read any registration state.
type failingRegStates struct{}

func (failingRegStates) UserState(context.Context, uuid.UUID) (string, bool, error) {
	return "", false, errors.New("store unavailable")
}

// O19: a registration state that cannot be read refuses the sign-in, as the
// password path does; nothing is linked and no session is minted.
func TestOIDCCallback_UnreadableRegistrationStateRefuses(t *testing.T) {
	h := newCallbackHarness(t)
	id := uuid.New()
	h.users.byID[id] = &domain.User{ID: id, OrganizationID: h.orgID, Email: "alice@example.com", Role: domain.RoleOrgUser,
		AuthSource: domain.AuthSourceLocal}
	h.svc.WithRegistrationStates(failingRegStates{})

	_, err := h.callWithClaims(t, nil)
	assert.ErrorIs(t, err, ErrCallbackForbidden)
	assert.NotErrorIs(t, err, ErrCallbackRegistrationPending, "an unread state is not reported as a pending approval")
	assert.Zero(t, h.sessionsMinted())
	assertNoUpstreamLink(t, h.users.byID[id], nil)
}

// D-021 control: an approved self-registrant whose organization does not
// require a verified email still signs in upstream while unverified.
func TestOIDCCallback_ApprovedUnverifiedRegistrantSignsInUpstream(t *testing.T) {
	h := newCallbackHarness(t)
	id := uuid.New()
	h.users.byID[id] = &domain.User{ID: id, OrganizationID: h.orgID, Email: "alice@example.com", Role: domain.RoleOrgUser,
		AuthSource: domain.AuthSourceLocal}
	h.svc.WithRegistrationStates(callbackRegStates{id: domain.RegistrationStateActive})

	u, err := h.callWithClaims(t, nil)
	require.NoError(t, err)
	assert.Equal(t, id, u.ID)
	assert.Equal(t, 1, h.sessionsMinted())
	assert.False(t, h.users.byID[id].EmailVerified, "Q-C2-1: a link never changes activation")
}
