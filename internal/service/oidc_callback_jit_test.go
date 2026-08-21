package service

import (
	"context"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/repository"
)

// fakeUserRepoForCallback is an in-memory UserRepository with REAL by-external-id
// / by-email / create / update behavior (the existing service-test doubles stub
// those lookups). createErr forces a create failure for the 500 path.
type fakeUserRepoForCallback struct {
	byID      map[uuid.UUID]*domain.User
	createErr error
}

var _ repository.UserRepository = (*fakeUserRepoForCallback)(nil)

func newCallbackUserRepo() *fakeUserRepoForCallback {
	return &fakeUserRepoForCallback{byID: map[uuid.UUID]*domain.User{}}
}

func (r *fakeUserRepoForCallback) Create(_ context.Context, u *domain.User) (*domain.User, error) {
	if r.createErr != nil {
		return nil, r.createErr
	}
	for _, e := range r.byID {
		if e.OrganizationID == u.OrganizationID && strings.EqualFold(e.Email, u.Email) {
			return nil, domain.ErrUserAlreadyExists
		}
	}
	if u.ID == uuid.Nil {
		u.ID = uuid.New()
	}
	cp := *u
	r.byID[cp.ID] = &cp
	out := cp
	return &out, nil
}

func (r *fakeUserRepoForCallback) GetByExternalID(_ context.Context, orgID uuid.UUID, extID string) (*domain.User, error) {
	for _, u := range r.byID {
		if u.OrganizationID == orgID && u.ExternalID != nil && *u.ExternalID == extID {
			cp := *u
			return &cp, nil
		}
	}
	return nil, domain.ErrUserNotFound
}

func (r *fakeUserRepoForCallback) GetByEmailAndOrgID(_ context.Context, orgID uuid.UUID, email string) (*domain.User, error) {
	for _, u := range r.byID {
		if u.OrganizationID == orgID && strings.EqualFold(u.Email, email) {
			cp := *u
			return &cp, nil
		}
	}
	return nil, domain.ErrUserNotFound
}

func (r *fakeUserRepoForCallback) Update(_ context.Context, id, orgID uuid.UUID, opts repository.UpdateUserOptions) (*domain.User, error) {
	u, ok := r.byID[id]
	if !ok || u.OrganizationID != orgID {
		return nil, domain.ErrUserNotFound
	}
	if opts.ExternalID != nil {
		v := *opts.ExternalID
		u.ExternalID = &v
	}
	if opts.OIDCIssuer != nil {
		v := *opts.OIDCIssuer
		u.OIDCIssuer = &v
	}
	if opts.OIDCLinked != nil {
		u.OIDCLinked = *opts.OIDCLinked
	}
	if opts.AuthSource != nil {
		u.AuthSource = *opts.AuthSource
	}
	if opts.Email != nil {
		u.Email = *opts.Email
	}
	if opts.Name != nil {
		v := *opts.Name
		u.Name = &v
	}
	cp := *u
	return &cp, nil
}

func (r *fakeUserRepoForCallback) GetByID(_ context.Context, id uuid.UUID) (*domain.User, error) {
	u, ok := r.byID[id]
	if !ok {
		return nil, domain.ErrUserNotFound
	}
	cp := *u
	return &cp, nil
}

// ---- remaining UserRepository surface: unused stubs ----

func (r *fakeUserRepoForCallback) FindUsersByEmail(context.Context, string) ([]*domain.User, error) {
	return nil, nil
}
func (r *fakeUserRepoForCallback) GetByIDWithOrg(context.Context, uuid.UUID) (*domain.User, error) {
	return nil, domain.ErrUserNotFound
}
func (r *fakeUserRepoForCallback) Delete(context.Context, uuid.UUID, uuid.UUID) error   { return nil }
func (r *fakeUserRepoForCallback) Undelete(context.Context, uuid.UUID, uuid.UUID) error { return nil }
func (r *fakeUserRepoForCallback) List(context.Context, repository.ListUserOptions) ([]*domain.User, int, error) {
	return nil, 0, nil
}
func (r *fakeUserRepoForCallback) ListByOrganization(context.Context, uuid.UUID, repository.ListUserOptions) ([]*domain.User, int, error) {
	return nil, 0, nil
}
func (r *fakeUserRepoForCallback) UpdateLastLogin(context.Context, uuid.UUID) error { return nil }
func (r *fakeUserRepoForCallback) ConsumeRecoveryCode(context.Context, uuid.UUID, string) (*domain.User, bool, error) {
	return nil, false, nil
}
func (r *fakeUserRepoForCallback) CountByOrganization(context.Context, uuid.UUID) (int, error) {
	return 0, nil
}
func (r *fakeUserRepoForCallback) CountOrgAdminsByOrganization(context.Context, uuid.UUID) (int, error) {
	return 0, nil
}
func (r *fakeUserRepoForCallback) CountOrgAdminsByOrganizations(context.Context, []uuid.UUID) (map[uuid.UUID]int, error) {
	return nil, nil
}
func (r *fakeUserRepoForCallback) CountVerifiedOrgAdminsByOrganization(context.Context, uuid.UUID) (int, error) {
	return 0, nil
}
func (r *fakeUserRepoForCallback) CountVerifiedOrgAdminsByOrganizations(context.Context, []uuid.UUID) (map[uuid.UUID]int, error) {
	return nil, nil
}
func (r *fakeUserRepoForCallback) VerifyPassword(context.Context, string, string) error { return nil }
func (r *fakeUserRepoForCallback) HashPassword(string) (string, error)                  { return "", nil }
func (r *fakeUserRepoForCallback) GetUserOrganization(context.Context, uuid.UUID) (*domain.Organization, error) {
	return nil, nil
}
func (r *fakeUserRepoForCallback) UpdateOrganizationID(context.Context, uuid.UUID, uuid.UUID) error {
	return nil
}

// ---- JIT tests ----

// callWithClaims signs the (optionally mutated) claims, runs the full callback,
// and unwraps the RESOLVED LOCAL user so the JIT tests stay focused on
// provisioning. On any error the user is nil and the error propagates (a
// resolved-but-forbidden path never mints a session).
func (h *callbackHarness) callWithClaims(t *testing.T, mutate func(claims jwt.MapClaims)) (*domain.User, error) {
	t.Helper()
	c := h.validClaims()
	if mutate != nil {
		mutate(c)
	}
	*h.idToken = h.signEdDSA(t, h.priv, h.kid, c)
	res, err := h.call()
	if err != nil {
		return nil, err
	}
	return res.User, nil
}

// (allow-list reject) An email whose domain is not allow-listed is refused
// (403) and NO user is created.
// RULE: OIDC-JIT-GATE-1
func TestOIDCCallback_JIT_NonAllowlistedDomainRejected(t *testing.T) {
	// PREMISE (non-emptiness): prove on a twin harness — same allow-list,
	// PERMITTED email — that the JIT success path actually lands users in
	// users.byID; otherwise the absence assertion below passes vacuously
	// against a store the service never writes to.
	ctrl := newCallbackHarness(t)
	ctrl.providers.byID[ctrl.pid].Config.EmailDomains = []string{"allowed.example"}
	ctrl.providers.byID[ctrl.pid].Config.AllowExternalDomains = false
	if _, err := ctrl.callWithClaims(t, func(c jwt.MapClaims) { c["email"] = "ok@allowed.example" }); err != nil {
		t.Fatalf("premise control call: %v", err)
	}
	if len(ctrl.users.byID) == 0 {
		t.Fatal("PREMISE broken: JIT success path landed no user in users.byID — refusal check would be vacuous")
	}

	h := newCallbackHarness(t)
	h.providers.byID[h.pid].Config.EmailDomains = []string{"allowed.example"}
	h.providers.byID[h.pid].Config.AllowExternalDomains = false

	_, err := h.callWithClaims(t, func(c jwt.MapClaims) { c["email"] = "eve@evil.example" })
	if err != ErrCallbackForbidden {
		t.Errorf("err = %v, want ErrCallbackForbidden", err)
	}
	if len(h.users.byID) != 0 {
		t.Errorf("a user was created for an off-allow-list email: %d", len(h.users.byID))
	}
}

// (AllowExternalDomains bypass) With the bypass on, an off-list domain is
// permitted and JIT-provisioned.
func TestOIDCCallback_JIT_AllowExternalDomainsBypass(t *testing.T) {
	h := newCallbackHarness(t)
	h.providers.byID[h.pid].Config.EmailDomains = nil
	h.providers.byID[h.pid].Config.AllowExternalDomains = true

	u, err := h.callWithClaims(t, func(c jwt.MapClaims) { c["email"] = "eve@anywhere.example" })
	if err != nil {
		t.Fatalf("bypass: %v", err)
	}
	if u == nil || u.Email != "eve@anywhere.example" {
		t.Errorf("expected JIT user for the bypassed domain, got %+v", u)
	}
}

// (unverified email) email_verified=false ⇒ no provisioning (403).
func TestOIDCCallback_JIT_UnverifiedEmailRejected(t *testing.T) {
	h := newCallbackHarness(t)
	_, err := h.callWithClaims(t, func(c jwt.MapClaims) { c["email_verified"] = false })
	if err != ErrCallbackForbidden {
		t.Errorf("err = %v, want ErrCallbackForbidden", err)
	}
	if len(h.users.byID) != 0 {
		t.Errorf("unverified email provisioned a user: %d", len(h.users.byID))
	}
}

// (JIT create) Allow-listed verified email with no match ⇒ a passwordless
// federated user is created with the ExternalID stamped.
func TestOIDCCallback_JIT_CreatesFederatedUser(t *testing.T) {
	h := newCallbackHarness(t)
	u, err := h.callWithClaims(t, nil)
	if err != nil {
		t.Fatalf("JIT create: %v", err)
	}
	if u.Email != "alice@example.com" {
		t.Errorf("email = %q", u.Email)
	}
	if u.ExternalID == nil || *u.ExternalID != h.srv.URL+"|upstream-user-123" {
		t.Errorf("ExternalID = %v, want issuer|sub stamped", u.ExternalID)
	}
	if u.PasswordHash != domain.NoPasswordSentinel {
		t.Errorf("PasswordHash = %q, want the no-password sentinel", u.PasswordHash)
	}
	if u.AuthSource != domain.AuthSourceIDJag {
		t.Errorf("AuthSource = %q, want id_jag", u.AuthSource)
	}
	if !u.EmailVerified {
		t.Errorf("federated user must be email-verified")
	}
	if len(h.users.byID) != 1 {
		t.Errorf("expected exactly one created user, got %d", len(h.users.byID))
	}
}

// (match by ExternalID) A returning user (same issuer|sub) resolves to the
// SAME local user — no duplicate is created.
func TestOIDCCallback_JIT_MatchByExternalIDNoDuplicate(t *testing.T) {
	h := newCallbackHarness(t)
	extID := h.srv.URL + "|upstream-user-123"
	existingID := uuid.New()
	h.users.byID[existingID] = &domain.User{
		ID: existingID, OrganizationID: h.orgID, Email: "alice@example.com",
		ExternalID: &extID, AuthSource: domain.AuthSourceIDJag, EmailVerified: true,
	}
	u, err := h.callWithClaims(t, nil)
	if err != nil {
		t.Fatalf("match by external id: %v", err)
	}
	if u.ID != existingID {
		t.Errorf("resolved user id = %v, want the existing %v", u.ID, existingID)
	}
	if len(h.users.byID) != 1 {
		t.Errorf("a duplicate was created: %d users", len(h.users.byID))
	}
}

// (no-email-takeover) ExternalID wins: a returning user whose provider changed
// their email resolves to THEIR account, not the account that now holds that
// email; and a NEW external identity cannot hijack an email already bound to a
// different external identity.
// RULE: OIDC-TAKEOVER-1
func TestOIDCCallback_JIT_NoEmailTakeover(t *testing.T) {
	// Case A — ExternalID-first: returning user's changed email does not match another account.
	t.Run("external id wins over changed email", func(t *testing.T) {
		h := newCallbackHarness(t)
		extID := h.srv.URL + "|upstream-user-123"
		mineID := uuid.New()
		otherID := uuid.New()
		h.users.byID[mineID] = &domain.User{ID: mineID, OrganizationID: h.orgID, Email: "old@example.com", ExternalID: &extID, EmailVerified: true}
		h.users.byID[otherID] = &domain.User{ID: otherID, OrganizationID: h.orgID, Email: "victim@example.com", EmailVerified: true}
		// Returning with the SAME externalID but the victim's email as the new claim.
		u, err := h.callWithClaims(t, func(c jwt.MapClaims) { c["email"] = "victim@example.com" })
		if err != nil {
			t.Fatalf("%v", err)
		}
		if u.ID != mineID {
			t.Errorf("resolved %v, want my own account %v (ExternalID must win, no hijack of %v)", u.ID, mineID, otherID)
		}
	})
	// Case B — a NEW external identity cannot seize an email bound to a DIFFERENT external identity.
	t.Run("new identity cannot hijack a bound email", func(t *testing.T) {
		h := newCallbackHarness(t)
		otherExt := "https://other.example|other-sub"
		victimID := uuid.New()
		h.users.byID[victimID] = &domain.User{ID: victimID, OrganizationID: h.orgID, Email: "alice@example.com", ExternalID: &otherExt, EmailVerified: true}
		// Incoming identity is srv.URL|upstream-user-123 (new), email alice@example.com (bound to otherExt).
		_, err := h.callWithClaims(t, nil)
		if err != ErrCallbackForbidden {
			t.Errorf("err = %v, want ErrCallbackForbidden (no hijack of a bound email)", err)
		}
	})
}

// (create failure) A repository create failure surfaces as a provision error
// (500-class) and no session is produced.
func TestOIDCCallback_JIT_CreateFailure(t *testing.T) {
	h := newCallbackHarness(t)
	h.users.createErr = context.DeadlineExceeded
	_, err := h.callWithClaims(t, nil)
	if err != ErrCallbackProvisionFailed {
		t.Errorf("err = %v, want ErrCallbackProvisionFailed", err)
	}
}
