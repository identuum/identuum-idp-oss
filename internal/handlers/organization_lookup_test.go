package handlers

// Unit tests for the public GET /api/v1/auth/organization-lookup route.
// Pin the wire contract identuum-ui's idp-client.orgLookup helper
// reads + the safety invariants the route promises (no secrets, no
// internal URLs, 404 collapse for inactive/deleted).
//
// Test discipline: every fake holds non-secret sentinel values; no
// assertion message echoes provider config / signing key / cookie
// material.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// -------- fakes --------

// stubOrgRepo implements the narrow GetByID / GetBySlug / GetByDomain
// subset of repository.OrganizationRepository the lookup handler
// touches. We do NOT satisfy the full interface (the handler never
// calls the other methods); the type assertion below pins the contract.
type stubOrgRepo struct {
	byID     map[uuid.UUID]*domain.Organization
	bySlug   map[string]*domain.Organization
	byDomain map[string]*domain.Organization
	err      error
}

func (s *stubOrgRepo) GetByID(_ context.Context, id uuid.UUID) (*domain.Organization, error) {
	if s.err != nil {
		return nil, s.err
	}
	if o, ok := s.byID[id]; ok {
		cp := *o
		return &cp, nil
	}
	return nil, domain.ErrOrganizationNotFound
}
func (s *stubOrgRepo) GetBySlug(_ context.Context, slug string) (*domain.Organization, error) {
	if s.err != nil {
		return nil, s.err
	}
	if o, ok := s.bySlug[slug]; ok {
		cp := *o
		return &cp, nil
	}
	return nil, domain.ErrOrganizationNotFound
}
func (s *stubOrgRepo) GetByDomain(_ context.Context, d string) (*domain.Organization, error) {
	if s.err != nil {
		return nil, s.err
	}
	if o, ok := s.byDomain[d]; ok {
		cp := *o
		return &cp, nil
	}
	return nil, domain.ErrOrganizationNotFound
}

// Compile-time check the stub satisfies the production seam interface.
var _ OrganizationLookupOrgSource = (*stubOrgRepo)(nil)

// stubOrgDomainRepo + stubIDPRepo: narrow stubs implementing the
// methods organization_lookup.go calls.
type stubOrgDomainRepo struct {
	verifiedByDomain map[string]*domain.OrganizationDomain
	err              error
}

func (s *stubOrgDomainRepo) GetVerifiedOrganizationDomainByDomain(_ context.Context, d string) (*domain.OrganizationDomain, error) {
	if s.err != nil {
		return nil, s.err
	}
	if v, ok := s.verifiedByDomain[d]; ok {
		cp := *v
		return &cp, nil
	}
	return nil, domain.ErrOrganizationDomainNotFound
}

type stubIDPRepo struct {
	byOrg map[uuid.UUID][]*domain.IdentityProvider
	err   error
}

func (s *stubIDPRepo) ListByOrganization(_ context.Context, orgID uuid.UUID) ([]*domain.IdentityProvider, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.byOrg[orgID], nil
}

// -------- harness --------

// newLookupHarness wires the route under test against minimal stubs.
// The OrganizationRepo dep is required by the route registration; the
// other two are conditionally populated by the caller.
func newLookupHarness(t *testing.T, deps OrganizationLookupHandlerDeps) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	RegisterOrganizationLookupRoute(r, deps)
	return r
}

// -------- shared seeds --------

func seedActiveOrg() (orgID uuid.UUID, org *domain.Organization) {
	orgID = uuid.New()
	org = &domain.Organization{
		ID:         orgID,
		Name:       "Acme Corp",
		Domain:     "acme.example.invalid",
		OrgSlug:    "acme",
		Active:     true,
		AuthPolicy: domain.AuthPolicyLocalOnly,
		MFAPolicy:  "optional",
	}
	return
}

// -------- tests --------

func TestOrgLookup_MissingParams_400(t *testing.T) {
	repo := &stubOrgRepo{}
	r := newLookupHarness(t, OrganizationLookupHandlerDeps{OrganizationRepo: repo})

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/auth/organization-lookup", nil))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status: want 400, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), `"invalid_request"`) {
		t.Fatalf("body: want invalid_request, got %q", w.Body.String())
	}
}

func TestOrgLookup_NoOrgRepo_RouteAbsent(t *testing.T) {
	// Without OrganizationRepo, the route MUST NOT register.
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	RegisterOrganizationLookupRoute(r, OrganizationLookupHandlerDeps{})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/auth/organization-lookup?domain=x.example", nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("status: want 404 (route absent), got %d", w.Code)
	}
}

func TestOrgLookup_BySlug_Success(t *testing.T) {
	orgID, org := seedActiveOrg()
	repo := &stubOrgRepo{
		byID:   map[uuid.UUID]*domain.Organization{orgID: org},
		bySlug: map[string]*domain.Organization{"acme": org},
	}
	r := newLookupHarness(t, OrganizationLookupHandlerDeps{OrganizationRepo: repo})

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/auth/organization-lookup?slug=acme", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status: want 200, got %d body=%q", w.Code, w.Body.String())
	}
	var body map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if body["slug"] != "acme" {
		t.Fatalf("slug: want acme, got %v", body["slug"])
	}
	if body["name"] != "Acme Corp" {
		t.Fatalf("name: want Acme Corp, got %v", body["name"])
	}
	if body["auth_policy"] != string(domain.AuthPolicyLocalOnly) {
		t.Fatalf("auth_policy: want local_only, got %v", body["auth_policy"])
	}
	if body["domain"] != "acme.example.invalid" {
		t.Fatalf("domain projection mismatch, got %v", body["domain"])
	}
	if _, ok := body["identity_providers"]; !ok {
		t.Fatal("identity_providers field missing from response")
	}
	idps, _ := body["identity_providers"].([]any)
	if idps == nil {
		t.Fatal("identity_providers must be non-nil array (even if empty)")
	}
	if len(idps) != 0 {
		t.Fatalf("identity_providers: want empty, got %d", len(idps))
	}
}

func TestOrgLookup_ByDomain_Success(t *testing.T) {
	orgID, org := seedActiveOrg()
	repo := &stubOrgRepo{
		byID:     map[uuid.UUID]*domain.Organization{orgID: org},
		byDomain: map[string]*domain.Organization{"acme.example.invalid": org},
	}
	r := newLookupHarness(t, OrganizationLookupHandlerDeps{OrganizationRepo: repo})

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/auth/organization-lookup?domain=ACME.example.invalid", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status: want 200, got %d body=%q", w.Code, w.Body.String())
	}
	var body map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if body["slug"] != "acme" {
		t.Fatalf("slug: want acme, got %v", body["slug"])
	}
}

func TestOrgLookup_VerifiedDomainTakesPrecedence(t *testing.T) {
	// The verified-domain global index should win over the legacy
	// organizations.domain column. We seed BOTH paths to different
	// orgs and assert the verified-domain org is the one returned.
	primaryOrgID := uuid.New()
	primaryOrg := &domain.Organization{
		ID:         primaryOrgID,
		Name:       "Primary",
		Domain:     "primary.example.invalid",
		OrgSlug:    "primary",
		Active:     true,
		AuthPolicy: domain.AuthPolicyLocalOnly,
	}
	verifiedOrgID := uuid.New()
	verifiedOrg := &domain.Organization{
		ID:         verifiedOrgID,
		Name:       "Verified",
		Domain:     "different.example.invalid",
		OrgSlug:    "verified",
		Active:     true,
		AuthPolicy: domain.AuthPolicyLocalOnly,
	}
	repo := &stubOrgRepo{
		byID: map[uuid.UUID]*domain.Organization{
			primaryOrgID:  primaryOrg,
			verifiedOrgID: verifiedOrg,
		},
		byDomain: map[string]*domain.Organization{
			"shared.example.invalid": primaryOrg, // legacy column → primary
		},
	}
	domRepo := &stubOrgDomainRepo{
		verifiedByDomain: map[string]*domain.OrganizationDomain{
			"shared.example.invalid": {
				ID:             uuid.New(),
				OrganizationID: verifiedOrgID,
				Domain:         "shared.example.invalid",
				VerifiedAt:     ptrTime(time.Now()),
			},
		},
	}
	r := newLookupHarness(t, OrganizationLookupHandlerDeps{
		OrganizationRepo:       repo,
		OrganizationDomainRepo: domRepo,
	})

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/auth/organization-lookup?domain=shared.example.invalid", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status: want 200, got %d", w.Code)
	}
	var body map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if body["slug"] != "verified" {
		t.Fatalf("verified-domain index should win; got slug=%v", body["slug"])
	}
}

func TestOrgLookup_UnknownDomain_404(t *testing.T) {
	repo := &stubOrgRepo{
		byID:     map[uuid.UUID]*domain.Organization{},
		byDomain: map[string]*domain.Organization{},
	}
	r := newLookupHarness(t, OrganizationLookupHandlerDeps{OrganizationRepo: repo})

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/auth/organization-lookup?domain=nobody.example.invalid", nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("status: want 404, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), `"organization_not_found"`) {
		t.Fatalf("body: want organization_not_found, got %q", w.Body.String())
	}
}

func TestOrgLookup_InactiveOrg_404(t *testing.T) {
	orgID, org := seedActiveOrg()
	org.Active = false
	repo := &stubOrgRepo{
		byID:     map[uuid.UUID]*domain.Organization{orgID: org},
		byDomain: map[string]*domain.Organization{"acme.example.invalid": org},
	}
	r := newLookupHarness(t, OrganizationLookupHandlerDeps{OrganizationRepo: repo})

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/auth/organization-lookup?domain=acme.example.invalid", nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("inactive org must collapse to 404, got %d", w.Code)
	}
	// Wire response MUST NOT distinguish inactive vs missing.
	if !strings.Contains(w.Body.String(), `"organization_not_found"`) {
		t.Fatalf("body must use organization_not_found sentinel even for inactive org; got %q", w.Body.String())
	}
}

func TestOrgLookup_SoftDeletedOrg_404(t *testing.T) {
	orgID, org := seedActiveOrg()
	now := time.Now()
	org.DeletedAt = &now
	repo := &stubOrgRepo{
		byID:     map[uuid.UUID]*domain.Organization{orgID: org},
		byDomain: map[string]*domain.Organization{"acme.example.invalid": org},
	}
	r := newLookupHarness(t, OrganizationLookupHandlerDeps{OrganizationRepo: repo})

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/auth/organization-lookup?domain=acme.example.invalid", nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("soft-deleted org must collapse to 404, got %d", w.Code)
	}
}

func TestOrgLookup_RepoError_500NotLeaking(t *testing.T) {
	repo := &stubOrgRepo{err: errors.New("internal-db-fault")}
	r := newLookupHarness(t, OrganizationLookupHandlerDeps{OrganizationRepo: repo})

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/auth/organization-lookup?domain=acme.example.invalid", nil))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status: want 500, got %d", w.Code)
	}
	if strings.Contains(w.Body.String(), "internal-db-fault") {
		t.Fatal("response body leaked underlying DB error message")
	}
}

func TestOrgLookup_IDPProjection_SafeFieldsOnly(t *testing.T) {
	// Seed an active IDP with a fully-populated config (including
	// secret-bearing fields) and assert the response carries ONLY
	// the safe projection (id/type/name/login_url/email_domains).
	orgID, org := seedActiveOrg()
	repo := &stubOrgRepo{
		byID:     map[uuid.UUID]*domain.Organization{orgID: org},
		byDomain: map[string]*domain.Organization{"acme.example.invalid": org},
	}
	idpID := uuid.New()
	idps := &stubIDPRepo{
		byOrg: map[uuid.UUID][]*domain.IdentityProvider{
			orgID: {
				{
					ID:             idpID,
					OrganizationID: orgID,
					Type:           domain.IDPTypeOIDC,
					Name:           "Acme OIDC",
					Active:         true,
					Config: domain.ProviderConfig{
						IssuerURL:             "https://issuer.example.invalid",
						ClientID:              "client-id-NOT-secret",
						ClientSecretEncrypted: "ENCRYPTED-SHOULD-NEVER-LEAK",
						BindDN:                "cn=binder",
						BindPasswordEncrypted: "BIND-PW-SHOULD-NEVER-LEAK",
						EmailDomains:          []string{"acme.example.invalid", "alt.example.invalid"},
					},
				},
			},
		},
	}
	r := newLookupHarness(t, OrganizationLookupHandlerDeps{
		OrganizationRepo:     repo,
		IdentityProviderRepo: idps,
	})

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/auth/organization-lookup?domain=acme.example.invalid", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status: want 200, got %d body=%q", w.Code, w.Body.String())
	}
	body := w.Body.String()
	// SAFE fields present:
	if !strings.Contains(body, `"Acme OIDC"`) {
		t.Fatal("response missing IdP name")
	}
	if !strings.Contains(body, `"oidc"`) {
		t.Fatal("response missing IdP type")
	}
	if !strings.Contains(body, `"acme.example.invalid"`) || !strings.Contains(body, `"alt.example.invalid"`) {
		t.Fatal("response missing IdP email_domains")
	}
	// UNSAFE fields MUST be absent:
	for _, banned := range []string{
		"ENCRYPTED-SHOULD-NEVER-LEAK",
		"BIND-PW-SHOULD-NEVER-LEAK",
		"client-id-NOT-secret", // client_id is operationally sensitive enough to keep out of public lookup
		"https://issuer.example.invalid",
		"client_secret",
		"bind_password",
		"issuer_url",
	} {
		if strings.Contains(body, banned) {
			t.Fatalf("public response leaked banned field/value: %q", banned)
		}
	}
}

// loginURLResponse is the minimal shape needed to assert login_url
// projection precisely (org-level + per-IdP).
type loginURLResponse struct {
	LoginURL          string `json:"login_url"`
	IdentityProviders []struct {
		Type     string `json:"type"`
		LoginURL string `json:"login_url"`
	} `json:"identity_providers"`
}

// SHIPPED: an active type=oidc provider projects the OSS login-initiation
// route both at the org level and on its IdP entry, and the URL leaks NO
// provider internals.
func TestOrgLookup_LoginURL_PopulatedForActiveOIDC(t *testing.T) {
	orgID, org := seedActiveOrg()
	repo := &stubOrgRepo{
		byID:     map[uuid.UUID]*domain.Organization{orgID: org},
		byDomain: map[string]*domain.Organization{"acme.example.invalid": org},
	}
	idpID := uuid.New()
	idps := &stubIDPRepo{
		byOrg: map[uuid.UUID][]*domain.IdentityProvider{
			orgID: {{
				ID: idpID, OrganizationID: orgID, Type: domain.IDPTypeOIDC,
				Name: "Acme OIDC", Active: true,
				Config: domain.ProviderConfig{
					ClientID:              "client-id-NOT-secret",
					ClientSecretEncrypted: "ENCRYPTED-SHOULD-NEVER-LEAK",
					IssuerURL:             "https://issuer.example.invalid",
					EmailDomains:          []string{"acme.example.invalid"},
				},
			}},
		},
	}
	r := newLookupHarness(t, OrganizationLookupHandlerDeps{OrganizationRepo: repo, IdentityProviderRepo: idps})

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/auth/organization-lookup?domain=acme.example.invalid", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status: want 200, got %d body=%q", w.Code, w.Body.String())
	}
	want := "/api/v1/auth/idp/" + idpID.String() + "/login"
	var got loginURLResponse
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.LoginURL != want {
		t.Errorf("org login_url = %q, want %q", got.LoginURL, want)
	}
	if len(got.IdentityProviders) != 1 || got.IdentityProviders[0].LoginURL != want {
		t.Errorf("per-IdP login_url = %+v, want %q", got.IdentityProviders, want)
	}
	// The login URL is a same-origin relative path with no provider internals.
	for _, banned := range []string{"ENCRYPTED-SHOULD-NEVER-LEAK", "client-id-NOT-secret", "https://issuer.example.invalid"} {
		if strings.Contains(got.LoginURL, banned) {
			t.Fatalf("login_url leaked a provider internal: %q", banned)
		}
	}
}

// No active OIDC provider ⇒ org-level login_url is empty (UI falls through
// to the password step).
func TestOrgLookup_LoginURL_EmptyWhenNoActiveOIDC(t *testing.T) {
	orgID, org := seedActiveOrg()
	repo := &stubOrgRepo{
		byID:     map[uuid.UUID]*domain.Organization{orgID: org},
		byDomain: map[string]*domain.Organization{"acme.example.invalid": org},
	}
	// No IdentityProviderRepo wired ⇒ empty projection.
	r := newLookupHarness(t, OrganizationLookupHandlerDeps{OrganizationRepo: repo})

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/auth/organization-lookup?domain=acme.example.invalid", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status: want 200, got %d", w.Code)
	}
	var got loginURLResponse
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.LoginURL != "" {
		t.Errorf("org login_url = %q, want empty (no active OIDC provider)", got.LoginURL)
	}
	if len(got.IdentityProviders) != 0 {
		t.Errorf("identity_providers = %+v, want empty", got.IdentityProviders)
	}
}

// HARDENING FLAG SET → the PUBLIC projection OMITS email_domains (neither the
// key nor the federated-domain values appear), while id/type/name/login_url are
// STILL returned so SSO login is unaffected.
func TestOrgLookup_HideEmailDomains_OmitsFromPublicProjection(t *testing.T) {
	orgID, org := seedActiveOrg()
	repo := &stubOrgRepo{
		byID:     map[uuid.UUID]*domain.Organization{orgID: org},
		byDomain: map[string]*domain.Organization{"acme.example.invalid": org},
	}
	idpID := uuid.New()
	// Federated-domain values chosen to NOT collide with the org's own domain,
	// so their absence from the body unambiguously proves the omission.
	idps := &stubIDPRepo{
		byOrg: map[uuid.UUID][]*domain.IdentityProvider{
			orgID: {{
				ID: idpID, OrganizationID: orgID, Type: domain.IDPTypeOIDC,
				Name: "Acme OIDC", Active: true,
				Config: domain.ProviderConfig{EmailDomains: []string{"federated-corp.invalid", "alt-federated.invalid"}},
			}},
		},
	}
	r := newLookupHarness(t, OrganizationLookupHandlerDeps{
		OrganizationRepo:                 repo,
		IdentityProviderRepo:             idps,
		HideIdentityProviderEmailDomains: true,
	})

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/auth/organization-lookup?domain=acme.example.invalid", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status: want 200, got %d body=%q", w.Code, w.Body.String())
	}
	body := w.Body.String()
	// email_domains OMITTED — the key is gone (omitempty) and neither
	// federated-domain value is disclosed.
	if strings.Contains(body, "email_domains") {
		t.Errorf("email_domains key present despite the hide flag: %q", body)
	}
	for _, d := range []string{"federated-corp.invalid", "alt-federated.invalid"} {
		if strings.Contains(body, d) {
			t.Errorf("federated domain %q leaked despite the hide flag", d)
		}
	}
	// id/type/name/login_url STILL returned — SSO login is unaffected.
	if !strings.Contains(body, `"Acme OIDC"`) || !strings.Contains(body, `"oidc"`) {
		t.Errorf("hide flag dropped id/type/name: %q", body)
	}
	want := "/api/v1/auth/idp/" + idpID.String() + "/login"
	var got loginURLResponse
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.LoginURL != want || len(got.IdentityProviders) != 1 || got.IdentityProviders[0].LoginURL != want {
		t.Errorf("login_url not returned under the hide flag: org=%q idps=%+v want=%q", got.LoginURL, got.IdentityProviders, want)
	}
}

func TestOrgLookup_InactiveIDPFilteredOut(t *testing.T) {
	orgID, org := seedActiveOrg()
	repo := &stubOrgRepo{
		byID:     map[uuid.UUID]*domain.Organization{orgID: org},
		byDomain: map[string]*domain.Organization{"acme.example.invalid": org},
	}
	idps := &stubIDPRepo{
		byOrg: map[uuid.UUID][]*domain.IdentityProvider{
			orgID: {
				{ID: uuid.New(), OrganizationID: orgID, Type: domain.IDPTypeOIDC, Name: "Inactive", Active: false},
				{ID: uuid.New(), OrganizationID: orgID, Type: domain.IDPTypeOIDC, Name: "Active", Active: true},
			},
		},
	}
	r := newLookupHarness(t, OrganizationLookupHandlerDeps{
		OrganizationRepo:     repo,
		IdentityProviderRepo: idps,
	})

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/auth/organization-lookup?domain=acme.example.invalid", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status: want 200, got %d", w.Code)
	}
	if strings.Contains(w.Body.String(), `"Inactive"`) {
		t.Fatal("inactive IdP must NOT appear in public lookup response")
	}
	if !strings.Contains(w.Body.String(), `"Active"`) {
		t.Fatal("active IdP must appear")
	}
}

// ptrTime returns a pointer to a time.Time for struct literal use.
func ptrTime(t time.Time) *time.Time { return &t }
