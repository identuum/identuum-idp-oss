package handlers

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/lifecycle"
	"github.com/identuum/identuum-idp-oss/internal/mw"
	"github.com/identuum/identuum-idp-oss/internal/repository"
	"github.com/identuum/identuum-idp-oss/internal/service"
	"github.com/identuum/identuum-idp-oss/internal/utils/uuidgen"
)

// ---- in-memory fakes (handlers package) ----

type fakeIDPConfigRepoH struct {
	byID map[uuid.UUID]*domain.IdentityProvider
}

var _ repository.IdentityProviderRepository = (*fakeIDPConfigRepoH)(nil)

func newFakeIDPConfigRepoH() *fakeIDPConfigRepoH {
	return &fakeIDPConfigRepoH{byID: map[uuid.UUID]*domain.IdentityProvider{}}
}

func (f *fakeIDPConfigRepoH) Create(_ context.Context, p *domain.IdentityProvider) (*domain.IdentityProvider, error) {
	id, err := uuidgen.NewV7() // mirrors the identity_providers DEFAULT uuidv7()
	if err != nil {
		return nil, err
	}
	cp := *p
	cp.ID = id
	f.byID[id] = &cp
	out := cp
	return &out, nil
}
func (f *fakeIDPConfigRepoH) GetByID(_ context.Context, id uuid.UUID) (*domain.IdentityProvider, error) {
	p, ok := f.byID[id]
	if !ok {
		return nil, fmt.Errorf("not found")
	}
	cp := *p
	return &cp, nil
}
func (f *fakeIDPConfigRepoH) GetByOrgAndType(_ context.Context, orgID uuid.UUID, t domain.IdentityProviderType) (*domain.IdentityProvider, error) {
	for _, p := range f.byID {
		if p.OrganizationID == orgID && p.Type == t {
			cp := *p
			return &cp, nil
		}
	}
	return nil, fmt.Errorf("not found")
}
func (f *fakeIDPConfigRepoH) ListByOrganization(_ context.Context, orgID uuid.UUID) ([]*domain.IdentityProvider, error) {
	out := []*domain.IdentityProvider{}
	for _, p := range f.byID {
		if p.OrganizationID == orgID {
			cp := *p
			out = append(out, &cp)
		}
	}
	return out, nil
}
func (f *fakeIDPConfigRepoH) Update(_ context.Context, p *domain.IdentityProvider) (*domain.IdentityProvider, error) {
	if _, ok := f.byID[p.ID]; !ok {
		return nil, fmt.Errorf("not found")
	}
	cp := *p
	f.byID[p.ID] = &cp
	out := cp
	return &out, nil
}
func (f *fakeIDPConfigRepoH) Delete(_ context.Context, id uuid.UUID, orgID uuid.UUID) error {
	p, ok := f.byID[id]
	if !ok || p.OrganizationID != orgID {
		return fmt.Errorf("not found")
	}
	delete(f.byID, id)
	return nil
}

type fakeIDPCipherH struct{}

func (fakeIDPCipherH) Encrypt(plaintext string) (string, error) {
	return "enc:" + base64.StdEncoding.EncodeToString([]byte(plaintext)), nil
}
func (fakeIDPCipherH) Decrypt(ciphertext string) (string, error) {
	raw := strings.TrimPrefix(ciphertext, "enc:")
	b, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// ---- engine + principals ----

func newIDPConfigEngine(t *testing.T, principal *domain.Principal) (*gin.Engine, *fakeIDPConfigRepoH, *service.OIDCProviderConfigService) {
	t.Helper()
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	if principal != nil {
		r.Use(mw.InjectPrincipalForTest(principal))
	}
	repo := newFakeIDPConfigRepoH()
	svc := service.NewOIDCProviderConfigService(lifecycle.NewStartupReport(), repo, fakeIDPCipherH{})
	RegisterOrganizationIdentityProviderRoutes(r, OrganizationIdentityProviderHandlerDeps{
		OIDCProviderConfigService: svc,
		Audit:                     &audit.Recorder{},
		StartupReport:             lifecycle.NewStartupReport(),
	})
	return r, repo, svc
}

const idpScopes = "idps:create idps:read idps:update idps:delete"

func idpConfigOrgAdmin(orgID uuid.UUID) *domain.Principal {
	return &domain.Principal{UserID: uuid.New(), OrganizationID: orgID, Role: domain.RoleOrgAdmin, Scope: idpScopes}
}
func idpConfigOrgAdminNoScope(orgID uuid.UUID) *domain.Principal {
	return &domain.Principal{UserID: uuid.New(), OrganizationID: orgID, Role: domain.RoleOrgAdmin}
}
func idpConfigSiteAdmin() *domain.Principal {
	return &domain.Principal{UserID: uuid.New(), OrganizationID: uuid.New(), Role: domain.RoleSiteAdmin, Scope: idpScopes}
}
func idpConfigOrgUser(orgID uuid.UUID) *domain.Principal {
	return &domain.Principal{UserID: uuid.New(), OrganizationID: orgID, Role: domain.RoleOrgUser, Scope: idpScopes}
}

func idpPath(orgID uuid.UUID) string {
	return "/api/v1/organizations/" + orgID.String() + "/identity-provider"
}

func idpDo(t *testing.T, r *gin.Engine, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		b, _ := json.Marshal(body)
		buf.Write(b)
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

func validCreateBody() map[string]any {
	return map[string]any{
		"type": "oidc",
		"name": "Google Workspace",
		"slug": "google",
		"config": map[string]any{
			"issuer_url":    "https://accounts.google.com",
			"client_id":     "cid.apps.googleusercontent.com",
			"client_secret": "TOP-SECRET-VALUE",
			"scopes":        []string{"openid", "email"},
			"email_domains": []string{"example.com"},
		},
	}
}

// ---------- (d) AUTH: own-org only, scope, site_admin refused ----------

// Own-org org_admin with the idps scopes can create/get/update/delete.
func TestIDPConfig_OwnOrgAdmin_FullCRUD(t *testing.T) {
	org := uuid.New()
	r, _, _ := newIDPConfigEngine(t, idpConfigOrgAdmin(org))

	if w := idpDo(t, r, http.MethodPost, idpPath(org), validCreateBody()); w.Code != http.StatusCreated {
		t.Fatalf("create: status = %d, want 201; body=%q", w.Code, w.Body.String())
	}
	if w := idpDo(t, r, http.MethodGet, idpPath(org), nil); w.Code != http.StatusOK {
		t.Fatalf("get: status = %d, want 200; body=%q", w.Code, w.Body.String())
	}
	upd := map[string]any{"name": "Google (updated)", "slug": "google", "config": map[string]any{"issuer_url": "https://accounts.google.com", "client_id": "cid.apps.googleusercontent.com"}}
	if w := idpDo(t, r, http.MethodPut, idpPath(org), upd); w.Code != http.StatusOK {
		t.Fatalf("update: status = %d, want 200; body=%q", w.Code, w.Body.String())
	}
	if w := idpDo(t, r, http.MethodDelete, idpPath(org), nil); w.Code != http.StatusOK {
		t.Fatalf("delete: status = %d, want 200; body=%q", w.Code, w.Body.String())
	}
}

// NO-BLIND-THE-ADMIN: the AUTHENTICATED org-admin identity-provider GET returns
// email_domains so org admins can see/manage what they configured. This surface
// has NO knowledge of the public-lookup hardening flag
// (OrganizationIdentityProviderHandlerDeps carries no hide toggle), so the flag
// that omits email_domains from the PUBLIC lookup can never blind this API.
func TestIDPConfig_AdminGetReturnsEmailDomains(t *testing.T) {
	org := uuid.New()
	r, _, _ := newIDPConfigEngine(t, idpConfigOrgAdmin(org))

	if w := idpDo(t, r, http.MethodPost, idpPath(org), validCreateBody()); w.Code != http.StatusCreated {
		t.Fatalf("create: status = %d, want 201; body=%q", w.Code, w.Body.String())
	}
	w := idpDo(t, r, http.MethodGet, idpPath(org), nil)
	if w.Code != http.StatusOK {
		t.Fatalf("get: status = %d, want 200; body=%q", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if !strings.Contains(body, "email_domains") || !strings.Contains(body, "example.com") {
		t.Errorf("admin GET must return email_domains (org admins manage it): %q", body)
	}
}

// A cross-org org_admin is refused on every verb (path org ≠ actor org).
func TestIDPConfig_CrossOrgAdmin_ForbiddenAllVerbs(t *testing.T) {
	actorOrg := uuid.New()
	otherOrg := uuid.New()
	r, _, _ := newIDPConfigEngine(t, idpConfigOrgAdmin(actorOrg))

	cases := []struct {
		method string
		body   any
	}{
		{http.MethodPost, validCreateBody()},
		{http.MethodGet, nil},
		{http.MethodPut, map[string]any{"name": "x", "config": map[string]any{"issuer_url": "https://accounts.google.com", "client_id": "cid"}}},
		{http.MethodDelete, nil},
	}
	for _, tc := range cases {
		w := idpDo(t, r, tc.method, idpPath(otherOrg), tc.body)
		if w.Code != http.StatusForbidden {
			t.Errorf("%s cross-org: status = %d, want 403 (own-org only); body=%q", tc.method, w.Code, w.Body.String())
		}
	}
}

// An org_admin without the idps scopes is refused (scope gate).
func TestIDPConfig_OrgAdminMissingScope_Forbidden(t *testing.T) {
	org := uuid.New()
	r, _, _ := newIDPConfigEngine(t, idpConfigOrgAdminNoScope(org))
	if w := idpDo(t, r, http.MethodPost, idpPath(org), validCreateBody()); w.Code != http.StatusForbidden {
		t.Errorf("org_admin without idps:create: status = %d, want 403", w.Code)
	}
	if w := idpDo(t, r, http.MethodGet, idpPath(org), nil); w.Code != http.StatusForbidden {
		t.Errorf("org_admin without idps:read: status = %d, want 403", w.Code)
	}
}

// An org_user is refused (not org_admin).
func TestIDPConfig_OrgUser_Forbidden(t *testing.T) {
	org := uuid.New()
	r, _, _ := newIDPConfigEngine(t, idpConfigOrgUser(org))
	if w := idpDo(t, r, http.MethodGet, idpPath(org), nil); w.Code != http.StatusForbidden {
		t.Errorf("org_user: status = %d, want 403", w.Code)
	}
}

// site_admin does NOT manage tenant identity providers → 403 on every verb,
// even though it satisfies the shared org-scope guard.
func TestIDPConfig_SiteAdmin_DoesNotManage(t *testing.T) {
	org := uuid.New()
	r, _, _ := newIDPConfigEngine(t, idpConfigSiteAdmin())
	for _, m := range []struct {
		method string
		body   any
	}{
		{http.MethodPost, validCreateBody()},
		{http.MethodGet, nil},
		{http.MethodPut, map[string]any{"name": "x", "config": map[string]any{"issuer_url": "https://accounts.google.com", "client_id": "cid"}}},
		{http.MethodDelete, nil},
	} {
		w := idpDo(t, r, m.method, idpPath(org), m.body)
		if w.Code != http.StatusForbidden {
			t.Errorf("site_admin %s: status = %d, want 403 (site_admin does not manage tenant IdPs); body=%q", m.method, w.Code, w.Body.String())
		}
	}
}

// Unauthenticated (no principal) is refused 401.
func TestIDPConfig_Unauthenticated_401(t *testing.T) {
	org := uuid.New()
	r, _, _ := newIDPConfigEngine(t, nil)
	if w := idpDo(t, r, http.MethodGet, idpPath(org), nil); w.Code != http.StatusUnauthorized {
		t.Errorf("unauthenticated: status = %d, want 401", w.Code)
	}
}

// ---------- (e) SECRET: client_secret is write-only ----------

// No response (create/get/update) returns the client_secret — neither the
// plaintext nor the stored ciphertext — while the secret IS persisted
// encrypted and recoverable via the service's in-memory decrypt.
func TestIDPConfig_ClientSecretWriteOnly(t *testing.T) {
	org := uuid.New()
	r, repo, svc := newIDPConfigEngine(t, idpConfigOrgAdmin(org))
	const plaintext = "TOP-SECRET-VALUE"

	assertNoSecret := func(label string, w *httptest.ResponseRecorder) {
		body := w.Body.String()
		if strings.Contains(body, plaintext) {
			t.Errorf("%s response leaked the plaintext client_secret: %q", label, body)
		}
		if strings.Contains(body, "client_secret") {
			t.Errorf("%s response contains a client_secret field: %q", label, body)
		}
		if strings.Contains(body, "enc:") {
			t.Errorf("%s response leaked the stored ciphertext: %q", label, body)
		}
	}

	createRec := idpDo(t, r, http.MethodPost, idpPath(org), validCreateBody())
	if createRec.Code != http.StatusCreated {
		t.Fatalf("create: status = %d, want 201; body=%q", createRec.Code, createRec.Body.String())
	}
	assertNoSecret("create", createRec)

	assertNoSecret("get", idpDo(t, r, http.MethodGet, idpPath(org), nil))

	upd := map[string]any{"name": "Google (updated)", "slug": "google", "config": map[string]any{"issuer_url": "https://accounts.google.com", "client_id": "cid.apps.googleusercontent.com"}}
	assertNoSecret("update", idpDo(t, r, http.MethodPut, idpPath(org), upd))

	// The secret WAS persisted, encrypted (not plaintext), and is recoverable
	// only via the service's decrypt path — proving write-only, not lost.
	stored, err := svc.GetOIDCProvider(context.Background(), org)
	if err != nil {
		t.Fatalf("GetOIDCProvider: %v", err)
	}
	if stored.Config.ClientSecretEncrypted == "" || stored.Config.ClientSecretEncrypted == plaintext {
		t.Fatalf("stored secret is not encrypted: %q", stored.Config.ClientSecretEncrypted)
	}
	if len(repo.byID) != 1 {
		t.Fatalf("expected exactly one stored provider, got %d", len(repo.byID))
	}
	plain, err := svc.DecryptClientSecret(stored)
	if err != nil {
		t.Fatalf("DecryptClientSecret: %v", err)
	}
	if plain != plaintext {
		t.Errorf("decrypted secret = %q, want %q", plain, plaintext)
	}
}
