package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/mw"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// dcrEngine wires the DCR endpoint on top of the in-memory client
// repo / live ClientService used by the other live OAuth admin
// tests. Kept private to this test file so the fixture surface
// stays tight.
type dcrEngine struct {
	r          *gin.Engine
	clientRepo *memClientRepo
	rec        *audit.Recorder
}

func newDCREngine(t *testing.T, principal *domain.Principal) dcrEngine {
	t.Helper()
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	if principal != nil {
		r.Use(mw.InjectPrincipalForTest(principal))
	}
	clientRepo := newMemClientRepo()
	rec := &audit.Recorder{}
	RegisterDCRRoutes(r, DCRHandlerDeps{
		ClientService: service.NewClientService(nil, clientRepo),
		Audit:         rec,
	})
	return dcrEngine{r: r, clientRepo: clientRepo, rec: rec}
}

func dcrPost(t *testing.T, eng dcrEngine, body any) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatalf("encode: %v", err)
		}
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/register", &buf)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	eng.r.ServeHTTP(rec, req)
	return rec
}

// TestDCR_RegisterSecretReturnedOnceAndAuditEmits is the golden
// path: a site_admin caller registers a confidential client and
// receives the client_id + one-shot client_secret in the response.
// Audit emits the dcr_registered event WITHOUT the secret.
func TestDCR_RegisterSecretReturnedOnceAndAuditEmits(t *testing.T) {
	eng := newDCREngine(t, siteAdminPrincipal())
	rec := dcrPost(t, eng, map[string]any{
		"client_name":   "Acme RP",
		"redirect_uris": []string{"https://rp.example.com/cb"},
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%q", rec.Code, rec.Body.String())
	}
	var resp dcrResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.ClientID == "" {
		t.Error("response must carry client_id")
	}
	if resp.ClientSecret == "" {
		t.Error("confidential client must receive one-time client_secret in response body")
	}
	if resp.ClientSecretExpiresAt != 0 {
		t.Errorf("client_secret_expires_at = %d; want 0 (never expires)", resp.ClientSecretExpiresAt)
	}
	if resp.ClientIDIssuedAt <= 0 {
		t.Errorf("client_id_issued_at = %d; want positive unix timestamp", resp.ClientIDIssuedAt)
	}
	// Sanity: redirect URIs round-trip.
	if len(resp.RedirectURIs) != 1 || resp.RedirectURIs[0] != "https://rp.example.com/cb" {
		t.Errorf("redirect URIs round-trip mismatch: %+v", resp.RedirectURIs)
	}
	events := eng.rec.Events()
	if len(events) != 1 || events[0].Action != "client.dcr_registered" || events[0].Outcome != "success" {
		t.Fatalf("expected one client.dcr_registered audit event, got %+v", events)
	}
	// Secret must NOT appear anywhere in audit metadata, even as
	// a substring (defensive check for accidental future logging).
	for k, v := range events[0].Metadata {
		if s, ok := v.(string); ok {
			if s == resp.ClientSecret || (resp.ClientSecret != "" && strings.Contains(s, resp.ClientSecret)) {
				t.Errorf("audit metadata key %q leaks client_secret: %v", k, v)
			}
		}
	}
}

// TestDCR_PublicClientHasNoSecret pins that a client whose declared
// token_endpoint_auth_method is "none" is treated as public and
// receives no client_secret.
func TestDCR_PublicClientHasNoSecret(t *testing.T) {
	eng := newDCREngine(t, siteAdminPrincipal())
	rec := dcrPost(t, eng, map[string]any{
		"client_name":                "Public SPA",
		"redirect_uris":              []string{"https://spa.example.com/cb"},
		"token_endpoint_auth_method": "none",
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%q", rec.Code, rec.Body.String())
	}
	var resp dcrResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.ClientSecret != "" {
		t.Errorf("public client must NOT receive client_secret; got %q", resp.ClientSecret)
	}
}

// TestDCR_MissingClientNameReturns400 pins the RFC 7591
// invalid_client_metadata error envelope for a missing client_name.
func TestDCR_MissingClientNameReturns400(t *testing.T) {
	eng := newDCREngine(t, siteAdminPrincipal())
	rec := dcrPost(t, eng, map[string]any{
		"redirect_uris": []string{"https://x.example.com/cb"},
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	var env map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &env)
	if env["error"] != "invalid_client_metadata" {
		t.Errorf("error field = %v; want invalid_client_metadata", env["error"])
	}
}

// TestDCR_MissingRedirectURIsReturns400 pins the RFC 7591
// invalid_client_metadata error envelope for missing redirect_uris.
func TestDCR_MissingRedirectURIsReturns400(t *testing.T) {
	eng := newDCREngine(t, siteAdminPrincipal())
	rec := dcrPost(t, eng, map[string]any{
		"client_name": "X",
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	var env map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &env)
	if env["error"] != "invalid_client_metadata" {
		t.Errorf("error field = %v; want invalid_client_metadata", env["error"])
	}
}

// TestDCR_UnknownGrantTypeRejected pins that a non-allowlisted
// grant_type returns invalid_client_metadata.
func TestDCR_UnknownGrantTypeRejected(t *testing.T) {
	eng := newDCREngine(t, siteAdminPrincipal())
	rec := dcrPost(t, eng, map[string]any{
		"client_name":   "X",
		"redirect_uris": []string{"https://x.example.com/cb"},
		"grant_types":   []string{"password"}, // disallowed
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%q", rec.Code, rec.Body.String())
	}
	var env map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &env)
	if env["error"] != "invalid_client_metadata" {
		t.Errorf("error field = %v; want invalid_client_metadata", env["error"])
	}
}

// TestDCR_SoftwareStatementRejected pins the conservative
// unapproved_software_statement posture: the foundation cannot
// verify signed software statements, so any non-empty one is
// rejected at the boundary.
func TestDCR_SoftwareStatementRejected(t *testing.T) {
	eng := newDCREngine(t, siteAdminPrincipal())
	rec := dcrPost(t, eng, map[string]any{
		"client_name":        "X",
		"redirect_uris":      []string{"https://x.example.com/cb"},
		"software_statement": "eyJhbGciOiJFZERTQSJ9.fake.fake",
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	var env map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &env)
	if env["error"] != "unapproved_software_statement" {
		t.Errorf("error field = %v; want unapproved_software_statement", env["error"])
	}
}

// TestDCR_NonSiteAdminReturns403 pins that the site_admin guard is
// enforced on the registration endpoint.
func TestDCR_NonSiteAdminReturns403(t *testing.T) {
	eng := newDCREngine(t, &domain.Principal{
		UserID:         uuid.New(),
		OrganizationID: uuid.New(),
		Role:           domain.RoleOrgAdmin,
	})
	rec := dcrPost(t, eng, map[string]any{
		"client_name":   "X",
		"redirect_uris": []string{"https://x.example.com/cb"},
	})
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
}

// TestDCR_UnauthenticatedReturns401 pins that an absent principal
// produces the auth-layer 401.
func TestDCR_UnauthenticatedReturns401(t *testing.T) {
	eng := newDCREngine(t, nil)
	rec := dcrPost(t, eng, map[string]any{
		"client_name":   "X",
		"redirect_uris": []string{"https://x.example.com/cb"},
	})
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

// TestDCR_BodyHasNoSecretHash pins that the response body never
// echoes the server-side hash of the secret, even when the secret
// itself is present.
func TestDCR_BodyHasNoSecretHash(t *testing.T) {
	eng := newDCREngine(t, siteAdminPrincipal())
	rec := dcrPost(t, eng, map[string]any{
		"client_name":   "X",
		"redirect_uris": []string{"https://x.example.com/cb"},
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d", rec.Code)
	}
	body := rec.Body.String()
	if strings.Contains(body, "client_secret_hash") {
		t.Errorf("response body must not contain client_secret_hash; got %q", body)
	}
}
