package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/mw"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// handlerFakeIntrospector is a tiny TokenClaimsVerifier
// implementation: it either returns canned claims or an error.
type handlerFakeIntrospector struct {
	claims *service.IntrospectionClaims
	err    error
}

func (f *handlerFakeIntrospector) IntrospectToken(_ context.Context, _ string) (*service.IntrospectionClaims, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.claims, nil
}

func newIntrospectionEngine(t *testing.T, principal *domain.Principal, v service.TokenClaimsVerifier) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	if principal != nil {
		r.Use(mw.InjectPrincipalForTest(principal))
	}
	RegisterIntrospectionRoutes(r, IntrospectionHandlerDeps{
		IntrospectionService: service.NewIntrospectionService(nil, v, nil),
		Audit:                &audit.Recorder{},
	})
	return r
}

// ---------- Route absence / auth guard ----------

func TestIntrospection_RouteAbsentWithoutService(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	RegisterIntrospectionRoutes(r, IntrospectionHandlerDeps{}) // nil service
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/v1/oauth/introspection", nil))
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 (no service → no routes)", w.Code)
	}
}

func TestIntrospection_Unauthenticated401(t *testing.T) {
	r := newIntrospectionEngine(t, nil, &handlerFakeIntrospector{})
	body := strings.NewReader("token=anything")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/introspection", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

func TestIntrospection_OrgAdmin403(t *testing.T) {
	p := &domain.Principal{Role: domain.RoleOrgAdmin, UserID: uuid.New(), OrganizationID: uuid.New()}
	r := newIntrospectionEngine(t, p, &handlerFakeIntrospector{})
	body := strings.NewReader("token=anything")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/introspection", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 (slice mounts RequireSiteAdmin until client-auth ports)", w.Code)
	}
}

// ---------- Request shape ----------

func TestIntrospection_FormMissingTokenReturns400(t *testing.T) {
	r := newIntrospectionEngine(t, siteAdminPrincipal(), &handlerFakeIntrospector{})
	body := strings.NewReader("token=")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/introspection", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestIntrospection_NoBodyReturns400(t *testing.T) {
	r := newIntrospectionEngine(t, siteAdminPrincipal(), &handlerFakeIntrospector{})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/introspection", nil)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

// ---------- active=false (invalid/expired) ----------

func TestIntrospection_InvalidTokenActiveFalse(t *testing.T) {
	r := newIntrospectionEngine(t, siteAdminPrincipal(), &handlerFakeIntrospector{err: errors.New("invalid signature")})
	body := strings.NewReader("token=BAD-SIGNATURE-TOKEN-SHOULD-NOT-LEAK")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/introspection", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (RFC 7662 §2.2)", w.Code)
	}
	var resp struct {
		Active bool `json:"active"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Active {
		t.Errorf("active=true; want false")
	}
	if strings.Contains(w.Body.String(), "BAD-SIGNATURE-TOKEN-SHOULD-NOT-LEAK") {
		t.Errorf("response leaked raw token sentinel: %q", w.Body.String())
	}
	if strings.Contains(strings.ToLower(w.Body.String()), "signature") || strings.Contains(strings.ToLower(w.Body.String()), "expired") {
		t.Errorf("response leaked verifier failure detail: %q", w.Body.String())
	}
}

// ---------- active=true ----------

func TestIntrospection_ValidTokenActiveTrue(t *testing.T) {
	uid := uuid.New()
	v := &handlerFakeIntrospector{claims: &service.IntrospectionClaims{
		Sub:      uid.String(),
		UserID:   uid,
		ClientID: "client-1",
		Email:    "u@example.test",
		Scope:    "openid users:read",
		Iss:      "https://idp.test",
		Exp:      1700000000,
		Iat:      1699999000,
		Jti:      "jti-1",
		Aud:      []string{"https://api.example.test"},
	}}
	r := newIntrospectionEngine(t, siteAdminPrincipal(), v)
	body := strings.NewReader("token=VALID-TOKEN-SHOULD-NOT-LEAK&token_type_hint=access_token")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/introspection", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if active, _ := resp["active"].(bool); !active {
		t.Errorf("active = %v, want true", resp["active"])
	}
	if resp["sub"] != uid.String() {
		t.Errorf("sub = %v", resp["sub"])
	}
	if resp["client_id"] != "client-1" {
		t.Errorf("client_id = %v", resp["client_id"])
	}
	if resp["token_type"] != "Bearer" {
		t.Errorf("token_type = %v", resp["token_type"])
	}
	if strings.Contains(w.Body.String(), "VALID-TOKEN-SHOULD-NOT-LEAK") {
		t.Errorf("response leaked raw token sentinel: %q", w.Body.String())
	}
}

// ---------- JSON request shape ----------

func TestIntrospection_JSONRequestSupported(t *testing.T) {
	uid := uuid.New()
	v := &handlerFakeIntrospector{claims: &service.IntrospectionClaims{
		Sub: uid.String(), UserID: uid, ClientID: "c",
	}}
	r := newIntrospectionEngine(t, siteAdminPrincipal(), v)
	body := strings.NewReader(`{"token":"JSON-TOKEN-SHOULD-NOT-LEAK"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/introspection", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	if strings.Contains(w.Body.String(), "JSON-TOKEN-SHOULD-NOT-LEAK") {
		t.Errorf("response leaked raw token sentinel")
	}
}

func TestIntrospection_JSONMissingTokenReturns400(t *testing.T) {
	r := newIntrospectionEngine(t, siteAdminPrincipal(), &handlerFakeIntrospector{})
	body := strings.NewReader(`{}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/introspection", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

// ---------- Form parsing edge case: token with special chars URL-encoded ----------

// ---------- ClientAuth flip ----------

// stubAuthnAllowAll always succeeds.
type stubAuthnAllowAll struct{}

func (stubAuthnAllowAll) Authenticate(_ context.Context, id, _, _ string) (*service.AuthenticatedClient, error) {
	return &service.AuthenticatedClient{
		Kind: service.AuthenticatedClientKindOAuth, ClientID: id,
	}, nil
}

// stubAuthnRejectAll always fails.
type stubAuthnRejectAll struct{}

func (stubAuthnRejectAll) Authenticate(_ context.Context, _, _, _ string) (*service.AuthenticatedClient, error) {
	return nil, errors.New("denied")
}

func newIntrospectionEngineWithClientAuth(t *testing.T, v service.TokenClaimsVerifier, ca mw.OAuthClientAuthenticator) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	RegisterIntrospectionRoutes(r, IntrospectionHandlerDeps{
		IntrospectionService: service.NewIntrospectionService(nil, v, nil),
		Audit:                &audit.Recorder{},
		ClientAuth:           ca,
	})
	return r
}

func TestIntrospection_ClientAuthFlipReplacesSiteAdmin(t *testing.T) {
	uid := uuid.New()
	v := &handlerFakeIntrospector{claims: &service.IntrospectionClaims{Sub: uid.String(), UserID: uid}}
	r := newIntrospectionEngineWithClientAuth(t, v, stubAuthnAllowAll{})
	body := strings.NewReader("token=ANY-TOKEN&client_id=cli-1&client_secret=S")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/introspection", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%q", w.Code, w.Body.String())
	}
}

// RULE: INTROSPECT-AUTH-1
func TestIntrospection_ClientAuthRejectionReturns401(t *testing.T) {
	v := &handlerFakeIntrospector{}
	r := newIntrospectionEngineWithClientAuth(t, v, stubAuthnRejectAll{})
	body := strings.NewReader("token=ANY-TOKEN&client_id=cli-1&client_secret=WRONG")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/introspection", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
	if w.Header().Get("WWW-Authenticate") != `Basic realm="oauth-client"` {
		t.Errorf("WWW-Authenticate = %q", w.Header().Get("WWW-Authenticate"))
	}
}

// When ClientAuth is wired, a site_admin bearer principal in
// context is NOT a bypass — only valid client credentials get
// through.
func TestIntrospection_ClientAuthWiredSiteAdminNoBypass(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(mw.InjectPrincipalForTest(siteAdminPrincipal()))
	RegisterIntrospectionRoutes(r, IntrospectionHandlerDeps{
		IntrospectionService: service.NewIntrospectionService(nil, &handlerFakeIntrospector{}, nil),
		Audit:                &audit.Recorder{},
		ClientAuth:           stubAuthnRejectAll{},
	})
	body := strings.NewReader("token=X&client_id=site-admin-cli&client_secret=WRONG")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/introspection", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 (site_admin bearer must not bypass client auth)", w.Code)
	}
}

func TestIntrospection_URLEncodedTokenPassesThrough(t *testing.T) {
	uid := uuid.New()
	v := &handlerFakeIntrospector{claims: &service.IntrospectionClaims{Sub: uid.String(), UserID: uid}}
	r := newIntrospectionEngine(t, siteAdminPrincipal(), v)
	rawToken := "eyJhbGciOiJFZERTQSJ9.payload.sig"
	form := url.Values{}
	form.Set("token", rawToken)
	body := strings.NewReader(form.Encode())
	req := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/introspection", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	if strings.Contains(w.Body.String(), rawToken) {
		t.Errorf("response leaked raw token: %q", w.Body.String())
	}
}
