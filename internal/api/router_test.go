package api

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/server"
)

// genEd25519PEM produces a fresh Ed25519 keypair and returns the
// PKIX-encoded PEM of the public half. Mirrors the helper in
// internal/server/jwks_test.go; duplicated locally rather than
// exported so the OSS API package has zero test-only coupling to
// the smoke server package.
func genEd25519PEM(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

// stubJWKSProvider lets a test inject a specific JWKS without
// touching the repository layer.
type stubJWKSProvider struct {
	set server.JWKS
}

func (s stubJWKSProvider) PublicJWKS(_ context.Context) (server.JWKS, error) {
	return s.set, nil
}

func TestNewOSSEngine_SystemInfoOK(t *testing.T) {
	e := NewOSSEngine(OSSRouterDeps{Version: "test-version 0.0.0"})
	req := httptest.NewRequest(http.MethodGet, "/system/info", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("/system/info status = %d, want 200; body=%q", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("/system/info body is not JSON: %v; raw=%q", err, rec.Body.String())
	}
	if body["status"] != "healthy" {
		t.Errorf("status = %v, want healthy", body["status"])
	}
	if body["version"] != "test-version 0.0.0" {
		t.Errorf("version = %v, want test-version 0.0.0", body["version"])
	}
	if body["mode"] != "oss" {
		t.Errorf("mode = %v, want oss", body["mode"])
	}
}

func TestNewOSSEngine_ComponentDiscoveryOK(t *testing.T) {
	e := NewOSSEngine(OSSRouterDeps{Version: "test-version 0.0.0"})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/component", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("/api/v1/component status = %d, want 200; body=%q", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("/api/v1/component body is not JSON: %v; raw=%q", err, rec.Body.String())
	}
	if body["component"] != "identuum-idp" {
		t.Errorf("component = %v, want identuum-idp", body["component"])
	}
	if body["product"] != "identuum-idp-oss" {
		t.Errorf("product = %v, want identuum-idp-oss", body["product"])
	}
	if body["version"] != "test-version 0.0.0" {
		t.Errorf("version = %v, want test-version 0.0.0", body["version"])
	}
	if body["status"] != "ok" {
		t.Errorf("status = %v, want ok", body["status"])
	}
	if body["capability_map_schema_version"] != "idp-capabilities.v1" {
		t.Errorf("capability_map_schema_version = %v, want idp-capabilities.v1", body["capability_map_schema_version"])
	}
}

func TestNewOSSEngine_ComponentDiscoveryCapabilityFacts(t *testing.T) {
	e := NewOSSEngine(OSSRouterDeps{})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/component", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("/api/v1/component body is not JSON: %v", err)
	}
	capabilities, ok := body["capabilities"].(map[string]any)
	if !ok {
		t.Fatalf("capabilities = %T, want object", body["capabilities"])
	}
	for key, want := range map[string]bool{
		"identity_provider":           true,
		"component_discovery":         true,
		"license_status":              true,
		"auth_provider_discovery":     true,
		"account_self_service":        true,
		"user_sessions":               true,
		"mfa":                         true,
		"webauthn":                    true,
		"authorization_server":        true,
		"oauth_clients":               true,
		"api_resources":               true,
		"service_accounts":            true,
		"scope_templates":             true,
		"org_roles":                   true,
		"protocol_settings":           true,
		"client_credentials":          true,
		"dynamic_client_registration": true,
		"scim":                        false,
		"audit_log":                   true,
		"audit_chain":                 false,
		"reporting":                   false,
		"anomaly_detection":           false,
		"observability":               false,
	} {
		if got, ok := capabilities[key].(bool); !ok || got != want {
			t.Errorf("capabilities[%q] = %v (%T), want %v", key, capabilities[key], capabilities[key], want)
		}
	}
}

func TestNewOSSEngine_ComponentDiscoveryLicenseProjectionIsSafe(t *testing.T) {
	e := NewOSSEngine(OSSRouterDeps{})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/component", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("/api/v1/component body is not JSON: %v", err)
	}
	license, ok := body["license"].(map[string]any)
	if !ok {
		t.Fatalf("license = %T, want object", body["license"])
	}
	for key, want := range map[string]any{
		"status":          "valid",
		"product":         "identuum-idp-oss",
		"tier":            "starter",
		"deployment_mode": "self_hosted",
		"license_type":    "oss",
	} {
		if got := license[key]; got != want {
			t.Errorf("license[%q] = %v, want %v", key, got, want)
		}
	}
	for _, forbidden := range []string{
		"licensee",
		"customer_id",
		"features",
		"entitlements",
		"signature",
		"ciphertext",
		"private_key",
		"secret",
		"token",
		"password",
		"env",
	} {
		if strings.Contains(rec.Body.String(), forbidden) {
			t.Errorf("/api/v1/component response contains forbidden marker %q: %s", forbidden, rec.Body.String())
		}
	}
}

func TestNewOSSEngine_HealthOK(t *testing.T) {
	e := NewOSSEngine(OSSRouterDeps{})
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("/health status = %d, want 200; body=%q", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("/health body is not JSON: %v", err)
	}
	if body["tier"] != "starter" {
		t.Errorf("tier = %v, want starter", body["tier"])
	}
}

// TestNewOSSEngine_MetricsNotOnPublicRouter pins that /metrics is
// NOT registered on the public API engine. It moved to its own
// listener (internal/runtime.Runtime.startMetricsListener, gated by
// Config.MetricsAddr) to close the tenant/IDP-enumeration exposure
// noted in docs/audit/changelog/security-headers-middleware.md — see
// docs/audit/changelog/metrics-separate-listener.md.
func TestNewOSSEngine_MetricsNotOnPublicRouter(t *testing.T) {
	e := NewOSSEngine(OSSRouterDeps{})
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("/metrics on the public API engine status = %d, want 404 (not registered)", rec.Code)
	}
}

// THE-PKCE-DECISION: the advertised set is exactly {EdDSA, ES256, RS256}.
// RS256 is present because it is a REAL capability (explicit-registration,
// testing-only, never the default); everything else stays banned.
func TestNewOSSEngine_DiscoverySigningAlgSet(t *testing.T) {
	e := NewOSSEngine(OSSRouterDeps{})
	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("discovery status = %d, want 200; body=%q", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("discovery body is not JSON: %v", err)
	}
	algs, ok := body["id_token_signing_alg_values_supported"].([]any)
	if !ok {
		t.Fatalf("id_token_signing_alg_values_supported is not an array: %T", body["id_token_signing_alg_values_supported"])
	}
	algSet := make(map[string]bool, len(algs))
	for _, a := range algs {
		if s, ok := a.(string); ok {
			algSet[s] = true
		}
	}
	if !algSet["EdDSA"] || !algSet["ES256"] || !algSet["RS256"] {
		t.Errorf("missing required EdDSA + ES256 + RS256; got %v", algSet)
	}
	for _, banned := range []string{"RS384", "RS512", "PS256", "PS384", "PS512", "HS256"} {
		if algSet[banned] {
			t.Errorf("discovery advertises banned algorithm %q", banned)
		}
	}
}

func TestNewOSSEngine_DiscoveryCustomIssuer(t *testing.T) {
	e := NewOSSEngine(OSSRouterDeps{
		DiscoveryConfig: server.OIDCDiscoveryConfig{Issuer: "https://idp.example.com/"},
	})
	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("discovery body is not JSON: %v", err)
	}
	if got := body["issuer"]; got != "https://idp.example.com" {
		t.Errorf("issuer = %v, want https://idp.example.com (trailing slash stripped)", got)
	}
}

func TestNewOSSEngine_JWKSEmptyDefault(t *testing.T) {
	e := NewOSSEngine(OSSRouterDeps{})
	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("jwks status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("jwks Content-Type = %q, want application/json", ct)
	}
	var set server.JWKS
	if err := json.Unmarshal(rec.Body.Bytes(), &set); err != nil {
		t.Fatalf("jwks body is not JWKS JSON: %v", err)
	}
	if set.Keys == nil || len(set.Keys) != 0 {
		t.Errorf("expected empty Keys slice; got %v", set.Keys)
	}
}

func TestNewOSSEngine_JWKSNoPrivateMaterial(t *testing.T) {
	edJWK, err := server.PublicKeyToJWK("ed-1", domain.KeyAlgorithmEdDSA, genEd25519PEM(t))
	if err != nil {
		t.Fatalf("PublicKeyToJWK: %v", err)
	}
	provider := stubJWKSProvider{set: server.JWKS{Keys: []server.JWK{edJWK}}}
	e := NewOSSEngine(OSSRouterDeps{JWKSProvider: provider})

	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("jwks status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, banned := range []string{`"d":`, `"p":`, `"q":`, `"dp":`, `"dq":`, `"qi":`, `"n":`, `"e":`} {
		if strings.Contains(body, banned) {
			t.Errorf("JWKS body contains banned field %s; body=%s", banned, body)
		}
	}
}

func TestNewOSSEngine_UnknownPathIs404(t *testing.T) {
	e := NewOSSEngine(OSSRouterDeps{})
	for _, path := range []string{
		"/",
		"/anything",
		"/api/v1/scim/v2/Users",
		"/mcp",
		"/api/v1/audit/events",
		"/api/v1/anomaly/events",
		"/api/v1/anomaly/stats",
		"/.well-known/jwks.txt",
	} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Errorf("GET %s status = %d, want 404 (must not be registered in the OSS scaffold)", path, rec.Code)
		}
	}
}

// TestNewOSSEngine_KeysRoutesAbsentWithoutService confirms that
// when OSSRouterDeps.KeyService is nil, the /api/v1/keys group is
// NOT registered. Default --gin-serve runs (no --jwks-db) must
// not surface admin endpoints.
func TestNewOSSEngine_KeysRoutesAbsentWithoutService(t *testing.T) {
	e := NewOSSEngine(OSSRouterDeps{})
	for _, path := range []string{
		"/api/v1/keys",
		"/api/v1/keys/reload",
	} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Errorf("GET %s status = %d, want 404 when KeyService is nil", path, rec.Code)
		}
	}
}

// TestNewOSSEngine_PublicRegistrationRoutesAbsent is the forward-compat
// tripwire for Decision D-015's AllowPublicRegistration disposition
// (ENFORCED_BY_ABSENCE in OSS Starter — see
// wiki/platform/org-policy-enforcement-decision.md).
//
// The policy field domain.Organization.AllowPublicRegistration exists
// in admin DTOs + migrations + repository projection (forward-compat
// with CE composition), but OSS Starter does NOT mount a
// public/self-registration handler. User creation is admin-gated only:
//   - POST /api/v1/users (site_admin OR org_admin + users:create);
//   - POST /api/v1/auth/claim (consumes an admin-minted invitation);
//   - POST /api/v1/auth/organizations/activate (consumes an
//     admin-minted activation token).
//
// No path through which an unauthenticated stranger can create an
// account exists.
//
// This test pins the absence: every candidate public-registration
// path returns 404 in the OSS scaffold. If a future PR adds a
// public-registration handler, this test fails — at which point the
// implementer MUST also wire the AllowPublicRegistration gate per
// Decision D-015 and update this test to point at the new path
// instead of asserting 404.
//
// Adding a route here without updating the gate would be a regression
// against D-015 and against the locked admin-local invariant
// (Decision D-004) — admin invitation flows must continue to succeed
// independently of any public-registration gate.
func TestNewOSSEngine_PublicRegistrationRoutesAbsent(t *testing.T) {
	e := NewOSSEngine(OSSRouterDeps{})
	candidatePaths := []struct {
		method string
		path   string
		why    string
	}{
		{http.MethodPost, "/api/v1/auth/register", "canonical public registration path (not mounted in OSS Starter)"},
		{http.MethodPost, "/api/v1/auth/signup", "alternative public registration path (not mounted in OSS Starter)"},
		{http.MethodPost, "/api/v1/users/register", "alternative public registration path under /users (not mounted in OSS Starter)"},
		{http.MethodPost, "/api/v1/register", "alternative public registration path (not mounted in OSS Starter)"},
		{http.MethodPost, "/api/v1/signup", "alternative public registration path (not mounted in OSS Starter)"},
	}
	for _, p := range candidatePaths {
		req := httptest.NewRequest(p.method, p.path, nil)
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s %s status = %d, want 404 (%s); if a public-registration handler is being added, this test MUST be updated to point at the new path AND the handler MUST consult domain.Organization.AllowPublicRegistration before any user row is written per Decision D-015 + D-004",
				p.method, p.path, rec.Code, p.why)
		}
	}
}

// TestNewOSSEngine_RegistrationApprovalRoutesAbsent is the
// forward-compat tripwire for Decision D-015's
// RequireRegistrationApproval disposition (corrected
// 2026-06-24 PM by slice
// agent-a-20260713-idp-oss-orgpolicy-enforcement-premise-reverification
// from OSS_ENFORCE → ENFORCED_BY_ABSENCE in OSS / DEFERRED_FOR_CE
// for the surface — see
// wiki/platform/org-policy-enforcement-decision.md §6).
//
// The policy field domain.Organization.RequireRegistrationApproval
// exists in admin DTOs + migrations + repository projection
// (forward-compat with CE composition), but OSS Starter does NOT
// mount a public/self-registration handler AND does NOT carry a
// pending-approval state machine on the users table. There is no
// users.registration_status / users.approval_status / users.status
// column today; no HandleApprove handler; no admin approval workflow.
//
// This test pins the absence: every candidate registration-approval
// path returns 404 in the OSS scaffold. If a future PR adds a
// public-registration handler + an approval workflow, this test
// fails — at which point the implementer MUST also wire the
// RequireRegistrationApproval gate per Decision D-015 §6 and update
// this test to point at the new path.
//
// Adding any of these routes without updating the gate would be a
// regression against D-015 and against the locked admin-local
// invariant (Decision D-004) — admin invitation flows must continue
// to mint admin rows immediately-active independently of any
// approval gate.
func TestNewOSSEngine_RegistrationApprovalRoutesAbsent(t *testing.T) {
	e := NewOSSEngine(OSSRouterDeps{})
	candidatePaths := []struct {
		method string
		path   string
		why    string
	}{
		{http.MethodPost, "/api/v1/users/pending/approve", "canonical approve-pending-user path (no pending-approval state machine in OSS today)"},
		{http.MethodPost, "/api/v1/users/approve", "alternative approve-pending-user path"},
		{http.MethodGet, "/api/v1/users/pending", "canonical list-pending-users path (no pending-approval state machine)"},
		{http.MethodPost, "/api/v1/registrations/approve", "alternative approve-registration path"},
		{http.MethodGet, "/api/v1/registrations", "canonical list-pending-registrations path"},
	}
	for _, p := range candidatePaths {
		req := httptest.NewRequest(p.method, p.path, nil)
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s %s status = %d, want 404 (%s); if a registration-approval handler is being added, this test MUST be updated to point at the new path AND the handler MUST consult domain.Organization.RequireRegistrationApproval at the registration code path per Decision D-015 §6 + D-004",
				p.method, p.path, rec.Code, p.why)
		}
	}
}

// TestRegisterOSSRoutes_Composability verifies the registration
// helper is callable against an arbitrary gin.IRouter so future CE
// composition can call it on the same engine before adding CE-only
// routes.
func TestRegisterOSSRoutes_Composability(t *testing.T) {
	e := NewOSSEngine(OSSRouterDeps{})
	// Re-registering the same routes on an already-populated
	// engine would panic in gin; the test simply confirms the
	// initial registration that NewOSSEngine performed wired the
	// public surface. A future CE-side helper would do:
	//
	//   r := api.NewOSSEngine(ossDeps)
	//   ce.RegisterCERoutes(r, ceDeps)
	//
	// without re-registering OSS routes. The presence of /health
	// on the engine demonstrates that NewOSSEngine actually called
	// RegisterOSSRoutes — distinct from a scaffold that only
	// returns an empty engine.
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("NewOSSEngine did not wire /health; got %d", rec.Code)
	}
}

// TestNewOSSEngine_DCRRoutesAbsentWithoutClientService pins the
// no-DB scaffold contract that DCR foundation routes are NOT
// mounted when OSSRouterDeps.ClientService is nil.
//
// NOTE: SCIM v2 was removed from OSS to close a licensing leak (it is a
// paid CE feature — Professional and above) — see docs/audit/changelog/scim-oss-leak-removal.md.
// The SCIM rows that used to share this absent-without-ClientService
// table were excised; the contract below is now DCR-only. The "DCR/SCIM"
// mentions further down are retained as historical context for the no-DB
// scaffold decision tree.
//
// The Codex 2026-06-29 audit framed this as "no-DB runtime mode leaves
// DCR with open-default behavior" — that framing collapses two
// distinct cases:
//
//  1. PURE no-DB runtime (--gin-serve without --jwks-db): buildDeps
//     returns OSSRouterDeps with NIL ClientService. The mountDCR
//     helper in router.go early-returns on `ClientService == nil`
//     (the advanced-DCR mounts were removed outright — see
//     docs/audit/changelog/dcr-surface-scoping.md). Therefore DCR
//     + SCIM routes are NOT
//     mounted — there is NO open-default exposure because there is
//     no route to open by default. THIS TEST PINS THAT INVARIANT.
//
//  2. TEST-FIXTURE mode (a caller builds OSSRouterDeps with a
//     ClientService but leaves OrganizationProtocolSettingsService
//     nil): DCR + SCIM routes ARE mounted with open-default
//     behaviour. This is the documented OSS scaffold default per
//     the doc-comment on OrganizationProtocolSettingsService in
//     this package — "When nil, every DCR/SCIM request is allowed
//     (the documented OSS scaffold default — test fixtures and
//     smoke binaries that have not wired the service keep the
//     foundation reachable). Production wiring binds this to the
//     Postgres-backed service." Tests that explicitly want the
//     open-default behaviour build the deps that way intentionally;
//     no production runtime path reaches this state because
//     --gin-serve --jwks-db wires both services together.
//
// See wiki/repos/identuum-idp-oss.md §"No-DB DCR/SCIM open-default
// — scaffold/smoke-only contract" for the full decision-tree.
//
// If a future PR mounts DCR/SCIM routes unconditionally (e.g.
// removes the `ClientService == nil` early-return), this test
// fires so the implementer reviews the production-runtime
// implication: open-default would become reachable from
// --gin-serve without --jwks-db, which is the contract that the
// boot-time warning in internal/runtime/runtime.go:472 explicitly
// flags as scaffold/smoke-only.
func TestNewOSSEngine_DCRRoutesAbsentWithoutClientService(t *testing.T) {
	e := NewOSSEngine(OSSRouterDeps{})
	candidatePaths := []struct {
		method string
		path   string
		why    string
	}{
		{http.MethodPost, "/api/v1/clients/register", "RFC 7591 DCR registration (must NOT be mounted without ClientService)"},
		{http.MethodGet, "/api/v1/clients/register/abc", "RFC 7592 DCR management read (must NOT be mounted without ClientService)"},
		{http.MethodPut, "/api/v1/clients/register/abc", "RFC 7592 DCR management write (must NOT be mounted without ClientService)"},
		{http.MethodDelete, "/api/v1/clients/register/abc", "RFC 7592 DCR management delete (must NOT be mounted without ClientService)"},
	}
	for _, tc := range candidatePaths {
		req := httptest.NewRequest(tc.method, tc.path, nil)
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s %s status = %d, want 404 (%s)", tc.method, tc.path, rec.Code, tc.why)
		}
	}
}
