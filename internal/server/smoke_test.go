package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSmokeHandler_HealthzOK(t *testing.T) {
	h := NewSmokeHandler()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("/healthz status = %d, want 200; body=%q", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("/healthz Content-Type = %q, want application/json", ct)
	}

	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("/healthz body is not JSON: %v; raw=%q", err, rec.Body.String())
	}
	if body["status"] != "ok" {
		t.Errorf("/healthz status field = %q, want \"ok\"", body["status"])
	}
	if body["endpoint"] != "healthz" {
		t.Errorf("/healthz endpoint field = %q, want \"healthz\"", body["endpoint"])
	}
	if body["mode"] != "smoke" {
		t.Errorf("/healthz mode field = %q, want \"smoke\"", body["mode"])
	}
	if body["version"] == "" {
		t.Errorf("/healthz version field is empty")
	}
}

func TestSmokeHandler_LivezOK(t *testing.T) {
	h := NewSmokeHandler()
	req := httptest.NewRequest(http.MethodGet, "/livez", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("/livez status = %d, want 200; body=%q", rec.Code, rec.Body.String())
	}

	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("/livez body is not JSON: %v; raw=%q", err, rec.Body.String())
	}
	if body["status"] != "alive" {
		t.Errorf("/livez status field = %q, want \"alive\"", body["status"])
	}
	if body["endpoint"] != "livez" {
		t.Errorf("/livez endpoint field = %q, want \"livez\"", body["endpoint"])
	}
}

// TestSmokeHandler_UnknownPathIs404 documents that the smoke surface
// is deliberately minimal — any path other than /healthz or /livez
// gets a stdlib http.ServeMux 404. No /, no /metrics, nothing else.
func TestSmokeHandler_UnknownPathIs404(t *testing.T) {
	h := NewSmokeHandler()
	for _, path := range []string{"/", "/anything", "/healthz/sub", "/metrics", "/.well-known/jwks.txt", "/oauth2/authorize"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Errorf("GET %s status = %d, want 404", path, rec.Code)
		}
	}
}

// TestSmokeHandler_NonGETIs405 verifies that non-GET requests to a
// smoke endpoint return 405 Method Not Allowed with the Allow header
// set, rather than executing the handler. Documents the contract for
// monitoring tooling that might HEAD or POST.
func TestSmokeHandler_NonGETIs405(t *testing.T) {
	h := NewSmokeHandler()
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch, http.MethodHead} {
		req := httptest.NewRequest(method, "/healthz", nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s /healthz status = %d, want 405", method, rec.Code)
		}
		if allow := rec.Header().Get("Allow"); allow != http.MethodGet {
			t.Errorf("%s /healthz Allow header = %q, want %q", method, allow, http.MethodGet)
		}
	}
}

// TestSmokeHandler_DiscoveryDefaults verifies the static discovery
// document is served at the standard OIDC well-known path with the
// safe localhost placeholders when no issuer override is supplied.
func TestSmokeHandler_DiscoveryDefaults(t *testing.T) {
	h := NewSmokeHandler()
	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("discovery status = %d, want 200; body=%q", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("discovery Content-Type = %q, want application/json", ct)
	}

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("discovery body is not JSON: %v; raw=%q", err, rec.Body.String())
	}

	wantStrings := map[string]string{
		"issuer":                 "http://localhost",
		"authorization_endpoint": "http://localhost/oauth2/authorize",
		"token_endpoint":         "http://localhost/oauth2/token",
		"jwks_uri":               "http://localhost/.well-known/jwks.json",
	}
	// Phase-3 OIDC conformance remediation: the discovery
	// document MUST NOT carry vendor-specific top-level keys.
	if _, ok := body["mode"]; ok {
		t.Errorf("discovery contains non-standard `mode` key: %v", body["mode"])
	}
	for k, want := range wantStrings {
		got, _ := body[k].(string)
		if got != want {
			t.Errorf("discovery[%q] = %v, want %q", k, body[k], want)
		}
	}

	// Array fields must be present and non-empty.
	for _, k := range []string{
		"response_types_supported",
		"subject_types_supported",
		"id_token_signing_alg_values_supported",
		"scopes_supported",
		"token_endpoint_auth_methods_supported",
		"grant_types_supported",
		"code_challenge_methods_supported",
	} {
		arr, ok := body[k].([]any)
		if !ok {
			t.Errorf("discovery[%q] is not an array: %T", k, body[k])
			continue
		}
		if len(arr) == 0 {
			t.Errorf("discovery[%q] is empty", k)
		}
	}
}

// TestSmokeHandler_DiscoveryIdentuumSigningPolicy enforces the Identuum
// signing policy at the discovery layer (THE-PKCE-DECISION).
// id_token_signing_alg_values_supported MUST be exactly
// {EdDSA, ES256, RS256}: EdDSA is the default; RS256 is advertised because
// it is a REAL capability — but it fires only on an explicit per-client
// registration, testing-only (owner ruling: "Add RS256 into the list BUT DO
// NOT USE except testing"). Every other RS*/PS*/HS*/none stays banned.
func TestSmokeHandler_DiscoveryIdentuumSigningPolicy(t *testing.T) {
	h := NewSmokeHandler()
	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("discovery body is not JSON: %v", err)
	}
	algsAny, ok := body["id_token_signing_alg_values_supported"].([]any)
	if !ok {
		t.Fatalf("id_token_signing_alg_values_supported is not an array: %T", body["id_token_signing_alg_values_supported"])
	}
	algs := make(map[string]bool, len(algsAny))
	for _, a := range algsAny {
		if s, ok := a.(string); ok {
			algs[s] = true
		}
	}

	// Required: the full advertised set. RS256 is present because the
	// capability is real (THE-PKCE-DECISION) — discovery advertises
	// nothing it cannot do, and nothing more.
	for _, must := range []string{"EdDSA", "ES256", "RS256"} {
		if !algs[must] {
			t.Errorf("id_token_signing_alg_values_supported missing required %q (got %v)", must, algs)
		}
	}
	// Forbidden for issuance (Identuum policy).
	for _, banned := range []string{"RS384", "RS512", "PS256", "PS384", "PS512", "HS256", "HS384", "HS512", "none"} {
		if algs[banned] {
			t.Errorf("id_token_signing_alg_values_supported MUST NOT include %q (Identuum no-issuance policy); got %v", banned, algs)
		}
	}
}

// Request objects are refused (OIDC §6.1), and discovery must say so
// EXPLICITLY — the Discovery default for request_uri_parameter_supported is
// TRUE when omitted, which would advertise support the OP refuses.
func TestSmokeHandler_DiscoveryRequestObjectFlagsExplicitlyFalse(t *testing.T) {
	h := NewSmokeHandler()
	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("discovery body is not JSON: %v", err)
	}
	for _, k := range []string{"request_parameter_supported", "request_uri_parameter_supported"} {
		v, ok := body[k]
		if !ok {
			t.Errorf("%s missing; explicit false is REQUIRED (the omitted default for request_uri_parameter_supported is true)", k)
			continue
		}
		if v != false {
			t.Errorf("%s = %v, want false — the OP refuses request objects", k, v)
		}
	}
}

// TestSmokeHandler_DiscoveryCustomIssuer verifies the
// NewSmokeHandlerWithDiscovery constructor wires a non-default issuer
// into all four URL fields (with the default endpoint suffixes) and
// strips a trailing slash from the issuer base.
func TestSmokeHandler_DiscoveryCustomIssuer(t *testing.T) {
	h := NewSmokeHandlerWithDiscovery(OIDCDiscoveryConfig{Issuer: "https://idp.example.com/"})
	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("discovery body is not JSON: %v", err)
	}
	wantStrings := map[string]string{
		"issuer":                 "https://idp.example.com",
		"authorization_endpoint": "https://idp.example.com/oauth2/authorize",
		"token_endpoint":         "https://idp.example.com/oauth2/token",
		"jwks_uri":               "https://idp.example.com/.well-known/jwks.json",
	}
	for k, want := range wantStrings {
		got, _ := body[k].(string)
		if got != want {
			t.Errorf("discovery[%q] = %v, want %q", k, body[k], want)
		}
	}
}

// TestSmokeHandler_DiscoveryExplicitEndpoints verifies that fully
// specified per-endpoint overrides win over the derived defaults.
func TestSmokeHandler_DiscoveryExplicitEndpoints(t *testing.T) {
	cfg := OIDCDiscoveryConfig{
		Issuer:                "https://idp.example.com",
		AuthorizationEndpoint: "https://auth.example.com/authorize",
		TokenEndpoint:         "https://auth.example.com/token",
		JWKSURI:               "https://keys.example.com/jwks",
	}
	h := NewSmokeHandlerWithDiscovery(cfg)
	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("discovery body is not JSON: %v", err)
	}
	wantStrings := map[string]string{
		"authorization_endpoint": "https://auth.example.com/authorize",
		"token_endpoint":         "https://auth.example.com/token",
		"jwks_uri":               "https://keys.example.com/jwks",
	}
	for k, want := range wantStrings {
		got, _ := body[k].(string)
		if got != want {
			t.Errorf("discovery[%q] = %v, want %q (explicit override should win)", k, body[k], want)
		}
	}
}

// TestSmokeHandler_DiscoveryPOSTIs405 verifies the discovery endpoint
// rejects non-GET methods the same way /healthz and /livez do.
func TestSmokeHandler_DiscoveryPOSTIs405(t *testing.T) {
	h := NewSmokeHandler()
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch, http.MethodHead} {
		req := httptest.NewRequest(method, "/.well-known/openid-configuration", nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s discovery status = %d, want 405", method, rec.Code)
		}
		if allow := rec.Header().Get("Allow"); allow != http.MethodGet {
			t.Errorf("%s discovery Allow header = %q, want %q", method, allow, http.MethodGet)
		}
	}
}

// TestSetSmokeVersion verifies the override mutates the package-level
// SmokeVersion used by future requests. The defer restores the
// default so other tests in this package are unaffected.
func TestSetSmokeVersion(t *testing.T) {
	original := SmokeVersion
	defer func() { SmokeVersion = original }()

	SetSmokeVersion("custom-test-version 0.0.0")
	h := NewSmokeHandler()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))

	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("/healthz body is not JSON: %v", err)
	}
	if body["version"] != "custom-test-version 0.0.0" {
		t.Errorf("version field = %q, want override", body["version"])
	}

	// Empty string is rejected (defensive — we keep the previous value).
	SetSmokeVersion("")
	if SmokeVersion != "custom-test-version 0.0.0" {
		t.Errorf("SetSmokeVersion(\"\") overwrote previous value: %q", SmokeVersion)
	}
}
