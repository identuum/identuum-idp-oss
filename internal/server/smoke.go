package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

// jwksFetchTimeout caps how long the JWKS handler waits on the
// provider before failing the request. The smoke handler does not
// background-refresh — every request hits the provider — so the
// timeout protects against slow DB fetches dominating request
// latency.
const jwksFetchTimeout = 5 * time.Second

// SmokeVersion is the build-time identifier surfaced in /healthz and
// /livez JSON. The cmd/identuum-idp entrypoint overrides it via
// SetSmokeVersion before constructing the handler so the served JSON
// matches the --version flag's output.
var SmokeVersion = "identuum-idp-oss-smoke unknown"

// SetSmokeVersion overrides SmokeVersion. Safe to call at init time;
// not safe to call concurrently with NewSmokeHandler.
func SetSmokeVersion(v string) {
	if v != "" {
		SmokeVersion = v
	}
}

// OIDCDiscoveryConfig drives the static
// /.well-known/openid-configuration document served by the smoke
// handler. Every field is optional; empty values fall back to safe
// localhost placeholders derived from Issuer (or "http://localhost"
// if Issuer is also empty). The smoke handler does NOT implement the
// underlying endpoints — this is metadata only, intended for
// conformance tooling to probe a structurally valid discovery
// document before the real handlers land.
type OIDCDiscoveryConfig struct {
	Issuer                string
	AuthorizationEndpoint string
	TokenEndpoint         string
	JWKSURI               string
}

// resolveDiscovery fills in defaults for any empty fields. Returns a
// new struct so the caller's value is never mutated. Issuer always
// has a trailing slash trimmed so paths concatenate cleanly.
func resolveDiscovery(cfg OIDCDiscoveryConfig) OIDCDiscoveryConfig {
	out := cfg
	if out.Issuer == "" {
		out.Issuer = "http://localhost"
	}
	out.Issuer = strings.TrimRight(out.Issuer, "/")
	if out.AuthorizationEndpoint == "" {
		out.AuthorizationEndpoint = out.Issuer + "/oauth2/authorize"
	}
	if out.TokenEndpoint == "" {
		out.TokenEndpoint = out.Issuer + "/oauth2/token"
	}
	if out.JWKSURI == "" {
		out.JWKSURI = out.Issuer + "/.well-known/jwks.json"
	}
	return out
}

// NewSmokeHandler returns the minimal HTTP surface for the --serve
// smoke command. Equivalent to NewSmokeHandlerWithJWKS with a
// zero-value OIDCDiscoveryConfig and an EmptyJWKSProvider — safe
// localhost defaults and {"keys":[]} from the JWKS endpoint.
func NewSmokeHandler() http.Handler {
	return NewSmokeHandlerWithJWKS(OIDCDiscoveryConfig{}, EmptyJWKSProvider{})
}

// NewSmokeHandlerWithDiscovery is the previous public constructor.
// Retained for backward compatibility; delegates to
// NewSmokeHandlerWithJWKS with an EmptyJWKSProvider so the JWKS
// endpoint serves {"keys":[]} reliably.
func NewSmokeHandlerWithDiscovery(cfg OIDCDiscoveryConfig) http.Handler {
	return NewSmokeHandlerWithJWKS(cfg, EmptyJWKSProvider{})
}

// NewSmokeHandlerWithJWKS returns the smoke surface plus a static
// /.well-known/openid-configuration document derived from cfg and a
// /.well-known/jwks.json endpoint backed by jwks.
//
// Endpoints (smoke + discovery + jwks):
//
//	GET  /healthz                          → 200 JSON
//	GET  /livez                            → 200 JSON
//	GET  /.well-known/openid-configuration → 200 JSON (static metadata)
//	GET  /.well-known/jwks.json            → 200 JSON (public JWKS)
//
// Every other path returns 404. Non-GET requests return 405 with
// `Allow: GET`. If jwks is nil, EmptyJWKSProvider is substituted so
// callers cannot accidentally serve 500s from the JWKS endpoint
// merely by forgetting to wire a provider.
//
// The discovery document advertises ONLY Identuum-policy signing
// algorithms (ES256 and EdDSA). The JWKS endpoint reuses the same
// policy: PublicKeyToJWK rejects RS256 (verify-only, never
// published), so RepositoryJWKSProvider's filter is consistent with
// what discovery advertises.
func NewSmokeHandlerWithJWKS(cfg OIDCDiscoveryConfig, jwks JWKSProvider) http.Handler {
	if jwks == nil {
		jwks = EmptyJWKSProvider{}
	}
	resolved := resolveDiscovery(cfg)

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", smokeJSONHandler("healthz", "ok"))
	mux.HandleFunc("/livez", smokeJSONHandler("livez", "alive"))
	mux.HandleFunc("/.well-known/openid-configuration", discoveryHandler(resolved))
	mux.HandleFunc("/.well-known/jwks.json", jwksHandler(jwks))
	return mux
}

// jwksHandler serves the public JWKS as application/json.
// Per-request: GET only (405 otherwise), 500 on provider error
// (with a generic "internal error" body — no detail surfaces to the
// caller because we cannot guarantee provider errors don't leak
// state).
func jwksHandler(provider JWKSProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), jwksFetchTimeout)
		defer cancel()
		set, err := provider.PublicJWKS(ctx)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error": "internal error",
			})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(set)
	}
}

func smokeJSONHandler(endpoint, status string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		body := map[string]string{
			"status":   status,
			"endpoint": endpoint,
			"version":  SmokeVersion,
			"mode":     "smoke",
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(body)
	}
}

// discoveryHandler returns the static OIDC discovery document keyed
// off cfg. The body uses an ordered map (via a struct) so the JSON
// field order is deterministic for snapshot diffing.
func discoveryHandler(cfg OIDCDiscoveryConfig) http.HandlerFunc {
	// Pre-compute the body once at handler-construction time; each
	// request just re-serialises. Allowed because cfg is immutable
	// for the handler's lifetime.
	body := discoveryDocument(cfg)
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(body)
	}
}

// ResolveDiscoveryConfig fills in safe localhost defaults for any
// empty fields in cfg and returns the resolved value. Exported so
// callers building Gin handlers (or other routing surfaces) can
// reuse the same defaulting + trailing-slash logic that powers the
// net/http smoke handler.
func ResolveDiscoveryConfig(cfg OIDCDiscoveryConfig) OIDCDiscoveryConfig {
	return resolveDiscovery(cfg)
}

// DiscoveryDocument is the exported builder for the static OIDC
// discovery payload. The Gin OSS router scaffold uses this so the
// signing-algorithm policy (only EdDSA + ES256) is single-sourced
// across both routing surfaces.
func DiscoveryDocument(cfg OIDCDiscoveryConfig) map[string]any {
	return discoveryDocument(resolveDiscovery(cfg))
}

// discoveryDocument returns a structurally valid OIDC discovery
// payload. Field set follows OIDC Core §3 + Discovery §4.1; values
// for unimplemented behaviour (e.g. scopes_supported) reflect the
// smallest credible Identuum baseline. The "mode" field is
// non-standard and signals to consumers that this document is a
// smoke artefact, not a live deployment.
func discoveryDocument(cfg OIDCDiscoveryConfig) map[string]any {
	return map[string]any{
		"issuer":                 cfg.Issuer,
		"authorization_endpoint": cfg.AuthorizationEndpoint,
		"token_endpoint":         cfg.TokenEndpoint,
		"jwks_uri":               cfg.JWKSURI,
		"response_types_supported": []string{
			"code",
		},
		"subject_types_supported": []string{
			"public",
		},
		// THE-PKCE-DECISION (owner ruling, verbatim): "Add RS256 into
		// the list BUT DO NOT USE except testing and put this into
		// documentation CLEARLY." RS256 here is a REAL capability —
		// key generation, JWKS publication, id_token signing — but it
		// fires ONLY when a client explicitly registers
		// id_token_signed_response_alg=RS256. EdDSA is, and stays, the
		// Identuum default; RS256 exists for conformance/interop
		// TESTING, not operation (docs/TESTING-OPERATORS.md). Must stay
		// in sync with domain.IDTokenSigningAlgorithms.
		"id_token_signing_alg_values_supported": []string{
			"EdDSA",
			"ES256",
			"RS256",
		},
		"scopes_supported": []string{
			"openid",
			"profile",
			"email",
		},
		"token_endpoint_auth_methods_supported": []string{
			"client_secret_basic",
			"client_secret_post",
			"private_key_jwt",
			"none",
		},
		"grant_types_supported": []string{
			"authorization_code",
			"refresh_token",
		},
		"code_challenge_methods_supported": []string{
			"S256",
		},
		// OIDC §6 request objects are unsupported and REFUSED with
		// request_not_supported / request_uri_not_supported. Both flags
		// are explicit because the Discovery DEFAULT for
		// request_uri_parameter_supported is true when omitted.
		"request_parameter_supported":     false,
		"request_uri_parameter_supported": false,
		// NOTE: this document deliberately omits any non-standard
		// "mode" / "build" / "tier" key. The OIDC conformance suite
		// flags vendor-specific top-level keys, so the OSS discovery
		// document stays strictly within OIDC Discovery 1.0 §3.
	}
}
