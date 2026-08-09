package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// discoveryStub serves /.well-known/openid-configuration (body built from the
// server's own URL) and, when jwk != nil, a /jwks document. It is HTTPS
// (httptest.NewTLSServer on 127.0.0.1); tests pass srv.Client() so the SSRF
// guard is bypassed for the loopback stub — the same approach the JWKS
// fetcher tests use.
func discoveryStub(t *testing.T, body func(issuer string) string, jwk map[string]any) (*httptest.Server, *int32) {
	t.Helper()
	var hits int32
	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc(wellKnownOpenIDConfigurationPath, func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, body(srv.URL))
	})
	if jwk != nil {
		mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
			doc, _ := json.Marshal(map[string]any{"keys": []any{jwk}})
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(doc)
		})
	}
	srv = httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	return srv, &hits
}

func validDiscovery(issuer string) string {
	return fmt.Sprintf(`{"issuer":%q,"authorization_endpoint":%q,"token_endpoint":%q,"jwks_uri":%q,"response_types_supported":["code"],"grant_types_supported":["authorization_code"],"id_token_signing_alg_values_supported":["ES256","EdDSA"]}`,
		issuer, issuer+"/authorize", issuer+"/token", issuer+"/jwks")
}

// discoverySvcFor builds a discovery service bound to the stub's TLS client
// (so the loopback stub is reachable) and a JWKS fetcher sharing that client.
func discoverySvcFor(srv *httptest.Server, mut func(*OIDCDiscoveryOptions)) *OIDCDiscoveryService {
	o := OIDCDiscoveryOptions{
		HTTPClient:  srv.Client(),
		JWKSFetcher: NewClientJWKSFetcherService(ClientJWKSFetcherOptions{HTTPClient: srv.Client()}),
	}
	if mut != nil {
		mut(&o)
	}
	return NewOIDCDiscoveryService(o)
}

// (happy path) A well-formed discovery document parses into the validated
// endpoints.
func TestDiscovery_HappyPathParses(t *testing.T) {
	srv, hits := discoveryStub(t, validDiscovery, nil)
	svc := discoverySvcFor(srv, nil)

	doc, err := svc.Discover(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if doc.Issuer != srv.URL {
		t.Errorf("issuer = %q, want %q", doc.Issuer, srv.URL)
	}
	if doc.AuthorizationEndpoint != srv.URL+"/authorize" || doc.TokenEndpoint != srv.URL+"/token" || doc.JWKSURI != srv.URL+"/jwks" {
		t.Errorf("endpoints wrong: %+v", doc)
	}
	if *hits != 1 {
		t.Errorf("discovery hits = %d, want 1", *hits)
	}
}

// (https-only, issuer) An http:// issuer is refused before any network call.
func TestDiscovery_RejectsNonHTTPSIssuer(t *testing.T) {
	svc := NewOIDCDiscoveryService(OIDCDiscoveryOptions{})
	for _, bad := range []string{"", "http://accounts.example.com", "ftp://x.example", "/relative", "not-a-url"} {
		_, err := svc.Discover(context.Background(), bad)
		if !errors.Is(err, ErrDiscoveryInvalidURL) {
			t.Errorf("issuer %q: err = %v, want ErrDiscoveryInvalidURL", bad, err)
		}
	}
}

// (https-only, endpoint) A discovered endpoint on http:// fails validation.
func TestDiscovery_RejectsNonHTTPSEndpoint(t *testing.T) {
	body := func(issuer string) string {
		badToken := strings.Replace(issuer, "https://", "http://", 1) + "/token"
		return fmt.Sprintf(`{"issuer":%q,"authorization_endpoint":%q,"token_endpoint":%q,"jwks_uri":%q}`,
			issuer, issuer+"/authorize", badToken, issuer+"/jwks")
	}
	srv, _ := discoveryStub(t, body, nil)
	svc := discoverySvcFor(srv, nil)
	if _, err := svc.Discover(context.Background(), srv.URL); !errors.Is(err, ErrDiscoveryFailed) {
		t.Errorf("http token_endpoint: err = %v, want ErrDiscoveryFailed", err)
	}
}

// (issuer consistency) A document whose issuer ≠ the requested issuer is
// refused (OIDC Discovery §4.3 mixup defense).
func TestDiscovery_RejectsIssuerMismatch(t *testing.T) {
	body := func(issuer string) string {
		return fmt.Sprintf(`{"issuer":"https://attacker.example","authorization_endpoint":%q,"token_endpoint":%q,"jwks_uri":%q}`,
			issuer+"/authorize", issuer+"/token", issuer+"/jwks")
	}
	srv, _ := discoveryStub(t, body, nil)
	svc := discoverySvcFor(srv, nil)
	if _, err := svc.Discover(context.Background(), srv.URL); !errors.Is(err, ErrDiscoveryFailed) {
		t.Errorf("issuer mismatch: err = %v, want ErrDiscoveryFailed", err)
	}
}

// (SSRF) With the real safehttp client, a link-local / cloud-metadata target
// is blocked at dial time and surfaces as a clean typed error.
func TestDiscovery_SSRFBlockedTargetRefused(t *testing.T) {
	svc := NewOIDCDiscoveryService(OIDCDiscoveryOptions{}) // default safehttp.NewSafeClient
	for _, target := range []string{"https://169.254.169.254", "https://127.0.0.1:9"} {
		_, err := svc.Discover(context.Background(), target)
		if !errors.Is(err, ErrDiscoveryFailed) {
			t.Errorf("SSRF target %q: err = %v, want ErrDiscoveryFailed (dial blocked)", target, err)
		}
	}
}

// (oversized) A discovery body over the response-size cap is rejected.
func TestDiscovery_OversizedResponseRejected(t *testing.T) {
	body := func(issuer string) string {
		pad := strings.Repeat(" ", 4096)
		return fmt.Sprintf(`{"issuer":%q,"authorization_endpoint":%q,"token_endpoint":%q,"jwks_uri":%q,"_pad":%q}`,
			issuer, issuer+"/authorize", issuer+"/token", issuer+"/jwks", pad)
	}
	srv, _ := discoveryStub(t, body, nil)
	svc := discoverySvcFor(srv, func(o *OIDCDiscoveryOptions) { o.ResponseBodyLimit = 512 })
	if _, err := svc.Discover(context.Background(), srv.URL); !errors.Is(err, ErrDiscoveryFailed) {
		t.Errorf("oversized: err = %v, want ErrDiscoveryFailed", err)
	}
}

// (malformed) Non-JSON body is rejected.
func TestDiscovery_MalformedJSONRejected(t *testing.T) {
	srv, _ := discoveryStub(t, func(string) string { return "{ this is not json" }, nil)
	svc := discoverySvcFor(srv, nil)
	if _, err := svc.Discover(context.Background(), srv.URL); !errors.Is(err, ErrDiscoveryFailed) {
		t.Errorf("malformed: err = %v, want ErrDiscoveryFailed", err)
	}
}

// (JWKS reuse) Provider signing-key resolution goes through the shared
// ClientJWKSFetcherService: a present kid resolves; an unknown kid returns the
// fetcher's negative-cache failure.
func TestDiscovery_ResolveSigningKeyByKidAndUnknown(t *testing.T) {
	_, jwk := ed25519JWK(t, "k1")
	srv, _ := discoveryStub(t, validDiscovery, jwk)
	svc := discoverySvcFor(srv, nil)

	doc, err := svc.Discover(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	key, err := svc.ResolveSigningKey(context.Background(), doc, "k1")
	if err != nil || key == nil {
		t.Fatalf("ResolveSigningKey(k1): key=%v err=%v", key, err)
	}
	if _, err := svc.ResolveSigningKey(context.Background(), doc, "unknown-kid"); !errors.Is(err, ErrJWKSFetchFailed) {
		t.Errorf("unknown kid: err = %v, want ErrJWKSFetchFailed", err)
	}
}

// (cache) A second Discover for the same issuer is served from cache — no
// second network fetch.
func TestDiscovery_CacheHitAvoidsRefetch(t *testing.T) {
	srv, hits := discoveryStub(t, validDiscovery, nil)
	svc := discoverySvcFor(srv, nil)

	if _, err := svc.Discover(context.Background(), srv.URL); err != nil {
		t.Fatalf("first Discover: %v", err)
	}
	if _, err := svc.Discover(context.Background(), srv.URL); err != nil {
		t.Fatalf("second Discover: %v", err)
	}
	if *hits != 1 {
		t.Errorf("discovery hits = %d, want 1 (second served from cache)", *hits)
	}
}
