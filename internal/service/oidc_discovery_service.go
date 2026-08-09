package service

import (
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/identuum/identuum-idp-oss/internal/utils/safehttp"
)

// OIDCDiscoveryService fetches, validates, and caches an upstream OIDC
// provider's metadata (OpenID Provider Configuration, OIDC Discovery 1.0 /
// RFC 8414) for the OSS relying-party login flow — Slice 3 of
// docs/design/oss-basic-oidc-login.md. It also resolves the provider's
// signing keys, delegating to the shared ClientJWKSFetcherService (the SAME
// fetch/cache/size-cap/negative-cache/HTTPS-guarded path used for client
// assertion JWKS) — it does NOT run a parallel fetcher.
//
// Safety posture (mirrors ClientJWKSFetcherService):
//
//   - HTTPS only. http:// is rejected unless AllowPlainHTTP (test-only).
//     The issuer, the discovered authorization/token endpoints, and the
//     jwks_uri are ALL required to be absolute https URLs.
//   - Outbound over safehttp.NewSafeClient by default — the SSRF guard
//     blocks loopback, RFC 1918 private, link-local (incl. 169.254.169.254
//     cloud metadata), multicast, and the unspecified address at dial time.
//   - Response body capped at ResponseBodyLimit (default 64 KiB) so a
//     malicious provider cannot stream an unbounded "discovery" document.
//   - Per-issuer positive cache (TTL) + a short negative cache so a failed
//     discovery is not retried in a hot loop.
//   - Issuer-consistency check (OIDC Discovery §4.3): the `issuer` in the
//     fetched document MUST equal the requested issuer — defends against a
//     provider-mixup / substitution.
//   - The raw response body is NEVER echoed to logs or errors; failures are
//     opaque typed sentinels (no panic — P-018).
type OIDCDiscoveryService struct {
	httpClient        *http.Client
	jwks              *ClientJWKSFetcherService
	cacheTTL          time.Duration
	negCacheTTL       time.Duration
	responseBodyLimit int64
	allowPlainHTTP    bool
	now               func() time.Time

	mu    sync.Mutex
	cache map[string]*oidcDiscoveryEntry
}

// OIDCDiscoveryDocument is the validated subset of the provider metadata the
// RP login flow needs. It is returned only after issuer-consistency + HTTPS +
// required-field validation have passed.
type OIDCDiscoveryDocument struct {
	Issuer                           string
	AuthorizationEndpoint            string
	TokenEndpoint                    string
	JWKSURI                          string
	ResponseTypesSupported           []string
	GrantTypesSupported              []string
	IDTokenSigningAlgValuesSupported []string
}

// OIDCDiscoveryOptions parameterises the discovery service.
type OIDCDiscoveryOptions struct {
	// HTTPClient is the client used for discovery GETs. nil ⇒
	// safehttp.NewSafeClient with the configured timeout.
	HTTPClient *http.Client
	// Timeout bounds a single discovery fetch. Defaults to 5 s.
	Timeout time.Duration
	// CacheTTL is the positive per-issuer cache window. Defaults to 10 min.
	CacheTTL time.Duration
	// NegativeCacheTTL is how long a failed discovery is remembered before a
	// retry is attempted. Defaults to 60 s.
	NegativeCacheTTL time.Duration
	// ResponseBodyLimit caps the discovery document size. Defaults to 64 KiB.
	ResponseBodyLimit int64
	// AllowPlainHTTP enables http:// for the issuer/endpoints/jwks_uri.
	// Test-only — production deployments MUST leave this false.
	AllowPlainHTTP bool
	// JWKSFetcher is the shared provider-JWKS fetcher REUSED for signing-key
	// resolution. nil ⇒ construct one sharing this service's HTTP client +
	// timeout + AllowPlainHTTP (still the same safehttp-guarded path).
	JWKSFetcher *ClientJWKSFetcherService
}

const (
	defaultDiscoveryTimeout           = 5 * time.Second
	defaultDiscoveryCacheTTL          = 10 * time.Minute
	defaultDiscoveryNegativeCacheTTL  = 60 * time.Second
	defaultDiscoveryResponseBodyLimit = int64(64 * 1024)
	wellKnownOpenIDConfigurationPath  = "/.well-known/openid-configuration"
)

// oidcDiscoveryEntry is one per-issuer cache row: a positive doc within
// expiry, or a negative marker within negExpiry.
type oidcDiscoveryEntry struct {
	doc       *OIDCDiscoveryDocument
	expiry    time.Time
	negExpiry time.Time
}

// ErrDiscoveryInvalidURL is returned for a pre-fetch issuer/URL validation
// failure (empty, relative, non-https, missing host).
var ErrDiscoveryInvalidURL = errors.New("service: invalid OIDC issuer/discovery URL")

// ErrDiscoveryFailed wraps any post-validation failure (transport / SSRF
// block / non-2xx / size limit / malformed JSON / issuer mismatch / missing
// or non-https endpoints). The raw response body is NEVER attached.
var ErrDiscoveryFailed = errors.New("service: OIDC discovery failed")

// NewOIDCDiscoveryService constructs the service. It has no required injected
// dependency (it builds its own safehttp client + JWKS fetcher when not
// supplied), so there is no fail-closed StartupReport fault — all failures are
// typed errors on the fetch path.
func NewOIDCDiscoveryService(opts OIDCDiscoveryOptions) *OIDCDiscoveryService {
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = defaultDiscoveryTimeout
	}
	hc := opts.HTTPClient
	if hc == nil {
		hc = safehttp.NewSafeClient()
		hc.Timeout = timeout
	}
	cacheTTL := opts.CacheTTL
	if cacheTTL <= 0 {
		cacheTTL = defaultDiscoveryCacheTTL
	}
	negTTL := opts.NegativeCacheTTL
	if negTTL <= 0 {
		negTTL = defaultDiscoveryNegativeCacheTTL
	}
	bodyLimit := opts.ResponseBodyLimit
	if bodyLimit <= 0 {
		bodyLimit = defaultDiscoveryResponseBodyLimit
	}
	jwks := opts.JWKSFetcher
	if jwks == nil {
		jwks = NewClientJWKSFetcherService(ClientJWKSFetcherOptions{
			HTTPClient:     opts.HTTPClient, // nil ⇒ its own safehttp client
			Timeout:        timeout,
			AllowPlainHTTP: opts.AllowPlainHTTP,
		})
	}
	return &OIDCDiscoveryService{
		httpClient:        hc,
		jwks:              jwks,
		cacheTTL:          cacheTTL,
		negCacheTTL:       negTTL,
		responseBodyLimit: bodyLimit,
		allowPlainHTTP:    opts.AllowPlainHTTP,
		now:               time.Now,
		cache:             map[string]*oidcDiscoveryEntry{},
	}
}

// Discover fetches + validates + caches the provider metadata for issuer.
// The discovery URL is issuer + "/.well-known/openid-configuration".
func (s *OIDCDiscoveryService) Discover(ctx context.Context, issuer string) (*OIDCDiscoveryDocument, error) {
	normIssuer, err := s.normalizeIssuer(issuer)
	if err != nil {
		return nil, err
	}

	now := s.now()
	s.mu.Lock()
	if e, ok := s.cache[normIssuer]; ok {
		if e.doc != nil && now.Before(e.expiry) {
			d := e.doc
			s.mu.Unlock()
			return d, nil
		}
		if !e.negExpiry.IsZero() && now.Before(e.negExpiry) {
			s.mu.Unlock()
			return nil, ErrDiscoveryFailed
		}
	}
	s.mu.Unlock()

	body, ferr := s.fetchOnce(ctx, normIssuer+wellKnownOpenIDConfigurationPath)
	if ferr != nil {
		s.recordNegative(normIssuer)
		return nil, ErrDiscoveryFailed
	}
	doc, verr := s.parseAndValidate(body, normIssuer)
	if verr != nil {
		s.recordNegative(normIssuer)
		return nil, ErrDiscoveryFailed
	}

	s.mu.Lock()
	s.cache[normIssuer] = &oidcDiscoveryEntry{doc: doc, expiry: s.now().Add(s.cacheTTL)}
	s.mu.Unlock()
	return doc, nil
}

// ResolveSigningKey resolves the provider's signing key for (jwks_uri, kid)
// by delegating to the shared ClientJWKSFetcherService — the SAME
// fetch/cache/negative-cache/size-cap/HTTPS-guarded path used for client
// assertion JWKS. No parallel fetcher. An empty kid resolves a single-key
// JWKS; an unknown kid returns the fetcher's ErrJWKSFetchFailed (negative).
func (s *OIDCDiscoveryService) ResolveSigningKey(ctx context.Context, doc *OIDCDiscoveryDocument, kid string) (crypto.PublicKey, error) {
	if doc == nil || doc.JWKSURI == "" {
		return nil, ErrDiscoveryFailed
	}
	return s.jwks.Fetch(ctx, doc.JWKSURI, kid)
}

func (s *OIDCDiscoveryService) recordNegative(issuer string) {
	s.mu.Lock()
	s.cache[issuer] = &oidcDiscoveryEntry{negExpiry: s.now().Add(s.negCacheTTL)}
	s.mu.Unlock()
}

// normalizeIssuer validates the issuer is an absolute https URL with a host
// and returns it with any trailing slash trimmed (for the well-known join +
// issuer-consistency comparison).
func (s *OIDCDiscoveryService) normalizeIssuer(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", ErrDiscoveryInvalidURL
	}
	if !s.isAllowedURL(trimmed) {
		return "", ErrDiscoveryInvalidURL
	}
	return strings.TrimRight(trimmed, "/"), nil
}

// isAllowedURL reports whether raw is an absolute https URL with a host
// (or http when AllowPlainHTTP is set, test-only).
func (s *OIDCDiscoveryService) isAllowedURL(raw string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || !u.IsAbs() || u.Host == "" {
		return false
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return true
	case "http":
		return s.allowPlainHTTP
	default:
		return false
	}
}

// fetchOnce performs a single GET, enforces a 2xx status + the response size
// cap, and returns the raw body. Any transport error (incl. a safehttp SSRF
// block at dial time) surfaces as ErrDiscoveryFailed.
func (s *OIDCDiscoveryService) fetchOnce(ctx context.Context, discoveryURL string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return nil, ErrDiscoveryFailed
	}
	req.Header.Set("Accept", "application/json")
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, ErrDiscoveryFailed
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, ErrDiscoveryFailed
	}
	limited := http.MaxBytesReader(nil, resp.Body, s.responseBodyLimit)
	body, readErr := io.ReadAll(limited)
	if readErr != nil {
		return nil, ErrDiscoveryFailed
	}
	return body, nil
}

// parseAndValidate decodes the metadata and enforces: issuer consistency,
// required endpoints present, and https-only for every endpoint + jwks_uri.
func (s *OIDCDiscoveryService) parseAndValidate(body []byte, requestedIssuer string) (*OIDCDiscoveryDocument, error) {
	var raw struct {
		Issuer                           string   `json:"issuer"`
		AuthorizationEndpoint            string   `json:"authorization_endpoint"`
		TokenEndpoint                    string   `json:"token_endpoint"`
		JWKSURI                          string   `json:"jwks_uri"`
		ResponseTypesSupported           []string `json:"response_types_supported"`
		GrantTypesSupported              []string `json:"grant_types_supported"`
		IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, ErrDiscoveryFailed
	}
	// Issuer consistency (OIDC Discovery §4.3): the returned issuer MUST equal
	// the requested issuer.
	if strings.TrimRight(raw.Issuer, "/") != requestedIssuer {
		return nil, ErrDiscoveryFailed
	}
	// Required endpoints must be present and https-only.
	if raw.AuthorizationEndpoint == "" || raw.TokenEndpoint == "" || raw.JWKSURI == "" {
		return nil, ErrDiscoveryFailed
	}
	for _, ep := range []string{raw.AuthorizationEndpoint, raw.TokenEndpoint, raw.JWKSURI} {
		if !s.isAllowedURL(ep) {
			return nil, ErrDiscoveryFailed
		}
	}
	return &OIDCDiscoveryDocument{
		Issuer:                           raw.Issuer,
		AuthorizationEndpoint:            raw.AuthorizationEndpoint,
		TokenEndpoint:                    raw.TokenEndpoint,
		JWKSURI:                          raw.JWKSURI,
		ResponseTypesSupported:           raw.ResponseTypesSupported,
		GrantTypesSupported:              raw.GrantTypesSupported,
		IDTokenSigningAlgValuesSupported: raw.IDTokenSigningAlgValuesSupported,
	}, nil
}
