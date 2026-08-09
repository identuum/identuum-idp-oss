package service

import (
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/identuum/identuum-idp-oss/internal/utils/safehttp"
)

// ClientJWKSFetcherService fetches and caches the JWKS document
// at a private_key_jwt client's configured `jwks_uri` so the
// ClientAssertionValidator can resolve a verification key without
// inline JWKS storage.
//
// Safety posture:
//
//   - HTTPS only by default. `http://` is rejected unless
//     AllowPlainHTTP is explicitly set (test-only mode).
//   - URLs with non-https/http schemes (file/gopher/ftp/data/unix)
//     are rejected outright.
//   - Underlying HTTP client uses safehttp.NewSafeClient, which
//     blocks connections to loopback, RFC 1918 private ranges,
//     link-local, multicast, and the unspecified address. Cloud
//     metadata IPs are blocked too. Operators that need an
//     internal JWKS endpoint can supply a custom HTTPClient that
//     does not run the SSRF guard.
//   - Request timeout defaults to 5 s.
//   - Response body is limited to ResponseBodyLimit (default
//     256 KiB) so a malicious server cannot stream gigabytes of
//     "JWKS".
//   - Cache TTL defaults to 10 minutes — a deliberately tight
//     positive window so a revoked upstream key returns to
//     usable state within minutes.
//   - The raw response body is NEVER echoed to logs or errors.
//   - The fetched keys themselves are NEVER serialised in audit
//     metadata; only the JWKS URI is observable.
type ClientJWKSFetcherService struct {
	httpClient         *http.Client
	cacheTTL           time.Duration
	negCacheTTL        time.Duration
	unknownKidCooldown time.Duration
	responseBodyLimit  int64
	negKidsMax         int
	allowPlainHTTP     bool
	now                func() time.Time

	mu      sync.Mutex
	entries map[string]*clientJWKSEntry
}

// ClientJWKSFetcherOptions parameterises the fetcher.
type ClientJWKSFetcherOptions struct {
	// HTTPClient is the underlying http.Client used for fetches.
	// nil falls back to safehttp.NewSafeClient with the
	// configured timeout.
	HTTPClient *http.Client
	// Timeout bounds a single fetch. Defaults to 5 s.
	Timeout time.Duration
	// CacheTTL is the positive cache window. Defaults to 10 min.
	CacheTTL time.Duration
	// ResponseBodyLimit caps the JWKS document size. Defaults to
	// 256 KiB.
	ResponseBodyLimit int64
	// AllowPlainHTTP enables http:// (and bypasses the SSRF guard
	// when an HTTPClient is also supplied). Test-only — production
	// deployments MUST leave this false.
	AllowPlainHTTP bool
	// NegativeCacheTTL is how long a "kid not in JWKS" result is
	// remembered before a refetch is attempted. Defaults to 60 s.
	NegativeCacheTTL time.Duration
	// UnknownKidCooldown rate-limits the one-shot refetch on
	// unknown kid per (jwks_uri) entry. Defaults to 5 s.
	UnknownKidCooldown time.Duration
	// NegativeCacheMaxKids bounds the number of negative-cache
	// entries retained per (jwks_uri) entry. Without a cap, a
	// registered private_key_jwt client presenting a stream of
	// distinct bogus kids grows process memory without limit (DoS),
	// since expired negatives are otherwise pruned only when a later
	// refetch's snapshot happens to cover them. Defaults to 256.
	// <=0 falls back to the default.
	NegativeCacheMaxKids int
}

const (
	defaultJWKSFetchTimeout       = 5 * time.Second
	defaultJWKSCacheTTL           = 10 * time.Minute
	defaultJWKSResponseBodyLimit  = int64(256 * 1024)
	defaultJWKSNegativeCacheTTL   = 60 * time.Second
	defaultJWKSUnknownKidCooldown = 5 * time.Second
	// defaultJWKSNegativeCacheMaxKids bounds negKids per entry so an
	// attacker streaming distinct bogus kids cannot grow memory without
	// limit. A few hundred covers legitimate key-rotation churn while
	// capping the DoS surface.
	defaultJWKSNegativeCacheMaxKids = 256
)

// clientJWKSEntry is one row in the in-memory cache.
type clientJWKSEntry struct {
	keysByKid     map[string]crypto.PublicKey
	singleKey     crypto.PublicKey // populated when the JWKS had exactly one key
	expiry        time.Time
	negKids       map[string]time.Time // kid → negative-cache expiry
	lastRefetchAt time.Time
}

// NewClientJWKSFetcherService constructs the fetcher.
func NewClientJWKSFetcherService(opts ClientJWKSFetcherOptions) *ClientJWKSFetcherService {
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = defaultJWKSFetchTimeout
	}
	hc := opts.HTTPClient
	if hc == nil {
		hc = safehttp.NewSafeClient()
		hc.Timeout = timeout
	}
	cacheTTL := opts.CacheTTL
	if cacheTTL <= 0 {
		cacheTTL = defaultJWKSCacheTTL
	}
	bodyLimit := opts.ResponseBodyLimit
	if bodyLimit <= 0 {
		bodyLimit = defaultJWKSResponseBodyLimit
	}
	negTTL := opts.NegativeCacheTTL
	if negTTL <= 0 {
		negTTL = defaultJWKSNegativeCacheTTL
	}
	cooldown := opts.UnknownKidCooldown
	if cooldown <= 0 {
		cooldown = defaultJWKSUnknownKidCooldown
	}
	negMax := opts.NegativeCacheMaxKids
	if negMax <= 0 {
		negMax = defaultJWKSNegativeCacheMaxKids
	}
	return &ClientJWKSFetcherService{
		httpClient:         hc,
		cacheTTL:           cacheTTL,
		negCacheTTL:        negTTL,
		unknownKidCooldown: cooldown,
		responseBodyLimit:  bodyLimit,
		negKidsMax:         negMax,
		allowPlainHTTP:     opts.AllowPlainHTTP,
		now:                time.Now,
		entries:            map[string]*clientJWKSEntry{},
	}
}

// ErrJWKSFetchInvalidURL is the opaque sentinel returned for any
// pre-fetch URL validation failure. Callers (the validator) map
// this to invalid_client at the wire layer.
var ErrJWKSFetchInvalidURL = errors.New("service: invalid JWKS URI")

// ErrJWKSFetchFailed wraps any post-validation failure
// (transport, parse, size limit, missing keys, kid not found).
// The raw response body is NEVER attached.
var ErrJWKSFetchFailed = errors.New("service: JWKS fetch failed")

// Fetch returns the verification key for (jwksURI, kid). When
// kid is empty and the JWKS contains exactly one key, that key is
// used.
//
// Cache behavior (parity with the monolith's AssertionJWKSCache):
//
//   - Positive cache: if the entry is within cacheTTL AND the kid
//     is present, the cached key is returned without a network
//     call.
//   - Negative cache: if a prior fetch did not include kid, the
//     negative entry is honored for negCacheTTL. A repeated
//     lookup for the same missing kid returns ErrJWKSFetchFailed
//     immediately, without a refetch.
//   - Unknown-kid refetch with cooldown: when the positive
//     snapshot is fresh but the kid is missing AND no negative
//     entry exists, one synchronous refetch is allowed per
//     unknownKidCooldown window. This catches the normal
//     key-rotation case where the upstream IdP has just published
//     a new kid.
//   - Successful refetch implicitly clears negative entries for
//     kids that the new snapshot now contains.
func (s *ClientJWKSFetcherService) Fetch(ctx context.Context, jwksURI, kid string) (crypto.PublicKey, error) {
	if err := s.validateJWKSURI(jwksURI); err != nil {
		return nil, err
	}
	now := s.now()

	s.mu.Lock()
	entry, ok := s.entries[jwksURI]
	if !ok {
		entry = &clientJWKSEntry{
			keysByKid: map[string]crypto.PublicKey{},
			negKids:   map[string]time.Time{},
		}
		s.entries[jwksURI] = entry
	}

	// Negative-cache short-circuit. Repeated probes for the same
	// missing kid within negCacheTTL return without any work.
	if kid != "" {
		if exp, hit := entry.negKids[kid]; hit && now.Before(exp) {
			s.mu.Unlock()
			return nil, ErrJWKSFetchFailed
		}
	}

	// Positive-cache hit.
	if entry.keysByKid != nil && now.Before(entry.expiry) {
		if kid == "" {
			if entry.singleKey != nil {
				s.mu.Unlock()
				return entry.singleKey, nil
			}
		} else if k, hit := entry.keysByKid[kid]; hit {
			s.mu.Unlock()
			return k, nil
		}
		// Snapshot fresh but the kid is unknown. Cooldown gate
		// determines whether we refetch or record a negative
		// entry immediately.
		if now.Sub(entry.lastRefetchAt) < s.unknownKidCooldown {
			if kid != "" {
				s.recordNegativeKid(entry, kid, now)
			}
			s.mu.Unlock()
			return nil, ErrJWKSFetchFailed
		}
		entry.lastRefetchAt = now
		// Fall through to refetch.
	}

	// Release the lock for the network call.
	s.mu.Unlock()
	fresh, err := s.fetchOnce(ctx, jwksURI)
	if err != nil {
		return nil, err
	}
	fresh.expiry = s.now().Add(s.cacheTTL)

	// Install the snapshot. Preserve any negative entries that
	// the new snapshot did NOT cover, drop those that it did.
	s.mu.Lock()
	entry = s.entries[jwksURI]
	if entry == nil {
		entry = &clientJWKSEntry{
			negKids: map[string]time.Time{},
		}
		s.entries[jwksURI] = entry
	}
	entry.keysByKid = fresh.keysByKid
	entry.singleKey = fresh.singleKey
	entry.expiry = fresh.expiry
	if entry.negKids == nil {
		entry.negKids = map[string]time.Time{}
	}
	for negKid := range entry.negKids {
		if _, present := entry.keysByKid[negKid]; present {
			delete(entry.negKids, negKid)
		}
	}
	// Return the requested key (or record a negative entry).
	if kid == "" {
		if entry.singleKey != nil {
			s.mu.Unlock()
			return entry.singleKey, nil
		}
		s.mu.Unlock()
		return nil, ErrJWKSFetchFailed
	}
	if k, hit := entry.keysByKid[kid]; hit {
		s.mu.Unlock()
		return k, nil
	}
	s.recordNegativeKid(entry, kid, s.now())
	s.mu.Unlock()
	return nil, ErrJWKSFetchFailed
}

// recordNegativeKid inserts a negative-cache entry for kid, keeping
// entry.negKids bounded by s.negKidsMax. MUST be called with s.mu held
// (all negKids access is already serialised there). Steps:
//
//  1. Prune EXPIRED negatives (now at/after their expiry). Nothing else
//     prunes expired negatives — the refetch path only drops negatives
//     the new snapshot covers — so without this an attacker streaming
//     distinct bogus kids within negCacheTTL would grow the map forever.
//  2. If inserting a NEW kid would reach the cap, evict the
//     oldest-expiring entries until there is room.
//  3. Insert (or refresh) the kid.
//
// Post-condition: len(entry.negKids) <= s.negKidsMax. Purely a memory
// guard — a genuinely-missing kid is still negatively cached and still
// short-circuits within negCacheTTL; a present kid still resolves.
func (s *ClientJWKSFetcherService) recordNegativeKid(entry *clientJWKSEntry, kid string, now time.Time) {
	// 1. Prune expired negatives.
	for k, exp := range entry.negKids {
		if !now.Before(exp) { // now >= exp → expired
			delete(entry.negKids, k)
		}
	}
	// 2. Make room for a NEW kid (an existing kid is refreshed in place,
	//    so it does not change the map size).
	if _, exists := entry.negKids[kid]; !exists {
		for len(entry.negKids) >= s.negKidsMax {
			var oldestKid string
			var oldestExp time.Time
			first := true
			for k, exp := range entry.negKids {
				if first || exp.Before(oldestExp) {
					oldestKid, oldestExp, first = k, exp, false
				}
			}
			if first { // defensively: nothing left to evict
				break
			}
			delete(entry.negKids, oldestKid)
		}
	}
	// 3. Insert / refresh.
	entry.negKids[kid] = now.Add(s.negCacheTTL)
}

// validateJWKSURI enforces the OSS allowlist:
//
//   - scheme must be https (or http when AllowPlainHTTP is set)
//   - host must be non-empty
//   - URL must be absolute
func (s *ClientJWKSFetcherService) validateJWKSURI(raw string) error {
	if strings.TrimSpace(raw) == "" {
		return ErrJWKSFetchInvalidURL
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ErrJWKSFetchInvalidURL
	}
	if !u.IsAbs() {
		return ErrJWKSFetchInvalidURL
	}
	scheme := strings.ToLower(u.Scheme)
	switch scheme {
	case "https":
	case "http":
		if !s.allowPlainHTTP {
			return ErrJWKSFetchInvalidURL
		}
	default:
		return ErrJWKSFetchInvalidURL
	}
	if u.Host == "" {
		return ErrJWKSFetchInvalidURL
	}
	return nil
}

// fetchOnce performs a single HTTP GET and parses the result.
func (s *ClientJWKSFetcherService) fetchOnce(ctx context.Context, jwksURI string) (*clientJWKSEntry, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURI, nil)
	if err != nil {
		return nil, ErrJWKSFetchFailed
	}
	req.Header.Set("Accept", "application/json")
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, ErrJWKSFetchFailed
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, ErrJWKSFetchFailed
	}
	limited := http.MaxBytesReader(nil, resp.Body, s.responseBodyLimit)
	body, readErr := io.ReadAll(limited)
	if readErr != nil {
		return nil, ErrJWKSFetchFailed
	}
	return parseJWKSBody(body)
}

// parseJWKSBody decodes the JWKS document and returns the
// populated entry.
func parseJWKSBody(body []byte) (*clientJWKSEntry, error) {
	var doc struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, ErrJWKSFetchFailed
	}
	if len(doc.Keys) == 0 {
		return nil, ErrJWKSFetchFailed
	}
	out := &clientJWKSEntry{keysByKid: map[string]crypto.PublicKey{}}
	for _, k := range doc.Keys {
		parsed, err := clientAssertionPublicKeyFromJWK(k)
		if err != nil {
			// Skip unsupported entries silently — a multi-key set
			// is still usable if at least one supported key is
			// present.
			continue
		}
		if kid, _ := k["kid"].(string); kid != "" {
			out.keysByKid[kid] = parsed
		}
	}
	if len(out.keysByKid) == 0 && len(doc.Keys) == 1 {
		// Single keyless entry — accept it for callers that pass
		// an empty kid (parity with resolveInlineAssertionJWKSKey).
		parsed, err := clientAssertionPublicKeyFromJWK(doc.Keys[0])
		if err != nil {
			return nil, ErrJWKSFetchFailed
		}
		out.singleKey = parsed
		return out, nil
	}
	if len(out.keysByKid) == 0 {
		return nil, ErrJWKSFetchFailed
	}
	// If exactly one supported key was parsed, also wire it as
	// singleKey so an empty-kid caller resolves cleanly.
	if len(out.keysByKid) == 1 {
		for _, v := range out.keysByKid {
			out.singleKey = v
		}
	}
	return out, nil
}

// Reference fmt so the linter does not strip the import when no
// fmt.X call survives a refactor.
var _ = fmt.Sprintf
