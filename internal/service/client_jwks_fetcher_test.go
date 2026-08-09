package service

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// ---------- helpers ----------

func ed25519JWK(t *testing.T, kid string) (ed25519.PublicKey, map[string]any) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	jwk := map[string]any{
		"kty": "OKP",
		"crv": "Ed25519",
		"x":   base64.RawURLEncoding.EncodeToString(pub),
	}
	if kid != "" {
		jwk["kid"] = kid
	}
	return pub, jwk
}

// EC P-256 JWK construction omitted from this file — modern Go
// staticcheck flags direct (*ecdsa.PublicKey).X/Y access. The
// ec-curve path is exercised end-to-end by
// internal/service/client_assertion_validator_test.go via the
// inline JWKS resolver, which shares clientAssertionPublicKeyFromJWK
// with this fetcher.

func newHTTPSJWKSServer(t *testing.T, jwk map[string]any) (*httptest.Server, *int32) {
	t.Helper()
	var hits int32
	doc, _ := json.Marshal(map[string]any{"keys": []any{jwk}})
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(doc)
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

// ---------- URL validation ----------

func TestFetch_RejectsEmptyURL(t *testing.T) {
	f := NewClientJWKSFetcherService(ClientJWKSFetcherOptions{})
	if _, err := f.Fetch(context.Background(), "", "kid"); !errors.Is(err, ErrJWKSFetchInvalidURL) {
		t.Errorf("err = %v", err)
	}
}

func TestFetch_RejectsHTTPByDefault(t *testing.T) {
	f := NewClientJWKSFetcherService(ClientJWKSFetcherOptions{})
	if _, err := f.Fetch(context.Background(), "http://example.com/jwks.json", "kid"); !errors.Is(err, ErrJWKSFetchInvalidURL) {
		t.Errorf("err = %v", err)
	}
}

func TestFetch_RejectsUnsupportedScheme(t *testing.T) {
	f := NewClientJWKSFetcherService(ClientJWKSFetcherOptions{})
	for _, raw := range []string{
		"file:///etc/passwd",
		"gopher://example.com/",
		"ftp://example.com/jwks.json",
		"data:text/plain,foo",
	} {
		if _, err := f.Fetch(context.Background(), raw, "kid"); !errors.Is(err, ErrJWKSFetchInvalidURL) {
			t.Errorf("scheme %q err = %v", raw, err)
		}
	}
}

func TestFetch_RejectsRelativeURL(t *testing.T) {
	f := NewClientJWKSFetcherService(ClientJWKSFetcherOptions{})
	if _, err := f.Fetch(context.Background(), "/relative/jwks.json", "kid"); !errors.Is(err, ErrJWKSFetchInvalidURL) {
		t.Errorf("err = %v", err)
	}
}

// ---------- happy path ----------

func TestFetch_ValidJWKSResolvesByKid(t *testing.T) {
	pub, jwk := ed25519JWK(t, "k1")
	srv, hits := newHTTPSJWKSServer(t, jwk)
	// httptest.NewTLSServer returns a 127.0.0.1 address, which
	// the safehttp default would reject. Inject the test client.
	f := NewClientJWKSFetcherService(ClientJWKSFetcherOptions{
		HTTPClient:     srv.Client(),
		AllowPlainHTTP: false,
	})
	got, err := f.Fetch(context.Background(), srv.URL, "k1")
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if gotPub, ok := got.(ed25519.PublicKey); !ok || !gotPub.Equal(pub) {
		t.Errorf("returned key mismatch")
	}
	if atomic.LoadInt32(hits) != 1 {
		t.Errorf("hits = %d", *hits)
	}
}

func TestFetch_WrongKidIsFailure(t *testing.T) {
	_, jwk := ed25519JWK(t, "k1")
	srv, _ := newHTTPSJWKSServer(t, jwk)
	f := NewClientJWKSFetcherService(ClientJWKSFetcherOptions{HTTPClient: srv.Client()})
	if _, err := f.Fetch(context.Background(), srv.URL, "k2"); !errors.Is(err, ErrJWKSFetchFailed) {
		t.Errorf("err = %v", err)
	}
}

func TestFetch_CacheHitAvoidsSecondNetworkCall(t *testing.T) {
	_, jwk := ed25519JWK(t, "k1")
	srv, hits := newHTTPSJWKSServer(t, jwk)
	f := NewClientJWKSFetcherService(ClientJWKSFetcherOptions{
		HTTPClient: srv.Client(),
		CacheTTL:   1 * time.Hour,
	})
	for i := 0; i < 3; i++ {
		if _, err := f.Fetch(context.Background(), srv.URL, "k1"); err != nil {
			t.Fatalf("fetch %d: %v", i, err)
		}
	}
	if atomic.LoadInt32(hits) != 1 {
		t.Errorf("network hits = %d, want 1 (cached)", *hits)
	}
}

func TestFetch_CacheExpiryRefetches(t *testing.T) {
	_, jwk := ed25519JWK(t, "k1")
	srv, hits := newHTTPSJWKSServer(t, jwk)
	f := NewClientJWKSFetcherService(ClientJWKSFetcherOptions{
		HTTPClient: srv.Client(),
		CacheTTL:   10 * time.Millisecond,
	})
	if _, err := f.Fetch(context.Background(), srv.URL, "k1"); err != nil {
		t.Fatalf("first: %v", err)
	}
	// Advance time via the now hook so the cache entry expires.
	frozen := time.Now()
	f.now = func() time.Time { return frozen.Add(time.Hour) }
	if _, err := f.Fetch(context.Background(), srv.URL, "k1"); err != nil {
		t.Fatalf("second: %v", err)
	}
	if got := atomic.LoadInt32(hits); got < 2 {
		t.Errorf("hits = %d, want >= 2", got)
	}
}

// ---------- non-2xx ----------

func TestFetch_Non2xxIsFailure(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	f := NewClientJWKSFetcherService(ClientJWKSFetcherOptions{HTTPClient: srv.Client()})
	if _, err := f.Fetch(context.Background(), srv.URL, "k1"); !errors.Is(err, ErrJWKSFetchFailed) {
		t.Errorf("err = %v", err)
	}
}

// ---------- oversized body ----------

func TestFetch_OversizedJWKSRejected(t *testing.T) {
	// Build a JWKS body bigger than the configured limit.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// 4 MiB of zeros wrapped in a benign JSON envelope.
		_, _ = w.Write([]byte(`{"keys":[`))
		for i := 0; i < 8; i++ {
			_, _ = w.Write([]byte(`"` + strings.Repeat("A", 512*1024) + `",`))
		}
		_, _ = w.Write([]byte(`{}]}`))
	}))
	t.Cleanup(srv.Close)
	f := NewClientJWKSFetcherService(ClientJWKSFetcherOptions{
		HTTPClient:        srv.Client(),
		ResponseBodyLimit: 64 * 1024,
	})
	if _, err := f.Fetch(context.Background(), srv.URL, "k1"); !errors.Is(err, ErrJWKSFetchFailed) {
		t.Errorf("err = %v", err)
	}
}

// ---------- malformed / missing keys ----------

func TestFetch_MalformedJSON(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{not-json`))
	}))
	t.Cleanup(srv.Close)
	f := NewClientJWKSFetcherService(ClientJWKSFetcherOptions{HTTPClient: srv.Client()})
	if _, err := f.Fetch(context.Background(), srv.URL, "k1"); !errors.Is(err, ErrJWKSFetchFailed) {
		t.Errorf("err = %v", err)
	}
}

func TestFetch_EmptyKeysArray(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"keys":[]}`))
	}))
	t.Cleanup(srv.Close)
	f := NewClientJWKSFetcherService(ClientJWKSFetcherOptions{HTTPClient: srv.Client()})
	if _, err := f.Fetch(context.Background(), srv.URL, "k1"); !errors.Is(err, ErrJWKSFetchFailed) {
		t.Errorf("err = %v", err)
	}
}

// ---------- negative cache / unknown-kid cooldown ----------

func TestFetch_UnknownKidWithinCooldownUsesNegativeCacheNoRefetch(t *testing.T) {
	_, jwk := ed25519JWK(t, "k1")
	srv, hits := newHTTPSJWKSServer(t, jwk)
	f := NewClientJWKSFetcherService(ClientJWKSFetcherOptions{
		HTTPClient:         srv.Client(),
		CacheTTL:           1 * time.Hour,
		NegativeCacheTTL:   1 * time.Hour,
		UnknownKidCooldown: 1 * time.Hour,
	})
	// First call: positive cache miss → fetch.
	if _, err := f.Fetch(context.Background(), srv.URL, "k1"); err != nil {
		t.Fatalf("priming: %v", err)
	}
	if atomic.LoadInt32(hits) != 1 {
		t.Errorf("hits after priming = %d", *hits)
	}
	// Second call: unknown kid in fresh cache → cooldown is fresh
	// (we just set lastRefetchAt? no, cooldown is "since last
	// refetch"; the priming fetch was a cold-miss not a refetch).
	// First unknown-kid request triggers refetch.
	if _, err := f.Fetch(context.Background(), srv.URL, "k-unknown"); err == nil {
		t.Errorf("expected error for unknown kid")
	}
	// After the unknown-kid refetch, hits should be 2.
	if atomic.LoadInt32(hits) != 2 {
		t.Errorf("hits after first unknown-kid = %d, want 2", *hits)
	}
	// Repeated unknown-kid within cooldown: hits should stay at 2
	// (negative cache + cooldown both block refetch).
	for i := 0; i < 5; i++ {
		_, _ = f.Fetch(context.Background(), srv.URL, "k-unknown")
	}
	if atomic.LoadInt32(hits) != 2 {
		t.Errorf("hits after repeated unknown-kid = %d, want 2", *hits)
	}
}

func TestFetch_NegativeCacheExpiryAllowsRefetch(t *testing.T) {
	_, jwk := ed25519JWK(t, "k1")
	srv, hits := newHTTPSJWKSServer(t, jwk)
	frozen := time.Now()
	f := NewClientJWKSFetcherService(ClientJWKSFetcherOptions{
		HTTPClient:         srv.Client(),
		CacheTTL:           1 * time.Hour,
		NegativeCacheTTL:   100 * time.Millisecond,
		UnknownKidCooldown: 0, // tests force the refetch via the now hook
	})
	f.now = func() time.Time { return frozen }
	// Prime + first unknown.
	_, _ = f.Fetch(context.Background(), srv.URL, "k1")
	_, _ = f.Fetch(context.Background(), srv.URL, "k-unknown")
	beforeAdvance := atomic.LoadInt32(hits)
	// Advance time PAST the negative-cache TTL.
	f.now = func() time.Time { return frozen.Add(time.Hour) }
	_, _ = f.Fetch(context.Background(), srv.URL, "k-unknown")
	if atomic.LoadInt32(hits) <= beforeAdvance {
		t.Errorf("expected refetch after negative TTL; hits before=%d after=%d", beforeAdvance, atomic.LoadInt32(hits))
	}
}

func TestFetch_RefetchClearsNegativeWhenUpstreamPublishesKid(t *testing.T) {
	// First snapshot has k1 only.
	_, jwk1 := ed25519JWK(t, "k1")
	doc1, _ := json.Marshal(map[string]any{"keys": []any{jwk1}})
	_, jwk2 := ed25519JWK(t, "k2")
	doc2, _ := json.Marshal(map[string]any{"keys": []any{jwk2}})
	body := &atomic.Value{}
	body.Store(doc1)
	var hits int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body.Load().([]byte))
	}))
	t.Cleanup(srv.Close)
	frozen := time.Now()
	f := NewClientJWKSFetcherService(ClientJWKSFetcherOptions{
		HTTPClient:         srv.Client(),
		CacheTTL:           1 * time.Hour,
		NegativeCacheTTL:   1 * time.Second,
		UnknownKidCooldown: 10 * time.Millisecond,
	})
	f.now = func() time.Time { return frozen }
	// Prime + first unknown-kid records negative entry for k2.
	_, _ = f.Fetch(context.Background(), srv.URL, "k1")
	if _, err := f.Fetch(context.Background(), srv.URL, "k2"); err == nil {
		t.Fatalf("expected k2 to be unknown initially")
	}
	// Upstream publishes k2.
	body.Store(doc2)
	// Advance past the negative-cache TTL (also past cooldown).
	f.now = func() time.Time { return frozen.Add(time.Minute) }
	got, err := f.Fetch(context.Background(), srv.URL, "k2")
	if err != nil {
		t.Errorf("k2 still unknown after upstream publish + cooldown: %v", err)
	}
	if got == nil {
		t.Errorf("k2 returned nil key")
	}
}

// ---------- negative-cache bound (P2-13) ----------

// TestFetch_NegativeCacheBounded drives far more than the cap of
// distinct unknown kids (a registered private_key_jwt client streaming
// bogus kids) and asserts negKids never exceeds the cap. The clock is
// FROZEN and NegativeCacheTTL is large, so expiry-pruning never fires —
// the bound must hold purely via eviction. TEETH: remove the cap/eviction
// from recordNegativeKid and this fails (map grows past the cap).
func TestFetch_NegativeCacheBounded(t *testing.T) {
	_, jwk := ed25519JWK(t, "k1")
	srv, _ := newHTTPSJWKSServer(t, jwk)
	frozen := time.Now()
	const maxKids = 8
	f := NewClientJWKSFetcherService(ClientJWKSFetcherOptions{
		HTTPClient:           srv.Client(),
		CacheTTL:             1 * time.Hour,
		NegativeCacheTTL:     1 * time.Hour, // large → no expiry pruning; cap holds via eviction
		UnknownKidCooldown:   1 * time.Hour, // after the first unknown, subsequent hit the cooldown insert site
		NegativeCacheMaxKids: maxKids,
	})
	f.now = func() time.Time { return frozen }

	if _, err := f.Fetch(context.Background(), srv.URL, "k1"); err != nil {
		t.Fatalf("prime positive cache: %v", err)
	}

	const streamed = maxKids * 10
	for i := 0; i < streamed; i++ {
		if _, err := f.Fetch(context.Background(), srv.URL, fmt.Sprintf("bogus-%d", i)); err == nil {
			t.Fatalf("bogus kid %d unexpectedly resolved", i)
		}
		f.mu.Lock()
		n := len(f.entries[srv.URL].negKids)
		f.mu.Unlock()
		if n > maxKids {
			t.Fatalf("negKids grew to %d, exceeds cap %d at i=%d (unbounded growth)", n, maxKids, i)
		}
	}
	f.mu.Lock()
	n := len(f.entries[srv.URL].negKids)
	f.mu.Unlock()
	if n != maxKids {
		t.Errorf("after %d distinct bogus kids, negKids=%d, want == cap %d", streamed, n, maxKids)
	}
}

// TestFetch_NegativeCacheExpiredEntriesPruned pins that a negative write
// prunes stale (expired) entries — the path that previously leaked them
// (they were dropped only when a refetch snapshot happened to cover
// them). Records a batch, advances past NegativeCacheTTL, records one
// more, and asserts the expired batch is gone.
func TestFetch_NegativeCacheExpiredEntriesPruned(t *testing.T) {
	_, jwk := ed25519JWK(t, "k1")
	srv, _ := newHTTPSJWKSServer(t, jwk)
	frozen := time.Now()
	f := NewClientJWKSFetcherService(ClientJWKSFetcherOptions{
		HTTPClient:           srv.Client(),
		CacheTTL:             1 * time.Hour,
		NegativeCacheTTL:     1 * time.Minute,
		UnknownKidCooldown:   1 * time.Hour,
		NegativeCacheMaxKids: 256,
	})
	f.now = func() time.Time { return frozen }
	if _, err := f.Fetch(context.Background(), srv.URL, "k1"); err != nil {
		t.Fatalf("prime: %v", err)
	}
	for i := 0; i < 5; i++ {
		_, _ = f.Fetch(context.Background(), srv.URL, fmt.Sprintf("old-%d", i))
	}
	f.mu.Lock()
	before := len(f.entries[srv.URL].negKids)
	f.mu.Unlock()
	if before == 0 {
		t.Fatalf("expected negatives to be recorded, got 0")
	}

	// Advance past NegativeCacheTTL, then trigger one more negative write.
	f.now = func() time.Time { return frozen.Add(2 * time.Minute) }
	_, _ = f.Fetch(context.Background(), srv.URL, "new-1")

	f.mu.Lock()
	defer f.mu.Unlock()
	neg := f.entries[srv.URL].negKids
	for k := range neg {
		if strings.HasPrefix(k, "old-") {
			t.Errorf("stale negative %q survived the prune", k)
		}
	}
	if _, ok := neg["new-1"]; !ok {
		t.Errorf("fresh negative new-1 missing after prune")
	}
}

// ---------- raw-body leak guard ----------

func TestFetch_FailureDoesNotLeakBody(t *testing.T) {
	const sentinel = "RAW-JWKS-BODY-MUST-NOT-LEAK"
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(sentinel))
	}))
	t.Cleanup(srv.Close)
	f := NewClientJWKSFetcherService(ClientJWKSFetcherOptions{HTTPClient: srv.Client()})
	_, err := f.Fetch(context.Background(), srv.URL, "k1")
	if err == nil {
		t.Errorf("expected failure")
	}
	if err != nil && strings.Contains(err.Error(), sentinel) {
		t.Errorf("error leaked raw body: %v", err)
	}
}

// fmt import compile guard.
var _ = fmt.Sprintf
