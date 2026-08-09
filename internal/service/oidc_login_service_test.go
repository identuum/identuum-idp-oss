package service

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/lifecycle"
	"github.com/identuum/identuum-idp-oss/internal/repository"
)

// fakeOIDCStateRepo is an in-memory OIDCStateRepository keyed by the state
// token (the table's primary key). createErr forces a persist failure.
type fakeOIDCStateRepo struct {
	byState   map[string]*domain.OIDCState
	createErr error
}

var _ repository.OIDCStateRepository = (*fakeOIDCStateRepo)(nil)

func newFakeOIDCStateRepo() *fakeOIDCStateRepo {
	return &fakeOIDCStateRepo{byState: map[string]*domain.OIDCState{}}
}

func (f *fakeOIDCStateRepo) Create(_ context.Context, st *domain.OIDCState) error {
	if f.createErr != nil {
		return f.createErr
	}
	cp := *st
	f.byState[st.State] = &cp
	return nil
}
func (f *fakeOIDCStateRepo) Get(_ context.Context, key string) (*domain.OIDCState, error) {
	s, ok := f.byState[key]
	if !ok {
		return nil, fmt.Errorf("not found")
	}
	cp := *s
	return &cp, nil
}
func (f *fakeOIDCStateRepo) ConsumeByState(_ context.Context, key string) (*domain.OIDCState, error) {
	s, ok := f.byState[key]
	if !ok {
		return nil, nil // already consumed / never existed — single-use reject
	}
	delete(f.byState, key)
	cp := *s
	return &cp, nil
}
func (f *fakeOIDCStateRepo) Delete(_ context.Context, key string) error {
	delete(f.byState, key)
	return nil
}

// DeleteExpired models the Pgx sweep (`expires_at < NOW()`): it removes rows
// whose ExpiresAt is in the past and leaves live rows untouched, returning the
// number removed.
func (f *fakeOIDCStateRepo) DeleteExpired(_ context.Context) (int64, error) {
	now := time.Now()
	var n int64
	for k, s := range f.byState {
		if s.ExpiresAt.Before(now) {
			delete(f.byState, k)
			n++
		}
	}
	return n, nil
}

// loginHarness wires the login service over fakes + a stub discovery server.
type loginHarness struct {
	svc       *OIDCLoginService
	providers *fakeIDPConfigRepo
	states    *fakeOIDCStateRepo
	pid       uuid.UUID
	redirect  string
	srv       *httptest.Server
}

func newOIDCLoginHarness(t *testing.T, discoveryBody func(string) string) *loginHarness {
	t.Helper()
	srv, _ := discoveryStub(t, discoveryBody, nil)
	discovery := NewOIDCDiscoveryService(OIDCDiscoveryOptions{HTTPClient: srv.Client()})
	providers := newFakeIDPConfigRepo()
	states := newFakeOIDCStateRepo()

	pid := uuid.New()
	redirect := "https://idp.example/api/v1/auth/idp/" + pid.String() + "/callback"
	providers.byID[pid] = &domain.IdentityProvider{
		ID:             pid,
		OrganizationID: uuid.New(),
		Type:           domain.IDPTypeOIDC,
		Active:         true,
		Config: domain.ProviderConfig{
			IssuerURL:    srv.URL,
			ClientID:     "client-abc",
			RedirectURIs: []string{redirect},
			Scopes:       []string{"openid", "email"},
		},
	}
	svc := NewOIDCLoginService(lifecycle.NewStartupReport(), OIDCLoginServiceDeps{
		Providers: providers,
		Discovery: discovery,
		States:    states,
		Cipher:    fakeSecretCipher{},
	}, OIDCLoginServiceOptions{})
	return &loginHarness{svc: svc, providers: providers, states: states, pid: pid, redirect: redirect, srv: srv}
}

func mustParseQuery(t *testing.T, rawURL string) url.Values {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse authorize URL %q: %v", rawURL, err)
	}
	return u.Query()
}

// (crypto-random + distinct) Two initiations produce distinct state + nonce,
// and the authorize URL carries state/nonce/code_challenge + S256 + openid.
func TestOIDCLogin_AuthorizeURLParamsAndDistinctPerRequest(t *testing.T) {
	h := newOIDCLoginHarness(t, validDiscovery)

	u1, err := h.svc.InitiateLogin(context.Background(), h.pid, "")
	if err != nil {
		t.Fatalf("initiate 1: %v", err)
	}
	u2, err := h.svc.InitiateLogin(context.Background(), h.pid, "")
	if err != nil {
		t.Fatalf("initiate 2: %v", err)
	}

	q1 := mustParseQuery(t, u1)
	q2 := mustParseQuery(t, u2)

	if q1.Get("response_type") != "code" {
		t.Errorf("response_type = %q, want code", q1.Get("response_type"))
	}
	if q1.Get("client_id") != "client-abc" {
		t.Errorf("client_id = %q", q1.Get("client_id"))
	}
	if q1.Get("redirect_uri") != h.redirect {
		t.Errorf("redirect_uri = %q, want configured %q", q1.Get("redirect_uri"), h.redirect)
	}
	if !strings.Contains(q1.Get("scope"), "openid") {
		t.Errorf("scope = %q, must contain openid", q1.Get("scope"))
	}
	if q1.Get("code_challenge_method") != "S256" {
		t.Errorf("code_challenge_method = %q, want S256", q1.Get("code_challenge_method"))
	}
	for _, k := range []string{"state", "nonce", "code_challenge"} {
		if q1.Get(k) == "" {
			t.Errorf("authorize URL missing %s", k)
		}
	}
	// Distinct per request.
	if q1.Get("state") == q2.Get("state") {
		t.Error("state repeated across requests — not crypto-random")
	}
	if q1.Get("nonce") == q2.Get("nonce") {
		t.Error("nonce repeated across requests — not crypto-random")
	}
	if q1.Get("code_challenge") == q2.Get("code_challenge") {
		t.Error("code_challenge repeated across requests")
	}
	if len(h.states.byState) != 2 {
		t.Errorf("persisted states = %d, want 2", len(h.states.byState))
	}
}

// (PKCE encrypted) The stored PKCE verifier is ciphertext (never plaintext),
// decrypts to a verifier whose S256 hash equals the authorize URL's
// code_challenge, and the verifier plaintext never appears in the URL.
func TestOIDCLogin_PKCEVerifierPersistedEncrypted(t *testing.T) {
	h := newOIDCLoginHarness(t, validDiscovery)
	authURL, err := h.svc.InitiateLogin(context.Background(), h.pid, "")
	if err != nil {
		t.Fatalf("initiate: %v", err)
	}
	if len(h.states.byState) != 1 {
		t.Fatalf("want 1 state, got %d", len(h.states.byState))
	}
	var st *domain.OIDCState
	for _, v := range h.states.byState {
		st = v
	}
	if st.PKCEVerifierEncrypted == "" || !strings.HasPrefix(st.PKCEVerifierEncrypted, "fakeenc:") {
		t.Fatalf("PKCE verifier not encrypted at rest: %q", st.PKCEVerifierEncrypted)
	}
	verifier, err := (fakeSecretCipher{}).Decrypt(st.PKCEVerifierEncrypted)
	if err != nil || verifier == "" {
		t.Fatalf("decrypt verifier: %q err=%v", verifier, err)
	}
	// The stored ciphertext must not equal the plaintext, and the plaintext
	// verifier must NOT appear in the authorize URL.
	if strings.Contains(authURL, verifier) {
		t.Errorf("authorize URL leaked the PKCE verifier plaintext")
	}
	// code_challenge == BASE64URL(SHA256(verifier)).
	sum := sha256.Sum256([]byte(verifier))
	wantChallenge := base64.RawURLEncoding.EncodeToString(sum[:])
	if got := mustParseQuery(t, authURL).Get("code_challenge"); got != wantChallenge {
		t.Errorf("code_challenge = %q, want S256(verifier) = %q", got, wantChallenge)
	}
}

// (open-redirect defense) An off-site / protocol-relative return_to is replaced
// with "/"; a same-site relative path is preserved.
func TestOIDCLogin_ReturnURLSanitized(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"", "/"},
		{"/dashboard?tab=1", "/dashboard?tab=1"},
		{"https://evil.example/steal", "/"},
		{"//evil.example", "/"},
		{"/\\evil", "/"},
		{"javascript:alert(1)", "/"},
	}
	for _, tc := range cases {
		h := newOIDCLoginHarness(t, validDiscovery)
		if _, err := h.svc.InitiateLogin(context.Background(), h.pid, tc.in); err != nil {
			t.Fatalf("initiate (%q): %v", tc.in, err)
		}
		var st *domain.OIDCState
		for _, v := range h.states.byState {
			st = v
		}
		if st.ReturnURL != tc.want {
			t.Errorf("return_to %q → stored %q, want %q", tc.in, st.ReturnURL, tc.want)
		}
	}
}

// (abort paths leave no state) unknown / non-oidc / inactive provider → 404
// sentinel; discovery failure → discovery sentinel; persist failure → persist
// sentinel. In every case, NO OIDCState row is written.
func TestOIDCLogin_AbortPathsLeaveNoState(t *testing.T) {
	t.Run("unknown provider", func(t *testing.T) {
		h := newOIDCLoginHarness(t, validDiscovery)
		_, err := h.svc.InitiateLogin(context.Background(), uuid.New(), "")
		if !errors.Is(err, ErrLoginProviderNotFound) {
			t.Errorf("err = %v, want ErrLoginProviderNotFound", err)
		}
		if len(h.states.byState) != 0 {
			t.Errorf("state persisted on abort: %d", len(h.states.byState))
		}
	})
	t.Run("non-oidc provider", func(t *testing.T) {
		h := newOIDCLoginHarness(t, validDiscovery)
		h.providers.byID[h.pid].Type = domain.IDPTypeLDAP
		_, err := h.svc.InitiateLogin(context.Background(), h.pid, "")
		if !errors.Is(err, ErrLoginProviderNotFound) {
			t.Errorf("err = %v, want ErrLoginProviderNotFound", err)
		}
		if len(h.states.byState) != 0 {
			t.Errorf("state persisted for ldap: %d", len(h.states.byState))
		}
	})
	t.Run("inactive provider", func(t *testing.T) {
		h := newOIDCLoginHarness(t, validDiscovery)
		h.providers.byID[h.pid].Active = false
		_, err := h.svc.InitiateLogin(context.Background(), h.pid, "")
		if !errors.Is(err, ErrLoginProviderNotFound) {
			t.Errorf("err = %v, want ErrLoginProviderNotFound", err)
		}
		if len(h.states.byState) != 0 {
			t.Errorf("state persisted for inactive: %d", len(h.states.byState))
		}
	})
	t.Run("discovery failure no redirect", func(t *testing.T) {
		h := newOIDCLoginHarness(t, func(string) string { return "{ not json" })
		_, err := h.svc.InitiateLogin(context.Background(), h.pid, "")
		if !errors.Is(err, ErrLoginDiscoveryFailed) {
			t.Errorf("err = %v, want ErrLoginDiscoveryFailed", err)
		}
		if len(h.states.byState) != 0 {
			t.Errorf("state persisted on discovery failure: %d", len(h.states.byState))
		}
	})
	t.Run("persist failure", func(t *testing.T) {
		h := newOIDCLoginHarness(t, validDiscovery)
		h.states.createErr = errors.New("db down")
		_, err := h.svc.InitiateLogin(context.Background(), h.pid, "")
		if !errors.Is(err, ErrLoginStatePersist) {
			t.Errorf("err = %v, want ErrLoginStatePersist", err)
		}
		if len(h.states.byState) != 0 {
			t.Errorf("state left behind on persist failure: %d", len(h.states.byState))
		}
	})
}
