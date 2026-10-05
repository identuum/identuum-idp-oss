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
	"net/url"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/lifecycle"
)

// FUNC-H4 (audits/oss-functionality-2026-10-05.md): upstream OIDC per the
// guide could not work — the callback had to be configured as an undocumented
// config.redirect_uris (login start answered 404 without it), and a provider
// on the operator's own network was refused by the SSRF guard with no way to
// test the success path. The callback is now derived from the IdP's issuer,
// and the default-off test setting IDENTUUM_IDP_TEST_ALLOW_PRIVATE_UPSTREAM_ISSUER
// selects UpstreamPrivateIssuerOptions, under which the whole sign-in runs
// against a provider on loopback.

func TestOIDCLogin_NoRedirectURIsUsesTheDerivedCallback(t *testing.T) {
	srv, _ := discoveryStub(t, validDiscovery, nil)
	providers := newFakeIDPConfigRepo()
	states := newFakeOIDCStateRepo()
	pid := uuid.New()
	providers.byID[pid] = &domain.IdentityProvider{
		ID: pid, OrganizationID: uuid.New(), Type: domain.IDPTypeOIDC, Active: true,
		Config: domain.ProviderConfig{IssuerURL: srv.URL, ClientID: "client-abc"},
	}
	deps := OIDCLoginServiceDeps{
		Providers: providers, Discovery: NewOIDCDiscoveryService(OIDCDiscoveryOptions{HTTPClient: srv.Client()}),
		States: states, Cipher: fakeSecretCipher{},
	}
	svc := NewOIDCLoginService(lifecycle.NewStartupReport(), deps, OIDCLoginServiceOptions{CallbackBaseURL: "https://idp.example/"})
	loc, err := svc.InitiateLogin(context.Background(), pid, "/")
	if err != nil {
		t.Fatalf("login start without config.redirect_uris: %v; want the derived callback", err)
	}
	u, _ := url.Parse(loc)
	want := "https://idp.example/api/v1/auth/idp/" + pid.String() + "/callback"
	if got := u.Query().Get("redirect_uri"); got != want {
		t.Errorf("redirect_uri = %q; want %q (the callback the guide says to register)", got, want)
	}
	for _, st := range states.byState {
		if st.RedirectURI != want {
			t.Errorf("stored redirect_uri = %q; want %q", st.RedirectURI, want)
		}
	}
	// With no issuer to derive from, a provider without redirect_uris is still
	// not usable for login.
	bare := NewOIDCLoginService(lifecycle.NewStartupReport(), deps, OIDCLoginServiceOptions{})
	if _, err := bare.InitiateLogin(context.Background(), pid, "/"); !errors.Is(err, ErrLoginProviderNotFound) {
		t.Errorf("no issuer and no redirect_uris: err = %v; want ErrLoginProviderNotFound", err)
	}
}

// loopbackProvider is a plain-HTTP OIDC provider on 127.0.0.1 — the shape of
// an internal Keycloak under test.
type loopbackProvider struct {
	srv   *httptest.Server
	priv  ed25519.PrivateKey
	nonce string
}

func newLoopbackProvider(t *testing.T, clientID string) *loopbackProvider {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p := &loopbackProvider{priv: priv}
	mux := http.NewServeMux()
	mux.HandleFunc(wellKnownOpenIDConfigurationPath, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"issuer":%q,"authorization_endpoint":%q,"token_endpoint":%q,"jwks_uri":%q}`,
			p.srv.URL, p.srv.URL+"/authorize", p.srv.URL+"/token", p.srv.URL+"/jwks")
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]any{
			"kty": "OKP", "crv": "Ed25519", "x": base64.RawURLEncoding.EncodeToString(pub), "kid": "k1",
		}}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		now := time.Now()
		tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwt.MapClaims{
			"iss": p.srv.URL, "aud": clientID, "sub": "upstream-1", "nonce": p.nonce,
			"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
			"email": "bob@example.com", "email_verified": true,
		})
		tok.Header["kid"] = "k1"
		signed, _ := tok.SignedString(priv)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"id_token":%q,"token_type":"Bearer"}`, signed)
	})
	p.srv = httptest.NewServer(mux) // plain http on 127.0.0.1
	t.Cleanup(p.srv.Close)
	return p
}

func TestUpstreamOIDC_TheDefaultTransportRefusesALoopbackIssuer(t *testing.T) {
	p := newLoopbackProvider(t, "client-abc")
	if _, err := NewOIDCDiscoveryService(OIDCDiscoveryOptions{}).Discover(context.Background(), p.srv.URL); err == nil {
		t.Fatal("the default (SSRF-guarded, https-only) discovery reached a plain-http loopback issuer")
	}
	cfg := NewOIDCProviderConfigService(lifecycle.NewStartupReport(), newFakeIDPConfigRepo(), fakeSecretCipher{})
	if _, err := cfg.CreateOIDCProvider(context.Background(), OIDCProviderInput{
		OrganizationID: uuid.New(), Type: domain.IDPTypeOIDC, Name: "Internal", IssuerURL: p.srv.URL, ClientID: "client-abc",
	}); !errors.Is(err, ErrInvalidIssuerURL()) {
		t.Errorf("default config service with an http issuer: err = %v; want ErrInvalidIssuerURL", err)
	}
}

func TestUpstreamOIDC_TheTestSettingRunsTheSignInAgainstALoopbackProvider(t *testing.T) {
	const clientID = "client-abc"
	ctx := context.Background()
	p := newLoopbackProvider(t, clientID)
	orgID := uuid.New()
	providers := newFakeIDPConfigRepo()
	states := newFakeOIDCStateRepo()
	discoveryOpts, callbackOpts := UpstreamPrivateIssuerOptions(5 * time.Second)
	discovery := NewOIDCDiscoveryService(discoveryOpts)

	// The guide's provider: no redirect_uris, the issuer on the operator's network.
	cfg := NewOIDCProviderConfigService(lifecycle.NewStartupReport(), providers, fakeSecretCipher{}).WithPlainHTTPIssuers()
	provider, err := cfg.CreateOIDCProvider(ctx, OIDCProviderInput{
		OrganizationID: orgID, Type: domain.IDPTypeOIDC, Name: "Internal", IssuerURL: p.srv.URL, ClientID: clientID,
		ClientSecret: "s", Scopes: []string{"openid", "email"}, EmailDomains: []string{"example.com"},
	})
	if err != nil {
		t.Fatalf("create the provider: %v", err)
	}
	login := NewOIDCLoginService(lifecycle.NewStartupReport(), OIDCLoginServiceDeps{
		Providers: providers, Discovery: discovery, States: states, Cipher: fakeSecretCipher{},
	}, OIDCLoginServiceOptions{CallbackBaseURL: "https://idp.example"})
	loc, err := login.InitiateLogin(ctx, provider.ID, "/dashboard")
	if err != nil {
		t.Fatalf("login start: %v", err)
	}
	authz, _ := url.Parse(loc)
	q := authz.Query()
	p.nonce = q.Get("nonce")

	sessions := NewUserSessionService(nil, newSessionRepo(), UserSessionServiceOptions{DefaultTTL: time.Hour})
	callback := NewOIDCCallbackService(lifecycle.NewStartupReport(), OIDCCallbackServiceDeps{
		Providers: providers, Discovery: discovery, States: states, Cipher: fakeSecretCipher{},
		Users: newCallbackUserRepo(), Organizations: newFakeOrgRepo(&domain.Organization{ID: orgID, Active: true}), Sessions: sessions,
	}, callbackOpts)
	res, err := callback.HandleCallback(ctx, provider.ID, q.Get("state"), "code-1", "198.51.100.4", "test-agent")
	if err != nil {
		t.Fatalf("callback: %v; want a signed-in session", err)
	}
	if res.Session == nil || res.User == nil || res.User.Email != "bob@example.com" || res.ReturnURL != "/dashboard" {
		t.Errorf("callback result = %+v; want bob's session returning to /dashboard", res)
	}
}
