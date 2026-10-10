//go:build integration

// Package e2e — OSS-UPSTREAM-CONSOLE-SESSION (test-book row V4-025; finding
// F-1 of TESTBOOK-FIXTURES-1): a sign-in through an upstream OpenID Connect
// provider lands the person in the console SIGNED IN, with the session a
// password sign-in gives — the same two cookies with the same attributes, the
// same refresh, the same logout and revocation — through the whole OSS engine
// (runtime.New + Start on the test database) against a loopback provider under
// the test setting IDENTUUM_IDP_TEST_ALLOW_PRIVATE_UPSTREAM_ISSUER, the
// approach of testbooks/fixtures (fixture a).
//
// Before the fix the callback set only the IdP's own browser-session cookie;
// the console's validate (through the /bff boundary, which lifts the
// access-token cookie into a Bearer) answered {"authenticated": false} and
// the page returned to /login.
//
// Tokens, codes, cookie values, secrets and passwords are never printed.
package e2e

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// upstreamProvider is a loopback OpenID Connect provider that signs one fixed
// person in at once (no form), as the fixtures' mock provider does.
type upstreamProvider struct {
	srv      *httptest.Server
	priv     ed25519.PrivateKey
	clientID string
	email    string
	mu       sync.Mutex
	nonces   map[string]string // code -> nonce
}

func newUpstreamProvider(t *testing.T, clientID string) *upstreamProvider {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p := &upstreamProvider{priv: priv, clientID: clientID, nonces: map[string]string{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
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
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		target, err := url.Parse(q.Get("redirect_uri"))
		if err != nil || !target.IsAbs() || q.Get("response_type") != "code" {
			http.Error(w, "bad authorize request", http.StatusBadRequest)
			return
		}
		code := uuid.NewString()
		p.mu.Lock()
		p.nonces[code] = q.Get("nonce")
		p.mu.Unlock()
		v := target.Query()
		v.Set("code", code)
		v.Set("state", q.Get("state"))
		target.RawQuery = v.Encode()
		http.Redirect(w, r, target.String(), http.StatusFound)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		p.mu.Lock()
		nonce, ok := p.nonces[r.PostForm.Get("code")]
		delete(p.nonces, r.PostForm.Get("code"))
		email := p.email
		p.mu.Unlock()
		if !ok {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":"invalid_grant"}`)
			return
		}
		now := time.Now()
		tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwt.MapClaims{
			"iss": p.srv.URL, "aud": clientID, "sub": "upstream-" + email, "nonce": nonce,
			"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
			"email": email, "email_verified": true, "name": "Upstream Person",
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

func (p *upstreamProvider) signIn(email string) {
	p.mu.Lock()
	p.email = email
	p.mu.Unlock()
}

// consoleClient is a browser: a cookie jar, no automatic redirects, and the
// console's own request headers on the /bff boundary.
type consoleClient struct {
	t      *testing.T
	base   string
	client *http.Client
}

func newConsoleClient(t *testing.T, base string) *consoleClient {
	jar, _ := cookiejar.New(nil)
	return &consoleClient{t: t, base: base, client: &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

// nav GETs an absolute URL as a top-level navigation and returns the answer
// with its body drained.
func (c *consoleClient) nav(abs string) *http.Response {
	c.t.Helper()
	res, err := c.client.Get(abs)
	if err != nil {
		c.t.Fatalf("GET: %v", err)
	}
	_, _ = io.Copy(io.Discard, res.Body)
	_ = res.Body.Close()
	return res
}

// bff calls the boundary the way the console's boot ladder does.
func (c *consoleClient) bff(method, path string) (int, map[string]any, *http.Response) {
	c.t.Helper()
	req, _ := http.NewRequest(method, c.base+path, nil)
	req.Header.Set("X-Requested-With", "identuum-ui")
	req.Header.Set("X-Identuum-Login-Step-Status", "200")
	res, err := c.client.Do(req)
	if err != nil {
		c.t.Fatalf("%s %s: %v", method, path, err)
	}
	raw, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	return res.StatusCode, m, res
}

func cookieNamed(cs []*http.Cookie, name string) *http.Cookie {
	for _, c := range cs {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// cookieShape is every attribute of a credential cookie but its value.
func cookieShape(c *http.Cookie) string {
	if c == nil {
		return "<absent>"
	}
	return fmt.Sprintf("path=%q httponly=%v samesite=%v secure=%v maxage=%d", c.Path, c.HttpOnly, c.SameSite, c.Secure, c.MaxAge)
}

// upstreamSignIn runs start → provider → callback in the client's browser and
// returns the callback's answer.
func upstreamSignIn(t *testing.T, c *consoleClient, pid string) *http.Response {
	t.Helper()
	start := c.nav(c.base + "/api/v1/auth/idp/" + pid + "/login?return_to=/")
	if start.StatusCode != http.StatusFound || start.Header.Get("Location") == "" {
		t.Fatalf("login start = %d; want 302 to the provider", start.StatusCode)
	}
	atProvider := c.nav(start.Header.Get("Location"))
	cb, err := url.Parse(atProvider.Header.Get("Location"))
	if atProvider.StatusCode != http.StatusFound || err != nil || !strings.HasSuffix(cb.Path, "/api/v1/auth/idp/"+pid+"/callback") || cb.Query().Get("code") == "" || cb.Query().Get("state") == "" {
		t.Fatalf("provider authorize = %d; want 302 back to the IdP's callback with a code and the state", atProvider.StatusCode)
	}
	// The provider was told the issuer's address; the engine under test
	// listens on an ephemeral port of the same host.
	return c.nav(c.base + cb.Path + "?" + cb.RawQuery)
}

func TestE2E_OSS_UpstreamSignInEstablishesTheConsoleSession(t *testing.T) {
	const clientID = "console-upstream-client"
	prov := newUpstreamProvider(t, clientID)
	w := startInviteEngine(t, map[string]string{"UI": inviteUIBase, "IDENTUUM_IDP_RATE_LIMIT_LOGIN_REQUESTS": "1000",
		"IDENTUUM_IDP_TEST_ALLOW_PRIVATE_UPSTREAM_ISSUER": "true"})
	db := w.pool
	// The organization admits upstream sign-ins (a local_only organization
	// refuses them at the callback, SEC-MFA F3).
	if _, err := db.Exec(w.ctx, `UPDATE organizations SET auth_policy = 'mixed' WHERE id = $1`, w.orgA.ID); err != nil {
		t.Fatalf("set auth_policy mixed: %v", err)
	}
	emailDomain := "up-" + uuid.NewString()[:8] + ".example.invalid"
	st, m, _ := w.call(w.bearers["adminA"], http.MethodPost, "/api/v1/organizations/"+w.orgA.ID.String()+"/identity-provider",
		`{"type":"oidc","name":"Loopback provider","slug":"loopback-`+uuid.NewString()[:8]+`","config":{"issuer_url":"`+prov.srv.URL+`","client_id":"`+clientID+`","client_secret":"not-a-secret-fixture-value","scopes":["openid","email","profile"],"email_domains":["`+emailDomain+`"]}}`)
	idp, _ := m["identity_provider"].(map[string]any)
	pid, _ := idp["id"].(string)
	if st != http.StatusCreated || pid == "" {
		t.Fatalf("register the provider = %d %v; want 201 with the provider", st, m)
	}
	email := "person@" + emailDomain
	prov.signIn(email)

	// ── 1. The sign-in: start → provider → callback ────────────────────────
	c := newConsoleClient(t, w.base)
	cb := upstreamSignIn(t, c, pid)
	if cb.StatusCode != http.StatusFound || cb.Header.Get("Location") != "/" {
		t.Fatalf("callback = %d to %q; want 302 to /", cb.StatusCode, cb.Header.Get("Location"))
	}
	if loc := cb.Header.Get("Location"); strings.Contains(loc, "token") || strings.Contains(loc, "#") {
		t.Errorf("the redirect target carries a token or a fragment: %q", loc)
	}
	cbCookies := cb.Cookies()
	if cookieNamed(cbCookies, browserSessionCookieName) == nil {
		t.Errorf("the callback did not set the IdP's own browser-session cookie")
	}
	access := cookieNamed(cbCookies, "access_token")
	refresh := cookieNamed(cbCookies, "refresh_token")
	if access == nil || access.Value == "" || refresh == nil || refresh.Value == "" {
		t.Errorf("the callback set access_token %v and refresh_token %v; want both, the cookies the console validates (F-1)", access != nil, refresh != nil)
	}

	// ── 2. The console's boot: validate through the boundary ───────────────
	st, body, _ := c.bff(http.MethodGet, "/bff/api/v1/validate")
	user, _ := body["user"].(map[string]any)
	if st != http.StatusOK || body["success"] != true || body["authenticated"] == false || user["email"] != email {
		t.Fatalf("console validate after the upstream sign-in = %d %v; want 200 success with the signed-in person (F-1: the page returned to /login)", st, body)
	}

	// ── 3. The same cookies a password sign-in sets, attribute for attribute ─
	pwID, pwEmail := w.createWithPassword(`,"must_change_password":false`)
	_ = pwID
	req, _ := http.NewRequest(http.MethodPost, w.base+"/api/v1/auth/login", strings.NewReader(`{"email":"`+pwEmail+`","password":"`+adminSetPassword+`","remember_me":false}`))
	req.Header.Set("Content-Type", "application/json")
	pw, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("password sign-in: %v", err)
	}
	_, _ = io.Copy(io.Discard, pw.Body)
	_ = pw.Body.Close()
	if pw.StatusCode != http.StatusOK {
		t.Fatalf("password sign-in = %d; want 200 (unchanged)", pw.StatusCode)
	}
	for _, name := range []string{"access_token", "refresh_token"} {
		if got, want := cookieShape(cookieNamed(cbCookies, name)), cookieShape(cookieNamed(pw.Cookies(), name)); got != want {
			t.Errorf("%s cookie after the upstream sign-in: %s; the password sign-in sets %s", name, got, want)
		}
	}
	if cookieNamed(pw.Cookies(), browserSessionCookieName) != nil {
		t.Errorf("the password sign-in set the browser-session cookie; want unchanged (none)")
	}

	// ── 4. Refresh after the upstream sign-in ──────────────────────────────
	st, body, res := c.bff(http.MethodPost, "/bff/session/refresh")
	if st != http.StatusNoContent || cookieNamed(res.Cookies(), "access_token") == nil {
		t.Errorf("refresh after the upstream sign-in = %d %v; want 204 with a new access_token cookie", st, body)
	}
	if st, body, _ = c.bff(http.MethodGet, "/bff/api/v1/validate"); st != http.StatusOK || body["success"] != true {
		t.Errorf("validate after the refresh = %d %v; want 200 success", st, body)
	}

	// ── 5. Audit: the upstream event names the session the console holds ───
	var sessionID string
	if err := db.QueryRow(w.ctx, `SELECT metadata->>'session_id' FROM audit_events WHERE event_type = 'auth.oidc_login.success' AND metadata->>'provider_id' = $1 ORDER BY created_at DESC LIMIT 1`, pid).Scan(&sessionID); err != nil || sessionID == "" {
		t.Fatalf("auth.oidc_login.success row for the provider: %v; want one with a session_id", err)
	}
	var sessionUser string
	if err := db.QueryRow(w.ctx, `SELECT u.email FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.id = $1`, sessionID).Scan(&sessionUser); err != nil || sessionUser != email {
		t.Errorf("the audited session belongs to %q (err %v); want %q", sessionUser, err, email)
	}

	// ── 6. Logout after the upstream sign-in: revoked, cookies cleared ─────
	st, body, res = c.bff(http.MethodPost, "/bff/session/logout")
	if st != http.StatusNoContent {
		t.Fatalf("logout after the upstream sign-in = %d %v; want 204", st, body)
	}
	for _, name := range []string{"access_token", "refresh_token"} {
		if cleared := cookieNamed(res.Cookies(), name); cleared == nil || cleared.MaxAge >= 0 {
			t.Errorf("logout did not clear the %s cookie", name)
		}
	}
	var revoked *time.Time
	if err := db.QueryRow(w.ctx, `SELECT revoked_at FROM sessions WHERE id = $1`, sessionID).Scan(&revoked); err != nil || revoked == nil {
		t.Errorf("session after logout: revoked_at %v (err %v); want revoked", revoked, err)
	}
	if st, body, _ = c.bff(http.MethodGet, "/bff/api/v1/validate"); st != http.StatusOK || body["authenticated"] != false {
		t.Errorf("validate after logout = %d %v; want 200 {\"authenticated\": false}", st, body)
	}
	var n int
	if err := db.QueryRow(w.ctx, `SELECT count(*) FROM audit_events WHERE event_type = 'user_session.logout' AND created_at > now() - interval '2 minutes'`).Scan(&n); err != nil || n < 1 {
		t.Errorf("user_session.logout rows = %d (err %v); want at least 1", n, err)
	}

	// ── 7. A refused upstream sign-in still sets nothing ───────────────────
	prov.signIn("outsider-" + uuid.NewString()[:8] + "@other.example.invalid")
	refused := upstreamSignIn(t, newConsoleClient(t, w.base), pid)
	if refused.StatusCode != http.StatusForbidden || len(refused.Cookies()) != 0 || refused.Header.Get("Location") != "" {
		t.Errorf("a sign-in outside email_domains = %d with %d cookies and Location %q; want 403, no cookie, no redirect", refused.StatusCode, len(refused.Cookies()), refused.Header.Get("Location"))
	}
}
