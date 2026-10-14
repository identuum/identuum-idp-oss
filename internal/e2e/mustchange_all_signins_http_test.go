//go:build integration

// Package e2e — OSS-0914-MUSTCHANGE: an administrator's requested password
// change (D-017) and the 24-hour expiry of an administrator-set password (G2)
// hold for every way a member signs in, not only password sign-in. Until
// v0.9.14 a passkey sign-in and an upstream-provider sign-in issued a full
// session without asking for the new password (KNOWN_ISSUES v0.9.13).
//
// Through the whole OSS engine (runtime.New + Start on the test database):
// the passkey ceremony is a software P-256 authenticator whose credential row
// is seeded through the credential store, the upstream provider is the
// loopback provider of upstream_console_session_http_test.go. Passwords,
// tokens, handles and cookie values are never printed.
package e2e

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/postgres"
)

// mcIssuer is the engine's issuer for the passkey ceremony: a hostname, so it
// can be the relying party ID, and the origin the software authenticator signs.
const mcIssuer = "http://idp.invite.test"

// softPasskey is a software authenticator holding one P-256 credential.
type softPasskey struct {
	priv   *ecdsa.PrivateKey
	credID []byte
	count  uint32
}

// mcSeedPasskey stores a passkey for the user through the credential store, as
// a finished registration would (attestation none).
func (w *inviteWorld) mcSeedPasskey(userID string) *softPasskey {
	w.t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		w.t.Fatal(err)
	}
	pub, err := priv.PublicKey.ECDH()
	if err != nil {
		w.t.Fatal(err)
	}
	pt := pub.Bytes() // 0x04 || X || Y
	// COSE_Key, EC2 / ES256 / P-256: {1: 2, 3: -7, -1: 1, -2: X, -3: Y}.
	cose := append([]byte{0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20}, pt[1:33]...)
	cose = append(append(cose, 0x22, 0x58, 0x20), pt[33:65]...)
	k := &softPasskey{priv: priv, credID: []byte(uuid.NewString())}
	uid := uuid.MustParse(userID)
	var org uuid.UUID
	if err := w.pool.QueryRow(w.ctx, `SELECT organization_id FROM users WHERE id = $1`, uid).Scan(&org); err != nil {
		w.t.Fatalf("read the user's organization: %v", err)
	}
	if _, err := postgres.NewPgxWebAuthnCredentialRepository(w.pool).Create(w.ctx, &domain.WebAuthnCredential{
		UserID: uid, OrganizationID: org, CredentialID: k.credID, PublicKey: cose, AttestationType: "none",
	}); err != nil {
		w.t.Fatalf("seed the passkey: %v", err)
	}
	return k
}

// mcPasskeySignIn runs begin → assertion (user present and verified) → finish
// for email and returns the finish answer.
func (w *inviteWorld) mcPasskeySignIn(email string, k *softPasskey) (*http.Response, map[string]any) {
	w.t.Helper()
	st, m, _ := w.call("", http.MethodPost, "/api/v1/auth/login/webauthn/begin", `{"email":"`+email+`"}`)
	sid, _ := m["session_id"].(string)
	opts, _ := m["publicKey"].(map[string]any)
	challenge, _ := opts["challenge"].(string)
	rpID, _ := opts["rpId"].(string)
	if st != http.StatusOK || sid == "" || challenge == "" || rpID == "" {
		w.t.Fatalf("passkey begin = %d; want 200 with a handle, a challenge and the relying party", st)
	}
	clientData, _ := json.Marshal(map[string]any{"type": "webauthn.get", "challenge": challenge, "origin": mcIssuer, "crossOrigin": false})
	rpHash := sha256.Sum256([]byte(rpID))
	k.count++
	authData := append(rpHash[:], 0x05) // user present + user verified
	authData = binary.BigEndian.AppendUint32(authData, k.count)
	cdHash := sha256.Sum256(clientData)
	digest := sha256.Sum256(append(append([]byte{}, authData...), cdHash[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, k.priv, digest[:])
	if err != nil {
		w.t.Fatal(err)
	}
	b64 := base64.RawURLEncoding.EncodeToString
	body, _ := json.Marshal(map[string]any{
		"id": b64(k.credID), "rawId": b64(k.credID), "type": "public-key",
		"response": map[string]any{"clientDataJSON": b64(clientData), "authenticatorData": b64(authData), "signature": b64(sig)},
	})
	req, _ := http.NewRequest(http.MethodPost, w.base+"/api/v1/auth/login/webauthn/finish?session_id="+url.QueryEscape(sid), strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		w.t.Fatalf("passkey finish: %v", err)
	}
	raw, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return res, out
}

// mcLiveSessions counts the user's sessions that are not revoked.
func (w *inviteWorld) mcLiveSessions(userID string) int {
	w.t.Helper()
	var n int
	if err := w.pool.QueryRow(w.ctx, `SELECT count(*) FROM sessions WHERE user_id = $1 AND revoked_at IS NULL`, userID).Scan(&n); err != nil {
		w.t.Fatalf("count sessions: %v", err)
	}
	return n
}

// mcNoCredential reports what a refused sign-in must not carry: a console
// cookie or a refresh token.
func mcNoCredential(t *testing.T, label string, res *http.Response, body map[string]any) {
	t.Helper()
	for _, name := range []string{"access_token", "refresh_token", browserSessionCookieName} {
		if cookieNamed(res.Cookies(), name) != nil {
			t.Errorf("%s set the %s cookie; want none before the member chooses a password", label, name)
		}
	}
	if v, _ := body["refresh_token"].(string); v != "" {
		t.Errorf("%s answered a refresh token; want none", label)
	}
}

// RULE: MUSTCHANGE-ALL-SIGNINS-PGX-1
func TestE2E_OSS_EverySignInMeetsTheRequiredPasswordChange(t *testing.T) {
	t.Run("passkey", mcPasskeySignIns)
	t.Run("upstream", mcUpstreamSignIns)
}

func mcPasskeySignIns(t *testing.T) {
	w := startInviteEngine(t, map[string]string{"UI": inviteUIBase, "ISSUER": mcIssuer, "IDENTUUM_IDP_UI_PUBLIC_BASE_URL": inviteUIBase, "IDENTUUM_IDP_RATE_LIMIT_LOGIN_REQUESTS": "1000"})

	// ── 1. an expired administrator-set password: refused, no change step ──
	id2, email2 := w.createWithPassword("")
	key2 := w.mcSeedPasskey(id2)
	w.g2Backdate(id2, "24 hours 1 second")
	res, m := w.mcPasskeySignIn(email2, key2)
	if res.StatusCode != http.StatusUnauthorized || m["error"] != "password_expired" || !strings.Contains(strings.ToLower(g2Str(m["message"])), "expired") || m["session_id"] != nil {
		t.Errorf("passkey sign-in with an expired admin-set password = %d %v; want 401 password_expired with its message and no handle", res.StatusCode, m["error"])
	}
	mcNoCredential(t, "passkey sign-in with an expired admin-set password", res, m)
	if n := w.mcLiveSessions(id2); n != 0 {
		t.Errorf("passkey sign-in with an expired password left %d live sessions; want 0", n)
	}
	if row := w.auditRow("user_session.login.password_expired", id2); row == nil || row["method"] != "passkey" {
		t.Errorf("audit row for the expiry = %v; want one naming the user with method passkey", row)
	}

	// ── 2. a pending change request: the change step, as password sign-in ──
	id, email := w.createWithPassword("")
	key := w.mcSeedPasskey(id)
	res, m = w.mcPasskeySignIn(email, key)
	handle, _ := m["session_id"].(string)
	if res.StatusCode != http.StatusUnauthorized || m["error"] != "password_change_required" || m["password_change_required"] != true || handle == "" {
		t.Fatalf("passkey sign-in with a pending change = %d %v; want 401 password_change_required with a session_id, as password sign-in answers", res.StatusCode, m["error"])
	}
	mcNoCredential(t, "passkey sign-in with a pending change", res, m)
	if n := w.mcLiveSessions(id); n != 0 {
		t.Errorf("passkey sign-in with a pending change left %d live sessions; want 0", n)
	}
	if row := w.auditRow("user_session.login.password_change_required", id); row == nil || row["method"] != "passkey" {
		t.Errorf("audit row for the change requirement = %v; want one naming the user with method passkey", row)
	}
	// The member chooses a password through the same change step, and the
	// next passkey sign-in is a full sign-in.
	if st, cm, _ := w.call("", http.MethodPost, "/api/v1/auth/login/password-change", `{"session_id":"`+handle+`","new_password":"`+g2Chosen+`"}`); st != http.StatusOK {
		t.Fatalf("change step after the passkey sign-in = %d %v; want 200", st, cm["error"])
	}
	if res, m := w.mcPasskeySignIn(email, key); res.StatusCode != http.StatusOK || m["session_id"] == nil {
		t.Errorf("passkey sign-in after the change = %d %v; want 200 with a session", res.StatusCode, m["error"])
	}

	// ── 3. a lasting administrator-set password: unchanged ─────────────────
	id3, email3 := w.createWithPassword(`,"must_change_password":false`)
	if res, m := w.mcPasskeySignIn(email3, w.mcSeedPasskey(id3)); res.StatusCode != http.StatusOK || m["session_id"] == nil {
		t.Errorf("passkey sign-in with a lasting admin-set password = %d %v; want 200 (unchanged)", res.StatusCode, m["error"])
	}
}

func mcUpstreamSignIns(t *testing.T) {
	const clientID = "mustchange-upstream-client"
	prov := newUpstreamProvider(t, clientID)
	w := startInviteEngine(t, map[string]string{"UI": inviteUIBase, "IDENTUUM_IDP_RATE_LIMIT_LOGIN_REQUESTS": "1000",
		"IDENTUUM_IDP_TEST_ALLOW_PRIVATE_UPSTREAM_ISSUER": "true"})
	if _, err := w.pool.Exec(w.ctx, `UPDATE organizations SET auth_policy = 'mixed' WHERE id = $1`, w.orgA.ID); err != nil {
		t.Fatalf("set auth_policy mixed: %v", err)
	}
	// createWithPassword's addresses are @example.invalid in organization A.
	st, m, _ := w.call(w.bearers["adminA"], http.MethodPost, "/api/v1/organizations/"+w.orgA.ID.String()+"/identity-provider",
		`{"type":"oidc","name":"Loopback provider","slug":"mc-`+uuid.NewString()[:8]+`","config":{"issuer_url":"`+prov.srv.URL+`","client_id":"`+clientID+`","client_secret":"not-a-secret-fixture-value","scopes":["openid","email","profile"],"email_domains":["example.invalid"]}}`)
	idp, _ := m["identity_provider"].(map[string]any)
	pid, _ := idp["id"].(string)
	if st != http.StatusCreated || pid == "" {
		t.Fatalf("register the provider = %d %v; want 201 with the provider", st, m)
	}
	linked := func(id string) (ext bool, source string) {
		t.Helper()
		if err := w.pool.QueryRow(w.ctx, `SELECT external_id IS NOT NULL, COALESCE(auth_source, '') FROM users WHERE id = $1`, id).Scan(&ext, &source); err != nil {
			t.Fatalf("read the user's link: %v", err)
		}
		return ext, source
	}
	refusedTo := func(label string, cb *http.Response, reason string) {
		t.Helper()
		if want := "/login?reason=" + reason; cb.StatusCode != http.StatusFound || cb.Header.Get("Location") != want {
			t.Errorf("%s = %d to %q; want 302 to %s", label, cb.StatusCode, cb.Header.Get("Location"), want)
		}
		if n := len(cb.Cookies()); n != 0 {
			t.Errorf("%s set %d cookies; want none", label, n)
		}
	}

	// ── 1. an expired administrator-set password: refused ─────────────────
	id2, email2 := w.createWithPassword("")
	w.g2Backdate(id2, "24 hours 1 second")
	prov.signIn(email2)
	refusedTo("provider sign-in with an expired admin-set password", upstreamSignIn(t, newConsoleClient(t, w.base), pid), "password_expired")
	if n := w.mcLiveSessions(id2); n != 0 {
		t.Errorf("the refused provider sign-in left %d live sessions; want 0", n)
	}
	if row := w.auditRow("user_session.login.password_expired", id2); row == nil || row["method"] != "oidc_upstream" {
		t.Errorf("audit row for the expiry = %v; want one naming the user with method oidc_upstream", row)
	}

	// ── 2. a pending change request: refused before any session or link ────
	id, email := w.createWithPassword("")
	prov.signIn(email)
	refusedTo("console sign-in through the provider with a pending change", upstreamSignIn(t, newConsoleClient(t, w.base), pid), "password_change_required")
	if n := w.mcLiveSessions(id); n != 0 {
		t.Errorf("the refused provider sign-in left %d live sessions; want 0", n)
	}
	if ext, source := linked(id); ext || source != string(domain.AuthSourceLocal) {
		t.Errorf("the refused provider sign-in linked the account (external_id %v, auth_source %q); want it unlinked and local", ext, source)
	}
	if row := w.auditRow("user_session.login.password_change_required", id); row == nil || row["method"] != "oidc_upstream" || row["provider_id"] != pid {
		t.Errorf("audit row for the change requirement = %v; want one naming the user, method oidc_upstream and the provider", row)
	}

	// A sign-in started for an application is refused the same way (D-023:
	// it would have set the browser-session cookie).
	st, m, raw := w.call(w.bearers["adminA"], http.MethodPost, "/api/v1/clients", `{"name":"mustchange-app","redirect_uris":["https://rp.example.test/cb"],"scope":"openid"}`)
	var app struct {
		Client struct {
			ClientID string `json:"client_id"`
		} `json:"client"`
	}
	_ = json.Unmarshal([]byte(raw), &app)
	if st != http.StatusCreated || app.Client.ClientID == "" {
		t.Fatalf("register an application = %d %v; want 201 with a client_id", st, m)
	}
	authorizeURL := "/api/v1/oauth/authorize?" + url.Values{"response_type": {"code"}, "client_id": {app.Client.ClientID}, "redirect_uri": {"https://rp.example.test/cb"}, "scope": {"openid"},
		"state": {"s-" + uuid.NewString()[:8]}, "code_challenge": {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"}, "code_challenge_method": {"S256"}}.Encode()
	refusedTo("application sign-in through the provider with a pending change", upstreamSignInTo(t, newConsoleClient(t, w.base), pid, authorizeURL), "password_change_required")

	// The member chooses a password through password sign-in (its audit row
	// says so); the provider sign-in then lands signed in.
	pst, pm := w.g2SignIn(email, adminSetPassword)
	handle, _ := pm["session_id"].(string)
	if pst != http.StatusUnauthorized || pm["error"] != "password_change_required" || handle == "" {
		t.Fatalf("password sign-in = %d %v; want 401 password_change_required (unchanged)", pst, pm["error"])
	}
	if row := w.auditRow("user_session.login.password_change_required", id); row == nil || row["method"] != "password" {
		t.Errorf("audit row of the password sign-in = %v; want method password", row)
	}
	if st, cm, _ := w.call("", http.MethodPost, "/api/v1/auth/login/password-change", `{"session_id":"`+handle+`","new_password":"`+g2Chosen+`"}`); st != http.StatusOK {
		t.Fatalf("change step = %d %v; want 200", st, cm["error"])
	}
	if cb := upstreamSignIn(t, newConsoleClient(t, w.base), pid); cb.StatusCode != http.StatusFound || cb.Header.Get("Location") != "/" || cookieNamed(cb.Cookies(), "access_token") == nil {
		t.Errorf("provider sign-in after the change = %d to %q; want 302 to / with the console cookies", cb.StatusCode, cb.Header.Get("Location"))
	}

	// ── 3. a provider-only member is never asked for a password ────────────
	jit := "provider-only-" + uuid.NewString()[:8] + "@example.invalid"
	prov.signIn(jit)
	if cb := upstreamSignIn(t, newConsoleClient(t, w.base), pid); cb.StatusCode != http.StatusFound || cb.Header.Get("Location") != "/" {
		t.Fatalf("first provider sign-in of a new member = %d to %q; want 302 to / (unchanged)", cb.StatusCode, cb.Header.Get("Location"))
	}
	// Even a stray flag on an account with no local password asks nothing.
	if _, err := w.pool.Exec(w.ctx, `UPDATE users SET requires_password_change = true, admin_password_set_at = NOW() - interval '25 hours' WHERE email = $1`, jit); err != nil {
		t.Fatalf("flag the provider-only member: %v", err)
	}
	if cb := upstreamSignIn(t, newConsoleClient(t, w.base), pid); cb.StatusCode != http.StatusFound || cb.Header.Get("Location") != "/" {
		t.Errorf("provider sign-in of a provider-only member = %d to %q; want 302 to / (never asked for a password)", cb.StatusCode, cb.Header.Get("Location"))
	}
}
