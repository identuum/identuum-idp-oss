//go:build integration

// Package e2e — OSS-FIN-2 (owner ruling D-018), through the whole OSS engine
// (runtime.New + Start on the test database):
//
//   - (a) RP-initiated logout without post_logout_redirect_uri answers the
//     IdP's own "You are signed out" page (200 text/html, no-store); the
//     redirect case is unchanged.
//   - (b) an org_admin marks its own organization's confidential client
//     first-party (skip_consent), audited with before and after; /authorize
//     then issues the code without the consent page and the code_issued
//     record says consent_skipped. A public client is refused (RFC 8252
//     §8.6: its identity cannot be assured, so consent is never skipped).
//   - A user created with a password before D-017 (unverified, no invite
//     token) can be invited; redeeming sets a new password and verifies.
//
// Tokens, codes, secrets and passwords are never printed.
package e2e

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

func TestE2E_OSS_OIDCFinish(t *testing.T) {
	w := startInviteEngine(t, map[string]string{"UI": inviteUIBase, "IDENTUUM_IDP_RATE_LIMIT_LOGIN_REQUESTS": "1000"})
	db := w.pool
	admin := w.bearers["adminA"]
	// D-026: turning skip_consent on needs the org_admin's current TOTP code.
	// Each accepted code burns its step, so the two proofs below use the
	// current step and the next.
	totp := w.enrollTOTP("adminA")

	// ── (a) end_session without a redirect: the signed-out page ────────────
	res, err := http.Get(w.base + "/api/v1/oidc/logout")
	if err != nil {
		t.Fatalf("logout: %v", err)
	}
	page, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusOK || !strings.HasPrefix(res.Header.Get("Content-Type"), "text/html") ||
		!strings.Contains(string(page), "You are signed out") || res.Header.Get("Cache-Control") != "no-store" ||
		!strings.Contains(res.Header.Get("Content-Security-Policy"), "script-src 'none'") || strings.Contains(string(page), "<script") {
		t.Errorf("logout without a redirect = %d %q; want 200 text/html, no-store, script-free signed-out page", res.StatusCode, res.Header.Get("Content-Type"))
	}

	// ── (b) skip_consent on the clients surface ────────────────────────────
	type created struct {
		Client struct {
			ID          string `json:"id"`
			ClientID    string `json:"client_id"`
			SkipConsent *bool  `json:"skip_consent"`
		} `json:"client"`
		Secret string `json:"client_secret"`
	}
	create := func(body string) (int, created) {
		st, _, raw := w.call(admin, http.MethodPost, "/api/v1/clients", body)
		var out created
		_ = json.Unmarshal([]byte(raw), &out)
		return st, out
	}
	const cb = "https://rp.example.test/cb"
	// D-026: no code, and a wrong code, create nothing.
	if st, m, _ := w.call(admin, http.MethodPost, "/api/v1/clients", `{"name":"no-code","redirect_uris":["`+cb+`"],"scope":"openid","skip_consent":true}`); st != http.StatusBadRequest || m["error"] != "mfa_code_required" {
		t.Errorf("skip_consent without an MFA code = %d %v; want 400 mfa_code_required", st, m)
	}
	if st, m, _ := w.call(admin, http.MethodPost, "/api/v1/clients", `{"name":"bad-code","redirect_uris":["`+cb+`"],"scope":"openid","skip_consent":true,"mfa_code":"000000"}`); st != http.StatusForbidden || m["error"] != "invalid_mfa_code" {
		t.Errorf("skip_consent with a wrong MFA code = %d %v; want 403 invalid_mfa_code", st, m)
	}
	st, fp := create(`{"name":"first-party","redirect_uris":["` + cb + `"],"scope":"openid","skip_consent":true,"mfa_code":"` + totp(0) + `"}`)
	if st != http.StatusCreated || fp.Client.SkipConsent == nil || !*fp.Client.SkipConsent || fp.Secret == "" {
		t.Fatalf("create a first-party client = %d skip_consent %v; want 201 with skip_consent true", st, fp.Client.SkipConsent)
	}
	st, tp := create(`{"name":"third-party","redirect_uris":["` + cb + `"],"scope":"openid"}`)
	if st != http.StatusCreated || tp.Client.SkipConsent == nil || *tp.Client.SkipConsent {
		t.Fatalf("create a client without skip_consent = %d skip_consent %v; want 201 with skip_consent false", st, tp.Client.SkipConsent)
	}
	// The public-client rule: refused on create and on update.
	if st, m, _ := w.call(admin, http.MethodPost, "/api/v1/clients", `{"name":"native","redirect_uris":["http://127.0.0.1/cb"],"is_public":true,"token_endpoint_auth_method":"none","skip_consent":true}`); st != http.StatusBadRequest || m["error"] != "invalid_request" {
		t.Errorf("create a public first-party client = %d %v; want 400 invalid_request", st, m)
	}
	st, pub := create(`{"name":"native-ok","redirect_uris":["http://127.0.0.1/cb"],"is_public":true,"token_endpoint_auth_method":"none"}`)
	if st != http.StatusCreated {
		t.Fatalf("create a public client = %d; want 201", st)
	}
	if st, m, _ := w.call(admin, http.MethodPut, "/api/v1/clients/"+pub.Client.ID, `{"skip_consent":true}`); st != http.StatusBadRequest || m["error"] != "invalid_request" {
		t.Errorf("mark a public client first-party = %d %v; want 400 invalid_request", st, m)
	}
	// Only the caller's own organization: another org_admin's PUT is 404.
	if st, _, _ := w.call(w.bearers["adminB"], http.MethodPut, "/api/v1/clients/"+tp.Client.ID, `{"skip_consent":true}`); st != http.StatusNotFound {
		t.Errorf("another org_admin marks the client first-party = %d; want 404", st)
	}
	// Update round trip, audited with before and after.
	// Turning it on needs the MFA code (the second proof, the next step);
	// turning it off needs none.
	if st, m, _ := w.call(admin, http.MethodPut, "/api/v1/clients/"+tp.Client.ID, `{"skip_consent":true}`); st != http.StatusBadRequest || m["error"] != "mfa_code_required" {
		t.Errorf("PUT skip_consent=true without a code = %d %v; want 400 mfa_code_required", st, m)
	}
	for _, want := range []bool{true, false} {
		body := `{"skip_consent":false}`
		if want {
			body = `{"skip_consent":true,"mfa_code":"` + totp(1) + `"}`
		}
		st, m, _ := w.call(admin, http.MethodPut, "/api/v1/clients/"+tp.Client.ID, body)
		if st != http.StatusOK || m["skip_consent"] != want {
			t.Fatalf("PUT skip_consent=%v = %d %v; want 200 with skip_consent %v", want, st, m["skip_consent"], want)
		}
	}
	var changes int
	if err := db.QueryRow(w.ctx, `SELECT count(*) FROM audit_events WHERE event_type = 'client.updated' AND metadata->>'client_id' = $1
		AND metadata ? 'skip_consent_before' AND metadata->>'skip_consent_before' <> metadata->>'skip_consent_after'`, tp.Client.ClientID).Scan(&changes); err != nil || changes != 2 {
		t.Errorf("client.updated rows carrying a skip_consent before/after change = %d (err %v); want 2", changes, err)
	}
	var proofRows int
	if err := db.QueryRow(w.ctx, `SELECT count(*) FROM audit_events WHERE event_type = 'client.updated' AND metadata->>'client_id' = $1
		AND metadata->>'skip_consent_after' = 'true' AND metadata->>'mfa_verified' = 'true'`, tp.Client.ClientID).Scan(&proofRows); err != nil || proofRows != 1 {
		t.Errorf("client.updated rows recording skip_consent on with mfa_verified = %d (err %v); want 1", proofRows, err)
	}
	if st, _, _ := w.call(admin, http.MethodPut, "/api/v1/clients/"+tp.Client.ID, `{"skip_consent":false}`); st != http.StatusOK {
		t.Fatalf("reset third-party = %d", st)
	}

	// /authorize: the first-party client gets a code with no consent page;
	// the third-party client is sent to consent.
	const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	// H2: /authorize acts for a browser session. A bearer access token alone
	// does not drive it.
	browser := w.browserSession("userA")
	authorizeAs := func(clientID string, bearer string) *url.URL {
		q := url.Values{"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {cb}, "scope": {"openid"}, "state": {"s-" + uuid.NewString()},
			"code_challenge": {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"}, "code_challenge_method": {"S256"}}
		req, _ := http.NewRequest(http.MethodGet, w.base+"/api/v1/oauth/authorize?"+q.Encode(), nil)
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		} else {
			req.AddCookie(&http.Cookie{Name: browserSessionCookieName, Value: browser})
		}
		res, err := noRedirect.Do(req)
		if err != nil {
			t.Fatalf("authorize: %v", err)
		}
		_ = res.Body.Close()
		loc, _ := url.Parse(res.Header.Get("Location"))
		if res.StatusCode != http.StatusFound || loc == nil {
			t.Fatalf("authorize %s = %d; want 302", clientID[:6], res.StatusCode)
		}
		return loc
	}
	authorize := func(clientID string) *url.URL { return authorizeAs(clientID, "") }
	if loc := authorizeAs(fp.Client.ClientID, w.bearers["userA"]); strings.HasPrefix(loc.String(), cb) || loc.Query().Get("code") != "" {
		t.Errorf("a bearer token alone minted a code at /authorize; want the sign-in page")
	}
	loc := authorize(fp.Client.ClientID)
	code := loc.Query().Get("code")
	if !strings.HasPrefix(loc.String(), cb+"?") || code == "" {
		t.Fatalf("first-party authorize went to %s%s; want the RP callback with a code", loc.Host, loc.Path)
	}
	if loc := authorize(tp.Client.ClientID); strings.HasPrefix(loc.String(), cb) || loc.Query().Get("code") != "" {
		t.Errorf("third-party authorize went to the RP callback; want the consent page")
	}
	req, _ := http.NewRequest(http.MethodPost, w.base+"/api/v1/oauth/token", strings.NewReader(url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {cb}, "code_verifier": {verifier}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(url.QueryEscape(fp.Client.ClientID), url.QueryEscape(fp.Secret))
	tres, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	var tok struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
	}
	_ = json.NewDecoder(tres.Body).Decode(&tok)
	_ = tres.Body.Close()
	if tres.StatusCode != http.StatusOK || tok.AccessToken == "" {
		t.Errorf("token exchange for the first-party code = %d; want 200 with an access token", tres.StatusCode)
	}
	// Back-channel logout: the ID token names its session by sid, and the
	// session is recorded as having been issued to this client, so ending it
	// can notify the client.
	var recordedSession string
	if err := db.QueryRow(w.ctx, `SELECT session_id::text FROM session_relying_parties WHERE client_id = $1`, fp.Client.ClientID).Scan(&recordedSession); err != nil {
		t.Errorf("session_relying_parties row for the first-party client: %v; want one", err)
	}
	if parts := strings.Split(tok.IDToken, "."); len(parts) == 3 {
		payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
		var claims struct {
			Sid string `json:"sid"`
		}
		_ = json.Unmarshal(payload, &claims)
		if claims.Sid == "" || claims.Sid != recordedSession {
			t.Errorf("id_token sid does not match the session recorded for the client (sid present: %v)", claims.Sid != "")
		}
	} else {
		t.Errorf("token response carried no id_token")
	}
	var skipped string
	if err := db.QueryRow(w.ctx, `SELECT coalesce(metadata->>'consent_skipped', '') FROM audit_events WHERE event_type = 'oauth_authorize.code_issued' AND metadata->>'client_id' = $1`, fp.Client.ClientID).Scan(&skipped); err != nil || skipped != "true" {
		t.Errorf("code_issued consent_skipped = %q (err %v); want true", skipped, err)
	}

	// ── A user created with a password before D-017 ────────────────────────
	email := "pre-d017-" + uuid.NewString() + "@example.invalid"
	old, err := w.repos.User.Create(w.ctx, &domain.User{ID: uuid.New(), OrganizationID: w.orgA.ID, Email: email,
		PasswordHash: "dm-" + uuid.NewString(), Role: domain.RoleOrgUser, AuthSource: domain.AuthSourceLocal, EmailVerified: false})
	if err != nil {
		t.Fatalf("seed a pre-D-017 user: %v", err)
	}
	st, im, _ := w.call(admin, http.MethodPost, "/api/v1/users/"+old.ID.String()+"/invite", "")
	itok, _ := im["invite_token"].(string)
	if st != http.StatusOK || itok == "" || im["email"] != email {
		t.Fatalf("invite a pre-D-017 user = %d; want 200 with an invite token", st)
	}
	if st, _, _ := w.call(w.bearers["adminB"], http.MethodPost, "/api/v1/users/"+old.ID.String()+"/invite", ""); st != http.StatusNotFound {
		t.Errorf("another org_admin invites the user = %d; want 404", st)
	}
	if st, m, _ := w.call("", http.MethodPost, "/api/v1/auth/invite", `{"token":"`+itok+`","password":"`+invitePassword+`"}`); st != http.StatusOK || m["success"] != true {
		t.Fatalf("redeem = %d %v; want 200 success", st, m)
	}
	var verified bool
	if err := db.QueryRow(w.ctx, `SELECT email_verified FROM users WHERE id = $1`, old.ID).Scan(&verified); err != nil || !verified {
		t.Errorf("after redeem verified = %v (err %v); want true", verified, err)
	}
	st, lm, _ := w.call("", http.MethodPost, "/api/v1/auth/login", `{"email":"`+email+`","password":"`+invitePassword+`"}`)
	if lm["error"] == "invalid credentials" || !(st == http.StatusOK || lm["error"] == "mfa_enrollment_required") {
		t.Errorf("sign-in after redeem = %d %v; want past the password", st, lm["error"])
	}
	if st, _, _ := w.call(admin, http.MethodPost, "/api/v1/users/"+old.ID.String()+"/invite", ""); st != http.StatusConflict {
		t.Errorf("invite the now-verified user = %d; want 409", st)
	}
	var n int
	if err := db.QueryRow(w.ctx, `SELECT count(*) FROM audit_events WHERE event_type = 'user.invite_reissued' AND metadata->>'user_id' = $1`, old.ID.String()).Scan(&n); err != nil || n != 1 {
		t.Errorf("user.invite_reissued rows for the pre-D-017 user = %d (err %v); want 1", n, err)
	}

	// ── The browser sign-in enrols TOTP after the D-017 change step ────────
	if _, err := db.Exec(w.ctx, `UPDATE organizations SET mfa_policy = 'required' WHERE id = $1`, w.orgA.ID); err != nil {
		t.Fatalf("require MFA in the organization: %v", err)
	}
	mid, memail := w.createWithPassword("")
	b := newBrowser(t, w.base)
	_, _, f := b.get("/api/v1/auth/browser-login?return_to=%2Fapi%2Fv1%2Foauth%2Fauthorize%3Fx%3D1")
	f.Set("email", memail)
	f.Set("password", adminSetPassword)
	_, _, changeForm := b.post(f)
	cf := hidden(changeForm)
	cf.Set("new_password", firstOwnPassword)
	cf.Set("confirm_password", firstOwnPassword)
	st, _, enrol := b.post(cf)
	ef := hidden(enrol)
	secret := regexp.MustCompile(`data-secret="([A-Z2-7]+)"`).FindStringSubmatch(enrol)
	if st != http.StatusOK || ef.Get("mfa_enroll_session") == "" || secret == nil || !strings.Contains(enrol, "otpauth://") || strings.Contains(enrol, "<script") || b.hasSessionCookie() {
		t.Fatalf("browser change under an MFA policy = %d; want 200 with the TOTP enrolment form (secret, otpauth link, no script, no session)", st)
	}
	ef.Set("totp_code", "000000")
	st, _, again := b.post(ef)
	if st != http.StatusOK || !strings.Contains(again, `data-error="invalid_code"`) || hidden(again).Get("mfa_enroll_session") != ef.Get("mfa_enroll_session") ||
		strings.Contains(again, "data-secret") || b.hasSessionCookie() {
		t.Errorf("a wrong enrolment code = %d; want the code form again with invalid_code, the same handle, no key, no session", st)
	}
	ef = hidden(again)
	ef.Set("totp_code", computeTOTPCodeForTest(t, secret[1], uint64(time.Now().Unix()/30)))
	st, loc2, _ := b.post(ef)
	if st != http.StatusSeeOther || loc2 != "/api/v1/oauth/authorize?x=1" || !b.hasSessionCookie() {
		t.Errorf("enrolment code = %d to %q (cookie %v); want 303 to return_to with the session cookie", st, loc2, b.hasSessionCookie())
	}
	var mfaOn bool
	var amr string
	_ = db.QueryRow(w.ctx, `SELECT mfa_enabled FROM users WHERE id = $1`, mid).Scan(&mfaOn)
	_ = db.QueryRow(w.ctx, `SELECT coalesce(amr, '') FROM sessions WHERE user_id = $1 ORDER BY created_at DESC LIMIT 1`, mid).Scan(&amr)
	if !mfaOn || !strings.Contains(amr, "otp") {
		t.Errorf("after browser enrolment mfa_enabled %v, session amr %q; want true and otp", mfaOn, amr)
	}
	if meta := w.auditRow("user_session.login.mfa_enrolled", mid); meta == nil {
		t.Errorf("no user_session.login.mfa_enrolled audit row for the browser enrolment")
	}
}

// OSS-FIN-3 item 5: a user whose organization requires MFA, who has none
// enrolled and no password change pending, enrols TOTP at the OpenID Connect
// browser sign-in (FIN-2's enrolment, without the change step first).
func TestE2E_OSS_BrowserEnrolWithoutChange(t *testing.T) {
	w := startInviteEngine(t, map[string]string{"UI": inviteUIBase, "IDENTUUM_IDP_RATE_LIMIT_LOGIN_REQUESTS": "1000"})
	if _, err := w.pool.Exec(w.ctx, `UPDATE organizations SET mfa_policy = 'required' WHERE id = $1`, w.orgA.ID); err != nil {
		t.Fatalf("require MFA in the organization: %v", err)
	}
	id, email := w.createWithPassword(`,"must_change_password":false`)
	b := newBrowser(t, w.base)
	_, _, f := b.get("/api/v1/auth/browser-login?return_to=%2Fapi%2Fv1%2Foauth%2Fauthorize%3Fx%3D1")
	f.Set("email", email)
	f.Set("password", adminSetPassword)
	st, _, enrol := b.post(f)
	ef := hidden(enrol)
	secret := regexp.MustCompile(`data-secret="([A-Z2-7]+)"`).FindStringSubmatch(enrol)
	if st != http.StatusOK || ef.Get("mfa_enroll_session") == "" || secret == nil || b.hasSessionCookie() {
		t.Fatalf("browser sign-in under an MFA policy, nothing enrolled = %d; want 200 with the TOTP enrolment form and no session", st)
	}
	ef.Set("totp_code", computeTOTPCodeForTest(t, secret[1], uint64(time.Now().Unix()/30)))
	st, loc, _ := b.post(ef)
	if st != http.StatusSeeOther || loc != "/api/v1/oauth/authorize?x=1" || !b.hasSessionCookie() {
		t.Errorf("enrolment code = %d to %q (cookie %v); want 303 to return_to with the session cookie", st, loc, b.hasSessionCookie())
	}
	var on bool
	_ = w.pool.QueryRow(w.ctx, `SELECT mfa_enabled FROM users WHERE id = $1`, id).Scan(&on)
	if !on {
		t.Errorf("mfa_enabled false after the browser enrolment")
	}
}
