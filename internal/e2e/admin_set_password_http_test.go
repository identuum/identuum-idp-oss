//go:build integration

// Package e2e — OSS-FIN-1 (owner ruling D-017): a user created with an
// admin-set password is active and verified (the admin vouches, audited)
// and, by default, must change the password at first sign-in — on the
// console (POST /api/v1/auth/login) and at the OpenID Connect browser
// sign-in (POST /api/v1/auth/browser-login) — before any session or token.
// The creator may send must_change_password:false (audited).
//
// Passwords, tokens and handles are never printed.
package e2e

import (
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/google/uuid"
)

const (
	adminSetPassword = "Admin-Set-Pass-2026!q"
	firstOwnPassword = "Own-New-Pass-2026!w"
)

// adminSetPasswordEvent reads the newest audit row of action for the user.
func (w *inviteWorld) auditRow(action, userID string) map[string]any {
	w.t.Helper()
	var meta map[string]any
	_ = w.pool.QueryRow(w.ctx, `SELECT metadata FROM audit_events WHERE event_type = $1 AND metadata->>'user_id' = $2 ORDER BY created_at DESC LIMIT 1`, action, userID).Scan(&meta)
	return meta
}

func (w *inviteWorld) createWithPassword(body string) (string, string) {
	w.t.Helper()
	email := "admin-set-" + uuid.NewString() + "@example.invalid"
	st, m, _ := w.call(w.bearers["adminA"], http.MethodPost, "/api/v1/users", `{"email":"`+email+`","password":"`+adminSetPassword+`","role":"org_user"`+body+`}`)
	id, _ := m["id"].(string)
	if st != http.StatusCreated || id == "" {
		w.t.Fatalf("create with a password = %d; want 201 with the user", st)
	}
	return id, email
}

// browser drives the server-rendered sign-in form with a cookie jar.
type browser struct {
	t      *testing.T
	base   string
	client *http.Client
}

var hiddenField = regexp.MustCompile(`name="([a-z_]+)" value="([^"]*)"`)

func newBrowser(t *testing.T, base string) *browser {
	jar, _ := cookiejar.New(nil)
	return &browser{t: t, base: base, client: &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

// form GETs path and returns the page and its hidden fields.
func (b *browser) get(path string) (int, string, url.Values) {
	b.t.Helper()
	res, err := b.client.Get(b.base + path)
	if err != nil {
		b.t.Fatalf("GET %s: %v", path, err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(raw), hidden(string(raw))
}

func hidden(page string) url.Values {
	v := url.Values{}
	for _, m := range hiddenField.FindAllStringSubmatch(page, -1) {
		v.Set(m[1], m[2])
	}
	return v
}

func (b *browser) post(form url.Values) (int, string, string) {
	b.t.Helper()
	res, err := b.client.PostForm(b.base+"/api/v1/auth/browser-login", form)
	if err != nil {
		b.t.Fatalf("POST browser-login: %v", err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	return res.StatusCode, res.Header.Get("Location"), string(raw)
}

func (b *browser) hasSessionCookie() bool {
	u, _ := url.Parse(b.base)
	for _, c := range b.client.Jar.Cookies(u) {
		if strings.Contains(c.Name, "session") && c.Value != "" {
			return true
		}
	}
	return false
}

func TestE2E_OSS_AdminSetPasswordMustChange(t *testing.T) {
	w := startInviteEngine(t, map[string]string{"UI": inviteUIBase, "IDENTUUM_IDP_RATE_LIMIT_LOGIN_REQUESTS": "1000"})

	// ── 1. Created with a password: verified, active, must change ─────────
	id, email := w.createWithPassword("")
	var verified, mustChange, banned bool
	if err := w.pool.QueryRow(w.ctx, `SELECT email_verified, requires_password_change, banned FROM users WHERE id = $1`, id).Scan(&verified, &mustChange, &banned); err != nil {
		t.Fatalf("read the created row: %v", err)
	}
	if !verified || !mustChange || banned {
		t.Errorf("created user: email_verified %v, requires_password_change %v, banned %v; want true, true, false", verified, mustChange, banned)
	}
	if meta := w.auditRow("user.created", id); meta["password_set_by_admin"] != true || meta["must_change_password"] != true {
		t.Errorf("user.created audit = %v; want password_set_by_admin true and must_change_password true", meta)
	}

	// ── 2. Console sign-in: the change step only ────────────────────────────
	st, m, raw := w.call("", http.MethodPost, "/api/v1/auth/login", `{"email":"`+email+`","password":"`+adminSetPassword+`"}`)
	handle, _ := m["session_id"].(string)
	if st != http.StatusUnauthorized || m["error"] != "password_change_required" || m["password_change_required"] != true || handle == "" {
		t.Fatalf("console sign-in = %d %v; want 401 password_change_required with a session_id", st, m["error"])
	}
	if strings.Contains(raw, "access_token") || strings.Contains(raw, "refresh_token") {
		t.Errorf("the change step answered a token")
	}
	var sessions int
	_ = w.pool.QueryRow(w.ctx, `SELECT COUNT(*) FROM sessions WHERE user_id = $1`, id).Scan(&sessions)
	if sessions != 0 {
		t.Errorf("%d session(s) exist before the change; want 0", sessions)
	}
	change := func(h, pw string) (int, map[string]any, string) {
		return w.call("", http.MethodPost, "/api/v1/auth/login/password-change", `{"session_id":"`+h+`","new_password":"`+pw+`"}`)
	}
	if st, m, _ := change(handle, adminSetPassword); st != http.StatusBadRequest || m["error"] != "weak_password" {
		t.Errorf("change to the admin-set password = %d %v; want 400 weak_password (must differ)", st, m["error"])
	}
	if st, m, _ := change(handle, "short"); st != http.StatusBadRequest || m["error"] != "weak_password" {
		t.Errorf("change to a weak password = %d %v; want 400 weak_password", st, m["error"])
	}
	st, m, _ = change(handle, firstOwnPassword)
	if st != http.StatusOK || m["access_token"] == nil || m["session_id"] == nil {
		t.Fatalf("change to a good password = %d %v; want 200 with a session and an access token", st, m["error"])
	}
	if st, _, _ := change(handle, "Another-Pass-2026!e"); st == http.StatusOK {
		t.Errorf("the change handle worked twice")
	}
	_ = w.pool.QueryRow(w.ctx, `SELECT requires_password_change FROM users WHERE id = $1`, id).Scan(&mustChange)
	if mustChange {
		t.Errorf("requires_password_change still true after the change")
	}
	if meta := w.auditRow("user_session.login.password_changed", id); meta == nil {
		t.Errorf("no user_session.login.password_changed audit row")
	}
	if meta := w.auditRow("user_session.login.password_change_required", id); meta == nil {
		t.Errorf("no user_session.login.password_change_required audit row")
	}
	if st, _, _ := w.call("", http.MethodPost, "/api/v1/auth/login", `{"email":"`+email+`","password":"`+adminSetPassword+`"}`); st != http.StatusUnauthorized {
		t.Errorf("the admin-set password still signs in = %d", st)
	}
	if st, _, _ := w.call("", http.MethodPost, "/api/v1/auth/login", `{"email":"`+email+`","password":"`+firstOwnPassword+`"}`); st != http.StatusOK {
		t.Errorf("the new password = %d; want 200", st)
	}

	// ── 3. OIDC browser sign-in: the change step only ───────────────────────
	id2, email2 := w.createWithPassword("")
	b := newBrowser(t, w.base)
	_, _, f := b.get("/api/v1/auth/browser-login?return_to=%2Fapi%2Fv1%2Foauth%2Fauthorize%3Fx%3D1")
	f.Set("email", email2)
	f.Set("password", adminSetPassword)
	st, _, page := b.post(f)
	cf := hidden(page)
	if st != http.StatusOK || !strings.Contains(page, `name="new_password"`) || cf.Get("password_change_session") == "" {
		t.Fatalf("browser sign-in = %d; want 200 with the change-password form", st)
	}
	if b.hasSessionCookie() {
		t.Errorf("the browser has a session cookie before the change")
	}
	cf.Set("new_password", adminSetPassword)
	cf.Set("confirm_password", adminSetPassword)
	st, _, page = b.post(cf)
	if st != http.StatusOK || !strings.Contains(page, `name="new_password"`) || !strings.Contains(page, `data-error="weak_password"`) || b.hasSessionCookie() {
		t.Errorf("browser change to the admin-set password = %d; want the form again with the reason, no session", st)
	}
	cf = hidden(page)
	cf.Set("new_password", firstOwnPassword)
	cf.Set("confirm_password", firstOwnPassword)
	st, loc, _ := b.post(cf)
	if st != http.StatusSeeOther || loc != "/api/v1/oauth/authorize?x=1" || !b.hasSessionCookie() {
		t.Errorf("browser change = %d to %q (cookie %v); want 303 to return_to with the session cookie", st, loc, b.hasSessionCookie())
	}
	_ = w.pool.QueryRow(w.ctx, `SELECT requires_password_change FROM users WHERE id = $1`, id2).Scan(&mustChange)
	if mustChange {
		t.Errorf("requires_password_change still true after the browser change")
	}

	// ── 4. must_change_password:false (audited) ─────────────────────────────
	id3, email3 := w.createWithPassword(`,"must_change_password":false`)
	if meta := w.auditRow("user.created", id3); meta["must_change_password"] != false || meta["password_set_by_admin"] != true {
		t.Errorf("user.created audit = %v; want must_change_password false, password_set_by_admin true", meta)
	}
	if st, m, _ := w.call("", http.MethodPost, "/api/v1/auth/login", `{"email":"`+email3+`","password":"`+adminSetPassword+`"}`); st != http.StatusOK || m["access_token"] == nil {
		t.Errorf("sign-in with must_change_password false = %d %v; want 200 with a token", st, m["error"])
	}

	// ── 5. Organization policy requires MFA: change first, then enrol ──────
	if _, err := w.pool.Exec(w.ctx, `UPDATE organizations SET mfa_policy = 'required' WHERE id = $1`, w.orgA.ID); err != nil {
		t.Fatalf("require MFA in the organization: %v", err)
	}
	id4, email4 := w.createWithPassword("")
	st, m, _ = w.call("", http.MethodPost, "/api/v1/auth/login", `{"email":"`+email4+`","password":"`+adminSetPassword+`"}`)
	h4, _ := m["session_id"].(string)
	if st != http.StatusUnauthorized || m["error"] != "password_change_required" || h4 == "" {
		t.Fatalf("sign-in under an MFA policy = %d %v; want the change step first", st, m["error"])
	}
	st, m, raw = change(h4, firstOwnPassword)
	if st != http.StatusUnauthorized || m["error"] != "mfa_enrollment_required" || m["session_id"] == nil || m["session_id"] == h4 {
		t.Errorf("change under an MFA policy = %d %v; want 401 mfa_enrollment_required with a new session_id", st, m["error"])
	}
	if strings.Contains(raw, "access_token") || strings.Contains(raw, "refresh_token") {
		t.Errorf("the change under an MFA policy answered a token")
	}
	_ = w.pool.QueryRow(w.ctx, `SELECT COUNT(*) FROM sessions WHERE user_id = $1`, id4).Scan(&sessions)
	if sessions != 0 {
		t.Errorf("%d session(s) exist before MFA enrolment; want 0", sessions)
	}
}
