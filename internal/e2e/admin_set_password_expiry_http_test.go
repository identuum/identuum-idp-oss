//go:build integration

// Package e2e — G2 (owner Q-G2 (a) + Q-G2b (a)): an admin-set password that
// carries the must-change flag expires 24 hours after the admin set it.
// Password sign-in then answers 401 {"error":"password_expired","message":...};
// the sign-in change step refuses it too. A NULL time (rows from before the
// change) never expires; must_change_password:false stores no time; the
// member's chosen password clears the flag and the time.
//
// The 24 hours are simulated by moving users.admin_password_set_at back in
// SQL (no Go clock is needed at this level). Compiles today (SQL text only);
// RED on the integration leg at 495885c: the column does not exist (migration
// 0055 proposed). Reuses createWithPassword / adminSetPassword
// (admin_set_password_http_test.go) and inviteWorld. Passwords, tokens and
// handles are never printed.
package e2e

import (
	"net/http"
	"strings"
	"testing"
)

const g2Chosen = "Member-Chosen-2026!g"

func (w *inviteWorld) g2SetAt(id string) (set bool) {
	w.t.Helper()
	if err := w.pool.QueryRow(w.ctx, `SELECT admin_password_set_at IS NOT NULL FROM users WHERE id = $1`, id).Scan(&set); err != nil {
		w.t.Fatalf("read admin_password_set_at: %v", err)
	}
	return set
}

func (w *inviteWorld) g2Backdate(id, interval string) {
	w.t.Helper()
	if _, err := w.pool.Exec(w.ctx, `UPDATE users SET admin_password_set_at = NOW() - $2::interval WHERE id = $1`, id, interval); err != nil {
		w.t.Fatalf("backdate admin_password_set_at: %v", err)
	}
}

func (w *inviteWorld) g2SignIn(email, pw string) (int, map[string]any) {
	w.t.Helper()
	st, m, _ := w.call("", http.MethodPost, "/api/v1/auth/login", `{"email":"`+email+`","password":"`+pw+`"}`)
	return st, m
}

// RULE: ADMIN-SET-PASSWORD-EXPIRES-PGX-1
func TestE2E_OSS_AdminSetPasswordExpires(t *testing.T) {
	w := startInviteEngine(t, map[string]string{"UI": inviteUIBase, "IDENTUUM_IDP_RATE_LIMIT_LOGIN_REQUESTS": "1000"})

	// ── 1. create with a password: the time is stored with the flag ─────────
	id, email := w.createWithPassword("")
	if !w.g2SetAt(id) {
		t.Fatalf("create with the must-change flag stored no admin_password_set_at")
	}
	// Inside 24 h: the change step, with a handle.
	st, m := w.g2SignIn(email, adminSetPassword)
	handle, _ := m["session_id"].(string)
	if st != http.StatusUnauthorized || m["error"] != "password_change_required" || handle == "" {
		t.Fatalf("sign-in inside 24h = %d %v; want 401 password_change_required with a session_id", st, m["error"])
	}

	// ── 2. past 24 h: sign-in and the change step both refuse ──────────────
	w.g2Backdate(id, "24 hours 1 second")
	if st, m := w.g2SignIn(email, adminSetPassword); st != http.StatusUnauthorized || m["error"] != "password_expired" ||
		!strings.Contains(strings.ToLower(g2Str(m["message"])), "expired") {
		t.Errorf("sign-in past 24h = %d %v; want 401 password_expired with a message", st, m["error"])
	}
	if st, m, _ := w.call("", http.MethodPost, "/api/v1/auth/login/password-change", `{"session_id":"`+handle+`","new_password":"`+g2Chosen+`"}`); st != http.StatusUnauthorized || m["error"] != "password_expired" {
		t.Errorf("change step past 24h = %d %v; want 401 password_expired", st, m["error"])
	}

	// ── 3. NULL time (a row from before the change) never expires ─────────
	if _, err := w.pool.Exec(w.ctx, `UPDATE users SET admin_password_set_at = NULL WHERE id = $1`, id); err != nil {
		t.Fatalf("clear admin_password_set_at: %v", err)
	}
	st, m = w.g2SignIn(email, adminSetPassword)
	handle, _ = m["session_id"].(string)
	if st != http.StatusUnauthorized || m["error"] != "password_change_required" || handle == "" {
		t.Fatalf("sign-in with a NULL time = %d %v; want 401 password_change_required", st, m["error"])
	}

	// ── 4. the member's chosen password clears the flag and the time ──────
	w.g2Backdate(id, "1 hour")
	if st, m, _ := w.call("", http.MethodPost, "/api/v1/auth/login/password-change", `{"session_id":"`+handle+`","new_password":"`+g2Chosen+`"}`); st == http.StatusUnauthorized && m["error"] == "password_expired" {
		t.Fatalf("change step inside 24h refused as expired")
	}
	if w.g2SetAt(id) {
		t.Errorf("admin_password_set_at still set after the member chose a password")
	}

	// ── 5. must_change_password:false: a lasting password, no time ─────────
	id2, email2 := w.createWithPassword(`,"must_change_password":false`)
	if w.g2SetAt(id2) {
		t.Errorf("a lasting admin-set password stored admin_password_set_at")
	}
	if st, m := w.g2SignIn(email2, adminSetPassword); st != http.StatusOK {
		t.Errorf("sign-in with a lasting admin-set password = %d %v; want 200", st, m["error"])
	}
}

func g2Str(v any) string { s, _ := v.(string); return s }
