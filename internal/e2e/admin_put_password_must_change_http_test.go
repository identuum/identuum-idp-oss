//go:build integration

// Package e2e — Q-B2 (a), owner 2026-10-12: a password an administrator sets
// through PUT /api/v1/users/:id must be changed at the next sign-in, as D-017
// does for create, unless the admin sends must_change_password:false. A
// password the member chooses through a reset link clears the requirement.
//
// Reuses the D-017 helpers in admin_set_password_http_test.go (createWithPassword,
// auditRow) and inviteWorld (user_invite_http_test.go). Needs PostgreSQL.
// Passwords, tokens and handles are never printed.
package e2e

import (
	"net/http"
	"testing"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/crypto"
)

const (
	adminPutPassword  = "Admin-Put-Pass-2026!r"
	adminPutPassword2 = "Admin-Put-Pass-2026!s"
	memberResetChosen = "Member-Chosen-2026!t"
)

func (w *inviteWorld) mustChangeFlag(id string) bool {
	w.t.Helper()
	var v bool
	if err := w.pool.QueryRow(w.ctx, `SELECT requires_password_change FROM users WHERE id = $1`, id).Scan(&v); err != nil {
		w.t.Fatalf("read requires_password_change: %v", err)
	}
	return v
}

func (w *inviteWorld) signIn(email, pw string) (int, any) {
	w.t.Helper()
	st, m, _ := w.call("", http.MethodPost, "/api/v1/auth/login", `{"email":"`+email+`","password":"`+pw+`"}`)
	return st, m["error"]
}

func TestE2E_OSS_AdminPutPasswordMustChange(t *testing.T) {
	w := startInviteEngine(t, map[string]string{"UI": inviteUIBase, "IDENTUUM_IDP_RATE_LIMIT_LOGIN_REQUESTS": "1000"})
	id, email := w.createWithPassword(`,"must_change_password":false`)
	put := func(body string) (int, map[string]any) {
		st, m, _ := w.call(w.bearers["adminA"], http.MethodPut, "/api/v1/users/"+id, body)
		return st, m
	}

	// ── 1. PUT password: the next password sign-in is the change step ───────
	st, m := put(`{"password":"` + adminPutPassword + `"}`)
	if st != http.StatusOK || m["requires_password_change"] != true {
		t.Fatalf("PUT password = %d requires_password_change=%v; want 200 and true", st, m["requires_password_change"])
	}
	if !w.mustChangeFlag(id) {
		t.Errorf("requires_password_change is false after an admin PUT password")
	}
	if st, code := w.signIn(email, adminPutPassword); st != http.StatusUnauthorized || code != "password_change_required" {
		t.Errorf("sign-in after an admin PUT password = %d %v; want 401 password_change_required", st, code)
	}

	// ── 2. PUT without a password leaves the flag; must_change alone is 400 ─
	if st, _ := put(`{"name":"Renamed Member"}`); st != http.StatusOK || !w.mustChangeFlag(id) {
		t.Errorf("PUT name = %d, flag %v; want 200 and the flag untouched (true)", st, w.mustChangeFlag(id))
	}
	if st, _ := put(`{"must_change_password":false}`); st != http.StatusBadRequest || !w.mustChangeFlag(id) {
		t.Errorf("PUT must_change_password alone = %d, flag %v; want 400 and nothing written", st, w.mustChangeFlag(id))
	}

	// ── 3. must_change_password:false lets the admin-set password stand ────
	if st, m := put(`{"password":"` + adminPutPassword2 + `","must_change_password":false}`); st != http.StatusOK || m["requires_password_change"] != false {
		t.Errorf("PUT password + false = %d requires_password_change=%v; want 200 and false", st, m["requires_password_change"])
	}
	if st, code := w.signIn(email, adminPutPassword2); st != http.StatusOK {
		t.Errorf("sign-in with must_change_password false = %d %v; want 200", st, code)
	}

	// ── 4. A reset the member completes clears the requirement ─────────────
	if st, _ := put(`{"password":"` + adminPutPassword + `"}`); st != http.StatusOK || !w.mustChangeFlag(id) {
		t.Fatalf("re-arm the flag: PUT = %d flag %v", st, w.mustChangeFlag(id))
	}
	raw := "e2e-reset-" + uuid.NewString()
	if _, err := w.pool.Exec(w.ctx, `INSERT INTO password_resets (user_id, token_hash, expires_at, created_at) VALUES ($1, $2, NOW() + interval '1 hour', NOW())`, id, crypto.HashToken(raw)); err != nil {
		t.Fatalf("seed a reset link: %v", err)
	}
	if st, _, _ := w.call("", http.MethodPost, "/api/v1/auth/password/reset", `{"token":"`+raw+`","new_password":"`+memberResetChosen+`"}`); st != http.StatusOK {
		t.Fatalf("reset = %d; want 200", st)
	}
	if w.mustChangeFlag(id) {
		t.Errorf("requires_password_change still true after the member reset their own password")
	}
	if st, code := w.signIn(email, memberResetChosen); st != http.StatusOK {
		t.Errorf("sign-in with the password the member chose = %d %v; want 200 (no change step)", st, code)
	}
	if meta := w.auditRow("user.updated", id); meta == nil {
		t.Errorf("no user.updated audit row for the admin PUT")
	}
}
