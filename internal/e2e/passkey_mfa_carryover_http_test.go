//go:build integration

// Package e2e — OSS-G8-PASSKEY-MFA-CARRYOVER (owner decision 2026-10-16): a
// passkey-only member of an organization that requires MFA, asked by an
// administrator to change the password, signs in with a user-verified passkey,
// chooses a password and is signed in. Until this slice the change step lost
// the passkey's proof and asked the member to enrol TOTP.
//
// Through the whole OSS engine on the test database, with the software
// authenticator of mustchange_all_signins_http_test.go (user present and
// verified). Passwords, handles, tokens and cookie values are never printed.
package e2e

import (
	"net/http"
	"testing"

	"github.com/identuum/identuum-idp-oss/internal/service"
)

// RULE: PASSKEY-MFA-CARRYOVER-PGX-1
func TestE2E_OSS_PasskeyProofCarriesThroughTheRequiredPasswordChange(t *testing.T) {
	w := startInviteEngine(t, map[string]string{"UI": inviteUIBase, "ISSUER": mcIssuer, "IDENTUUM_IDP_UI_PUBLIC_BASE_URL": inviteUIBase, "IDENTUUM_IDP_RATE_LIMIT_LOGIN_REQUESTS": "1000"})
	if _, err := w.pool.Exec(w.ctx, `UPDATE organizations SET mfa_policy = 'required' WHERE id = $1`, w.orgA.ID); err != nil {
		t.Fatalf("require MFA in the organization: %v", err)
	}
	pendingRow := func(handle string) (kind string, consumed bool) {
		t.Helper()
		if err := w.pool.QueryRow(w.ctx, `SELECT kind, consumed_at IS NOT NULL FROM mfa_pending_login_sessions WHERE id = $1`, handle).Scan(&kind, &consumed); err != nil {
			t.Fatalf("read the change handle: %v", err)
		}
		return kind, consumed
	}
	totpState := func(id string) (enabled bool, secret bool, codes int) {
		t.Helper()
		if err := w.pool.QueryRow(w.ctx, `SELECT mfa_enabled, mfa_secret IS NOT NULL, CASE WHEN jsonb_typeof(mfa_recovery_codes) = 'array' THEN jsonb_array_length(mfa_recovery_codes) ELSE 0 END FROM users WHERE id = $1`, id).Scan(&enabled, &secret, &codes); err != nil {
			t.Fatalf("read the member's TOTP state: %v", err)
		}
		return enabled, secret, codes
	}

	// ── 1. the passkey-only member: the change finishes the sign-in ─────────
	id, email := w.createWithPassword("")
	key := w.mcSeedPasskey(id)
	if en, sec, n := totpState(id); en || sec || n != 0 {
		t.Fatalf("fixture: member has TOTP (enabled %v, secret %v, %d codes); want none", en, sec, n)
	}
	res, m := w.mcPasskeySignIn(email, key)
	handle, _ := m["session_id"].(string)
	if res.StatusCode != http.StatusUnauthorized || m["error"] != "password_change_required" || handle == "" {
		t.Fatalf("passkey sign-in with a pending change = %d %v; want 401 password_change_required with a handle", res.StatusCode, m["error"])
	}
	mcNoCredential(t, "passkey sign-in with a pending change", res, m)
	if n := w.mcLiveSessions(id); n != 0 {
		t.Fatalf("passkey sign-in before the change left %d live sessions; want 0", n)
	}
	// The proof survives a fresh read of the store: it is the row's kind.
	if kind, consumed := pendingRow(handle); kind != "password_change_passkey_uv" || consumed {
		t.Fatalf("change handle = kind %q, consumed %v; want password_change_passkey_uv, unconsumed", kind, consumed)
	}
	st, cm, _ := w.call("", http.MethodPost, "/api/v1/auth/login/password-change", `{"session_id":"`+handle+`","new_password":"`+g2Chosen+`"}`)
	access, _ := cm["access_token"].(string)
	if st != http.StatusOK || cm["session_id"] == nil || access == "" || cm["mfa_enrollment_required"] != nil || cm["mfa_required"] != nil {
		t.Fatalf("change step after the passkey = %d %v; want 200 with a session and no MFA step", st, cm["error"])
	}
	var acr, amr string
	if err := w.pool.QueryRow(w.ctx, `SELECT acr, COALESCE(amr, '') FROM sessions WHERE user_id = $1 AND revoked_at IS NULL`, id).Scan(&acr, &amr); err != nil {
		t.Fatalf("read the session: %v", err)
	}
	if acr != service.ACRPhishingResistant || amr != "" {
		t.Errorf("session acr %q amr %q; want %q and no amr, as the direct passkey sign-in", acr, amr, service.ACRPhishingResistant)
	}
	if _, consumed := pendingRow(handle); !consumed {
		t.Errorf("the change handle is not consumed")
	}
	if en, sec, n := totpState(id); en || sec || n != 0 {
		t.Errorf("TOTP state after = enabled %v, secret %v, %d codes; want untouched (none)", en, sec, n)
	}
	if row := w.auditRow("user_session.login.success", id); row == nil || row["method"] != "passkey" {
		t.Errorf("sign-in audit row = %v; want method passkey", row)
	}
	if st, mm, _ := w.call(access, http.MethodGet, "/api/v1/me/mfa/status", ""); st != http.StatusOK {
		t.Errorf("authenticated read with the new session = %d %v; want 200", st, mm["error"])
	}
	// The handle is spent: a replay issues nothing.
	if st, rm, _ := w.call("", http.MethodPost, "/api/v1/auth/login/password-change", `{"session_id":"`+handle+`","new_password":"`+g2Chosen+`x"}`); st != http.StatusUnauthorized || rm["session_id"] != nil {
		t.Errorf("replayed change = %d %v; want 401 and no session", st, rm["error"])
	}
	if n := w.mcLiveSessions(id); n != 1 {
		t.Errorf("live sessions after the replay = %d; want 1", n)
	}

	// ── 2. control: a password sign-in of a member with a passkey ──────────
	id2, email2 := w.createWithPassword("")
	_ = w.mcSeedPasskey(id2)
	pst, pm := w.g2SignIn(email2, adminSetPassword)
	h2, _ := pm["session_id"].(string)
	if pst != http.StatusUnauthorized || pm["error"] != "password_change_required" || h2 == "" {
		t.Fatalf("password sign-in = %d %v; want 401 password_change_required", pst, pm["error"])
	}
	if kind, _ := pendingRow(h2); kind != "password_change" {
		t.Errorf("password sign-in minted kind %q; want password_change", kind)
	}
	st, cm, _ = w.call("", http.MethodPost, "/api/v1/auth/login/password-change", `{"session_id":"`+h2+`","new_password":"`+g2Chosen+`"}`)
	if st != http.StatusUnauthorized || cm["error"] != "mfa_enrollment_required" {
		t.Errorf("change step after a password sign-in = %d %v; want 401 mfa_enrollment_required (unchanged)", st, cm["error"])
	}
	if n := w.mcLiveSessions(id2); n != 0 {
		t.Errorf("password sign-in left %d live sessions; want 0 before MFA", n)
	}
}
