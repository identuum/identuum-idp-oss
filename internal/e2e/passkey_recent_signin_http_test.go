//go:build integration

package e2e

import (
	"net/http"
	"testing"
)

// H6 through the whole engine: starting a passkey registration needs a recent
// sign-in. The same session that may begin one right after signing in may not
// an hour later.
func TestE2E_OSS_PassKeyRegistrationNeedsARecentSignIn(t *testing.T) {
	// The passkey ceremony needs the browser origin it will run on.
	w := startInviteEngine(t, map[string]string{"UI": inviteUIBase, "ISSUER": "http://idp.invite.test", "IDENTUUM_IDP_UI_PUBLIC_BASE_URL": inviteUIBase, "IDENTUUM_IDP_RATE_LIMIT_LOGIN_REQUESTS": "1000"})
	bearer := w.bearers["userA"]

	st, m, _ := w.call(bearer, http.MethodPost, "/api/v1/webauthn/register/begin", "")
	if st != http.StatusOK {
		t.Fatalf("a fresh sign-in begins a registration = %d %v; want 200", st, m)
	}

	if _, err := w.pool.Exec(w.ctx, `UPDATE sessions SET created_at = created_at - interval '1 hour' WHERE user_id = $1`, w.ids["userA"]); err != nil {
		t.Fatalf("age the session: %v", err)
	}
	st, m, _ = w.call(bearer, http.MethodPost, "/api/v1/webauthn/register/begin", "")
	if st != http.StatusForbidden || m["error"] != "reauth_required" {
		t.Errorf("the same session an hour later = %d %v; want 403 reauth_required", st, m)
	}
}
