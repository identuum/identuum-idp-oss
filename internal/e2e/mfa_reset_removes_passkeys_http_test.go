//go:build integration

package e2e

import (
	"net/http"
	"testing"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// H6 through the whole engine: an organization admin's MFA reset removes the
// user's passkeys as well as the authenticator, and only that user's.
func TestE2E_OSS_AdminMFAResetRemovesThePassKeys(t *testing.T) {
	w := startInviteEngine(t, map[string]string{"UI": inviteUIBase, "IDENTUUM_IDP_RATE_LIMIT_LOGIN_REQUESTS": "1000"})
	_ = w.enrollTOTP("userA") // userA has an authenticator to reset

	seed := func(name string) uuid.UUID {
		t.Helper()
		u, err := w.repos.User.GetByID(w.ctx, w.ids[name])
		if err != nil || u == nil {
			t.Fatalf("load %s: %v", name, err)
		}
		cred, err := w.repos.WebAuthnCredential.Create(w.ctx, &domain.WebAuthnCredential{
			UserID: u.ID, OrganizationID: u.OrganizationID, CredentialID: []byte(uuid.NewString()),
			PublicKey: []byte("fixture-public-key"), AttestationType: "none", Nickname: "fixture " + name,
		})
		if err != nil {
			t.Fatalf("seed a passkey for %s: %v", name, err)
		}
		return cred.ID
	}
	seed("userA")
	seed("adminB") // another user's passkey must survive

	count := func(name string) int {
		t.Helper()
		creds, err := w.repos.WebAuthnCredential.ListByUser(w.ctx, w.ids[name])
		if err != nil {
			t.Fatalf("list passkeys of %s: %v", name, err)
		}
		return len(creds)
	}
	if count("userA") != 1 || count("adminB") != 1 {
		t.Fatalf("premise: each user holds one passkey, got userA=%d adminB=%d", count("userA"), count("adminB"))
	}

	st, m, _ := w.call(w.bearers["adminA"], http.MethodPost, "/api/v1/users/"+w.ids["userA"].String()+"/recovery/reset-mfa", "")
	if st != http.StatusOK {
		t.Fatalf("reset MFA = %d %v; want 200", st, m)
	}
	if got := count("userA"); got != 0 {
		t.Errorf("passkeys of the reset user = %d; want 0", got)
	}
	if got := count("adminB"); got != 1 {
		t.Errorf("passkeys of another user = %d; want 1 (untouched)", got)
	}
}
