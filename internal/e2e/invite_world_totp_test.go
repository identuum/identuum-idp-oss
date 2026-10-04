//go:build integration

package e2e

import (
	"time"

	localcrypto "github.com/identuum/identuum-idp-oss/internal/crypto"
	"github.com/identuum/identuum-idp-oss/internal/repository"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// enrollTOTP gives the named seeded user a real TOTP enrolment — a known
// base32 secret sealed under the engine's own key, as the enrolment endpoint
// stores it — and returns the code generator for it. code(0) is the code for
// the current 30-second step, code(1) the next: the engine accepts a ±1 step
// window and burns each step it accepts (replay guard), so a test that needs
// several proofs asks for successive steps, never the same one twice.
func (w *inviteWorld) enrollTOTP(name string) (code func(stepsAhead int) string) {
	w.t.Helper()
	const secret = "JBSWY3DPEHPK3PXP" // RFC 6238 test secret, never a real one
	cs, err := localcrypto.NewCryptoService(inviteEncryptionKey)
	if err != nil {
		w.t.Fatalf("crypto service: %v", err)
	}
	sealed, err := cs.Encrypt(secret)
	if err != nil {
		w.t.Fatalf("seal TOTP secret: %v", err)
	}
	u, err := w.repos.User.GetByID(w.ctx, w.ids[name])
	if err != nil || u == nil {
		w.t.Fatalf("load %s: %v", name, err)
	}
	enabled := true
	if _, err := w.repos.User.Update(w.ctx, u.ID, u.OrganizationID, repository.UpdateUserOptions{MFAEnabled: &enabled, MFASecret: &sealed}); err != nil {
		w.t.Fatalf("enrol %s: %v", name, err)
	}
	return func(stepsAhead int) string {
		w.t.Helper()
		step := uint64(time.Now().Unix())/uint64(service.TOTPPeriodSeconds) + uint64(stepsAhead)
		return computeTOTPCodeForTest(w.t, secret, step)
	}
}
