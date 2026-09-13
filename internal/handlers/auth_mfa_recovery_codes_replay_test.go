package handlers

// auth_mfa_recovery_codes_replay_test.go — the wire half of
// TOTP-SINGLE-USE-1 (THE-CODE-THAT-WORKS-TWICE): on the recovery-code
// regenerate route a replayed TOTP code is refused, and the refusal is
// byte-identical to a wrong code's — same status, same body, same audit
// (none) — so a replay never tells a caller that the code was once valid.

import (
	"net/http"
	"testing"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

func TestMFARecoveryCodesRegenerate_ReplayIsIndistinguishableFromWrongCode(t *testing.T) {
	uid := uuid.New()
	eng := newRecoveryEngine(t, &domain.Principal{UserID: uid, Role: domain.RoleOrgUser})
	seedRecoveryUser(eng, uid, true)
	code := recoveryTOTPNow(t)
	wrongCode := "000000"
	if wrongCode == code {
		wrongCode = "111111"
	}

	first := recoveryReqWithCode(t, eng, code)
	if first.Code != http.StatusOK {
		t.Fatalf("PREMISE: the first presentation must succeed: status = %d body = %s", first.Code, first.Body.String())
	}
	updatesAfterFirst := eng.userRepo.calls
	eventsAfterFirst := len(eng.rec.Events())

	replay := recoveryReqWithCode(t, eng, code)
	updatesAfterReplay := eng.userRepo.calls
	eventsAfterReplay := len(eng.rec.Events())

	wrong := recoveryReqWithCode(t, eng, wrongCode)
	updatesAfterWrong := eng.userRepo.calls
	eventsAfterWrong := len(eng.rec.Events())

	// Status and body: compared byte for byte, and both are the route
	// family's one refusal.
	if replay.Code != http.StatusUnauthorized {
		t.Fatalf("a replayed TOTP code was not refused: status = %d body = %s", replay.Code, replay.Body.String())
	}
	if replay.Code != wrong.Code || replay.Body.String() != wrong.Body.String() {
		t.Fatalf("replay and wrong code differ on the wire: replay %d %q, wrong %d %q", replay.Code, replay.Body.String(), wrong.Code, wrong.Body.String())
	}
	if want := `{"error":"invalid_code"}`; replay.Body.String() != want {
		t.Fatalf("refusal body = %q; want %s", replay.Body.String(), want)
	}
	// Audit shape: the refusal writes no row in either case, so the
	// recorder is unchanged by both — the same absence.
	if eventsAfterReplay != eventsAfterFirst || eventsAfterWrong != eventsAfterReplay {
		t.Fatalf("audit rows differ: after first %d, after replay %d, after wrong %d", eventsAfterFirst, eventsAfterReplay, eventsAfterWrong)
	}
	// Nothing was burned or replaced by either refusal.
	if updatesAfterReplay != updatesAfterFirst || updatesAfterWrong != updatesAfterFirst {
		t.Fatalf("a refusal mutated the user: updates after first %d, replay %d, wrong %d", updatesAfterFirst, updatesAfterReplay, updatesAfterWrong)
	}
	// And a fresh code — the next step, inside the verifier's window — still succeeds.
	if next := recoveryReqWithCode(t, eng, recoveryTOTPAtOffset(t, 1)); next.Code != http.StatusOK {
		t.Fatalf("a fresh code was refused after a replay: status = %d body = %s", next.Code, next.Body.String())
	}
}
