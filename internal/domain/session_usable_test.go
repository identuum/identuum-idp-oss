package domain

import (
	"testing"
	"time"
)

// A session is usable only when it is valid, not revoked, and not expired;
// each disqualifier is reported with a reason, and a revoked session surfaces
// its stored revocation reason.
// RULE: SESSION-USABLE-1
func TestSession_CanBeUsedGatesEveryDisqualifier(t *testing.T) {
	now := time.Now()
	future := now.Add(time.Hour)
	past := now.Add(-time.Hour)

	usable := &Session{IsValid: true, ExpiresAt: future}
	if ok, reason := usable.CanBeUsed(now); !ok || reason != "" {
		t.Fatalf("a valid, unrevoked, unexpired session must be usable: ok=%v reason=%q", ok, reason)
	}

	invalid := &Session{IsValid: false, ExpiresAt: future}
	if ok, reason := invalid.CanBeUsed(now); ok || reason == "" {
		t.Errorf("an invalid session must not be usable: ok=%v reason=%q", ok, reason)
	}

	reasonText := "password_changed"
	revoked := &Session{IsValid: true, ExpiresAt: future, RevokedAt: &now, RevokedReason: &reasonText}
	if ok, reason := revoked.CanBeUsed(now); ok || reason != reasonText {
		t.Errorf("a revoked session must not be usable and must surface its reason: ok=%v reason=%q", ok, reason)
	}

	expired := &Session{IsValid: true, ExpiresAt: past}
	if ok, reason := expired.CanBeUsed(now); ok || reason == "" {
		t.Errorf("an expired session must not be usable: ok=%v reason=%q", ok, reason)
	}
}
