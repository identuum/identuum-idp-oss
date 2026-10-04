package crypto

import (
	"errors"
	"strings"
	"testing"
)

// A sign-in for an email that has no account compares against a dummy hash. If
// the dummy's cost differs from a real hash's, the response time tells a caller
// which emails have accounts. The cost is its memory, iterations, parallelism
// and key length: they must be the ones GenerateHash emits.
func TestDummyPasswordHash_CostsWhatARealHashCosts(t *testing.T) {
	real, err := GenerateHash([]byte("correct horse"))
	if err != nil {
		t.Fatalf("GenerateHash: %v", err)
	}
	costOf := func(phc string) (string, int) {
		parts := strings.Split(phc, "$")
		if len(parts) != 6 {
			t.Fatalf("not a PHC string: %q", phc)
		}
		return parts[2] + "$" + parts[3], len(parts[4]) + len(parts[5])
	}
	wantParams, wantLens := costOf(real)
	gotParams, gotLens := costOf(DummyPasswordHash())
	if gotParams != wantParams || gotLens != wantLens {
		t.Errorf("dummy hash cost = %s (salt+key %d chars); a real hash = %s (%d chars)", gotParams, gotLens, wantParams, wantLens)
	}
}

func TestDummyPasswordHash_RunsTheRealComparisonAndNeverMatches(t *testing.T) {
	err := CompareHashAndPassword([]byte(DummyPasswordHash()), []byte("anything"))
	if !errors.Is(err, ErrMismatchedHashAndPassword) {
		t.Errorf("dummy compare = %v; want a full comparison that mismatches (not a format refusal)", err)
	}
}
