package crypto

import (
	"sync"
	"testing"
)

// Every Argon2id run holds 64 MiB. Without a bound, a burst of sign-in attempts
// runs them all at once and can exhaust the process's memory: the number of runs
// in flight is capped, and the rest wait their turn.
func TestPasswordHashing_RunsAreBoundedInFlight(t *testing.T) {
	gate := hashGate
	limit := cap(gate.slots)
	if limit < 1 {
		t.Fatalf("hash gate capacity = %d; want at least 1", limit)
	}
	gate.resetPeak()

	phc, err := GenerateHash([]byte("pw"))
	if err != nil {
		t.Fatalf("GenerateHash: %v", err)
	}
	gate.resetPeak()

	const callers = 24
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = CompareHashAndPassword([]byte(phc), []byte("not the password"))
		}()
	}
	wg.Wait()

	if peak := gate.peakInFlight(); peak > limit {
		t.Errorf("peak Argon2id runs in flight = %d; want at most %d", peak, limit)
	}
	if peak := gate.peakInFlight(); peak < 1 {
		t.Errorf("peak in flight = %d; the gate is not wrapped around the hashing", peak)
	}
}

func TestHashGate_CapacityIsWithinBounds(t *testing.T) {
	if n := cap(hashGate.slots); n < 2 || n > 8 {
		t.Errorf("hash gate capacity = %d; want between 2 and 8", n)
	}
}
