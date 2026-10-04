package crypto

import (
	"context"
	"errors"
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

// A request whose client has gone does not keep waiting for a hashing slot: the
// wait ends with the request's context, and nothing is hashed for it.
func TestPasswordHashing_TheWaitForASlotEndsWithTheRequest(t *testing.T) {
	gate := &hashLimiter{slots: make(chan struct{}, 1)}
	gate.slots <- struct{}{} // every slot is taken
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ran := false
	if _, err := gate.run(ctx, func() []byte { ran = true; return nil }); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if ran {
		t.Error("the hash ran for a request that had gone")
	}

	held := hashGate
	t.Cleanup(func() { hashGate = held })
	hashGate = gate
	if _, err := GenerateHashContext(ctx, []byte("pw")); !errors.Is(err, context.Canceled) {
		t.Errorf("GenerateHashContext: err = %v, want context.Canceled", err)
	}
	if err := CompareHashAndPasswordContext(ctx, []byte(DummyPasswordHash()), []byte("pw")); !errors.Is(err, context.Canceled) {
		t.Errorf("CompareHashAndPasswordContext: err = %v, want context.Canceled", err)
	}
}

func TestHashGate_CapacityIsWithinBounds(t *testing.T) {
	if n := cap(hashGate.slots); n < 2 || n > 8 {
		t.Errorf("hash gate capacity = %d; want between 2 and 8", n)
	}
}
