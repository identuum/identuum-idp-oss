package crypto

import (
	"context"
	"runtime"
	"sync"
)

// hashLimiter bounds how many Argon2id runs are in flight. Each run holds
// domain.Argon2Memory (64 MiB); sign-in, password change, reset and invite
// all reach it, so a burst of unauthenticated attempts would otherwise run
// them all at once.
type hashLimiter struct {
	slots chan struct{}

	mu       sync.Mutex
	inFlight int
	peak     int
}

// hashGate is the one limiter every Argon2id run in this package passes through.
// Its capacity follows the CPUs, between 2 and 8 (at most 512 MiB at once).
var hashGate = &hashLimiter{slots: make(chan struct{}, hashGateCapacity())}

func hashGateCapacity() int {
	return min(max(runtime.GOMAXPROCS(0), 2), 8)
}

// run executes f once a slot is free and returns its result. The wait ends
// with ctx (a client that has gone), and then f does not run.
func (g *hashLimiter) run(ctx context.Context, f func() []byte) ([]byte, error) {
	select {
	case g.slots <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	defer func() { <-g.slots }()
	g.mu.Lock()
	g.inFlight++
	g.peak = max(g.peak, g.inFlight)
	g.mu.Unlock()
	defer func() {
		g.mu.Lock()
		g.inFlight--
		g.mu.Unlock()
	}()
	return f(), nil
}

func (g *hashLimiter) resetPeak() {
	g.mu.Lock()
	g.peak = g.inFlight
	g.mu.Unlock()
}

func (g *hashLimiter) peakInFlight() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.peak
}
