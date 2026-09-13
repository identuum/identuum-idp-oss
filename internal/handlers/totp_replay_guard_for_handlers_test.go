package handlers

import (
	"context"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/service"
)

// memTOTPStepsForHandlers is the handler tests' in-memory
// repository.TOTPUsedStepRepository (THE-CODE-THAT-WORKS-TWICE): the same
// contract as the pgx store — first use once per (user, step) — so a
// handler test can present a code twice and see the wire's answer.
type memTOTPStepsForHandlers struct {
	mu   sync.Mutex
	used map[string]time.Time
}

func newMemTOTPStepsForHandlers() *memTOTPStepsForHandlers {
	return &memTOTPStepsForHandlers{used: map[string]time.Time{}}
}

func (m *memTOTPStepsForHandlers) Claim(_ context.Context, userID uuid.UUID, step int64, expiresAt time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := userID.String() + ":" + strconv.FormatInt(step, 10)
	if _, seen := m.used[k]; seen {
		return false, nil
	}
	m.used[k] = expiresAt
	return true, nil
}

func (m *memTOTPStepsForHandlers) DeleteExpiredBefore(_ context.Context, cutoff time.Time) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var n int64
	for k, exp := range m.used {
		if exp.Before(cutoff) {
			delete(m.used, k)
			n++
		}
	}
	return n, nil
}

// testReplayGuardForHandlers wires a fresh in-memory single-use store.
func testReplayGuardForHandlers() *service.TOTPReplayGuard {
	return service.NewTOTPReplayGuard(nil, newMemTOTPStepsForHandlers(), service.TOTPReplayGuardOptions{})
}
