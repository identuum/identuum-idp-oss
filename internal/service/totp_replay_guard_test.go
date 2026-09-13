package service

import (
	"context"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

// memTOTPSteps is the in-memory repository.TOTPUsedStepRepository the
// service tests use: it keeps the store's contract exactly (Claim answers
// first-use once per (user, step)) and a non-nil err makes every call fail,
// so a test can prove the guard fails CLOSED. Test support only; the
// appliance wires the pgx store.
type memTOTPSteps struct {
	mu     sync.Mutex
	used   map[string]time.Time
	err    error
	claims int
}

func newMemTOTPSteps() *memTOTPSteps {
	return &memTOTPSteps{used: map[string]time.Time{}}
}

func (m *memTOTPSteps) key(userID uuid.UUID, step int64) string {
	return userID.String() + ":" + strconv.FormatInt(step, 10)
}

func (m *memTOTPSteps) Claim(_ context.Context, userID uuid.UUID, step int64, expiresAt time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return false, m.err
	}
	m.claims++
	k := m.key(userID, step)
	if _, seen := m.used[k]; seen {
		return false, nil
	}
	m.used[k] = expiresAt
	return true, nil
}

func (m *memTOTPSteps) DeleteExpiredBefore(_ context.Context, cutoff time.Time) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return 0, m.err
	}
	var n int64
	for k, exp := range m.used {
		if exp.Before(cutoff) {
			delete(m.used, k)
			n++
		}
	}
	return n, nil
}

func (m *memTOTPSteps) rows() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.used)
}

// testReplayGuard is the guard every service test wires: a fresh
// in-memory store, default geometry.
func testReplayGuard(t *testing.T) *TOTPReplayGuard {
	t.Helper()
	return NewTOTPReplayGuard(nil, newMemTOTPSteps(), TOTPReplayGuardOptions{})
}

// testReplayGuardOver wires a guard over the given store so a test can
// inspect or break it.
func testReplayGuardOver(store *memTOTPSteps) *TOTPReplayGuard {
	return NewTOTPReplayGuard(nil, store, TOTPReplayGuardOptions{})
}
