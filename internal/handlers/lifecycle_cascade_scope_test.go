package handlers

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/google/uuid"
)

// cascadeSpySessionRevoker records the user ids handed to RevokeUserSessions
// and can be told to fail, to prove the cascade is best-effort.
type cascadeSpySessionRevoker struct {
	mu      sync.Mutex
	users   []uuid.UUID
	failErr error
}

func (s *cascadeSpySessionRevoker) RevokeUserSessions(_ context.Context, userID uuid.UUID, _ string, _ map[string]any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.users = append(s.users, userID)
	return s.failErr
}

func (s *cascadeSpySessionRevoker) calls() []uuid.UUID {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]uuid.UUID(nil), s.users...)
}

// cascadeSpyRefreshRevoker records the user ids handed to RevokeAllForUser.
type cascadeSpyRefreshRevoker struct {
	mu    sync.Mutex
	users []uuid.UUID
}

func (s *cascadeSpyRefreshRevoker) RevokeAllForUser(_ context.Context, userID uuid.UUID) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.users = append(s.users, userID)
	return 0, nil
}

func (s *cascadeSpyRefreshRevoker) calls() []uuid.UUID {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]uuid.UUID(nil), s.users...)
}

// cascadeRevokeUser revokes the target user's sessions AND all their OAuth
// refresh tokens — both scoped to exactly that user id — and is best-effort: a
// revoker error is logged, not propagated (the function returns nothing and the
// other revoker still fires), and a nil revoker is skipped without a panic.
// RULE: USER-LIFECYCLE-CASCADE-1
func TestCascadeRevokeUser_ScopedAndBestEffort(t *testing.T) {
	uid := uuid.New()
	other := uuid.New()

	// Happy path: both revokers fire for exactly the target user.
	sess := &cascadeSpySessionRevoker{}
	refresh := &cascadeSpyRefreshRevoker{}
	cascadeRevokeUser(context.Background(), sess, refresh, uid, "user_deleted")
	if got := sess.calls(); len(got) != 1 || got[0] != uid {
		t.Fatalf("session cascade must revoke exactly the target user, got %v (uid=%s)", got, uid)
	}
	if got := refresh.calls(); len(got) != 1 || got[0] != uid {
		t.Fatalf("refresh cascade must revoke exactly the target user, got %v (uid=%s)", got, uid)
	}
	if sess.calls()[0] == other {
		t.Fatalf("session cascade must never touch another user %s", other)
	}

	// Best-effort: a session-revoker error does NOT stop the refresh revoke.
	sessErr := &cascadeSpySessionRevoker{failErr: errors.New("boom")}
	refreshAfterErr := &cascadeSpyRefreshRevoker{}
	cascadeRevokeUser(context.Background(), sessErr, refreshAfterErr, uid, "user_deleted")
	if len(refreshAfterErr.calls()) != 1 {
		t.Errorf("best-effort: refresh revoke must still fire after a session-revoker error, got %d calls", len(refreshAfterErr.calls()))
	}

	// Nil revokers are skipped without panic and touch nothing.
	cascadeRevokeUser(context.Background(), nil, nil, uid, "user_deleted")
}
