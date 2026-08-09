package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// P3-4: the max-session cap evicted BEFORE the insert, so any failure between
// the two — token generation, hashing, the insert itself — left the user's
// oldest sessions ALREADY REVOKED for a session that never came into being.
// The login failed AND the user was logged out elsewhere, for nothing.
func TestCreateUserSession_FailedCreateDoesNotEvictExistingSessions(t *testing.T) {
	repo := newSessionRepo()
	userID := uuid.New()

	// Seed the user at the cap so a further login would normally evict.
	for i := 0; i < 2; i++ {
		id := uuid.New()
		repo.byID[id] = &domain.Session{
			ID:        id,
			UserID:    userID,
			CreatedAt: time.Now().Add(-time.Duration(i+1) * time.Hour),
			ExpiresAt: time.Now().Add(time.Hour),
			IsValid:   true,
		}
	}

	// CONTROL: the seeded sessions really are visible as active, or the
	// assertion below would pass because there was nothing to evict.
	active, err := repo.ListActiveByUserID(context.Background(), userID)
	if err != nil || len(active) != 2 {
		t.Fatalf("CONTROL FAILED: ListActiveByUserID = %d sessions, err = %v; want 2 — "+
			"this test proves nothing unless there are sessions available to evict", len(active), err)
	}

	repo.createErr = errors.New("insert failed")
	svc := NewUserSessionService(nil, repo, UserSessionServiceOptions{DefaultTTL: time.Hour})

	if _, err := svc.CreateUserSession(context.Background(), CreateUserSessionInput{
		UserID:             userID,
		MaxSessionsPerUser: 2,
		Role:               "org_user",
	}); err == nil {
		t.Fatal("create was expected to fail; the fixture returns an insert error")
	}

	stillActive, err := repo.ListActiveByUserID(context.Background(), userID)
	if err != nil {
		t.Fatalf("re-listing sessions: %v", err)
	}
	if len(stillActive) != 2 {
		t.Fatalf("the create FAILED but only %d of 2 sessions survived — the user was logged "+
			"out elsewhere for a session that never existed", len(stillActive))
	}
}

// And the cap must still BITE on the happy path, or the fix above is just a
// removal of the feature.
func TestCreateUserSession_SucceedingCreateStillEnforcesTheCap(t *testing.T) {
	repo := newSessionRepo()
	userID := uuid.New()
	for i := 0; i < 2; i++ {
		id := uuid.New()
		repo.byID[id] = &domain.Session{
			ID:        id,
			UserID:    userID,
			CreatedAt: time.Now().Add(-time.Duration(i+1) * time.Hour),
			ExpiresAt: time.Now().Add(time.Hour),
			IsValid:   true,
		}
	}

	svc := NewUserSessionService(nil, repo, UserSessionServiceOptions{DefaultTTL: time.Hour})
	if _, err := svc.CreateUserSession(context.Background(), CreateUserSessionInput{
		UserID:             userID,
		MaxSessionsPerUser: 2,
		Role:               "org_user",
	}); err != nil {
		t.Fatalf("create: %v", err)
	}

	active, err := repo.ListActiveByUserID(context.Background(), userID)
	if err != nil {
		t.Fatalf("listing: %v", err)
	}
	if len(active) != 2 {
		t.Errorf("active sessions = %d, want exactly the cap of 2 — the cap must still trim", len(active))
	}
}
