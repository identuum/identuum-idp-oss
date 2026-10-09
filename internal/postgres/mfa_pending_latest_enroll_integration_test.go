//go:build integration

package postgres_test

// OSS-HARDEN-1 item 2 against the live SQL: GetLatestLiveEnroll finds the
// user's newest enrol-kind row that holds a secret and is neither consumed nor
// expired, and nothing else.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/postgres"
	"github.com/identuum/identuum-idp-oss/internal/repository"
)

func TestMFAPending_GetLatestLiveEnroll(t *testing.T) {
	pool := keyEncPool(t)
	defer pool.Close()
	ctx := context.Background()
	repo := postgres.NewPgxMFAPendingLoginSessionRepository(pool)
	orgID := seedScratchOrg(t, pool)
	userID := seedSessionUser(t, ctx, pool, orgID)
	other := seedSessionUser(t, ctx, pool, orgID)
	now := time.Now().UTC()
	var ids []uuid.UUID
	seed := func(user uuid.UUID, kind string, secret *string, created, expires time.Time, consumed bool) uuid.UUID {
		t.Helper()
		id := uuid.New()
		var at *time.Time
		if consumed {
			at = &now
		}
		if _, err := pool.Exec(ctx, `
			INSERT INTO mfa_pending_login_sessions (id, user_id, kind, secret, remember_me, created_at, expires_at, consumed_at)
			VALUES ($1, $2, $3, $4, false, $5, $6, $7)`, id, user, kind, secret, created, expires, at); err != nil {
			t.Fatalf("seed: %v", err)
		}
		ids = append(ids, id)
		return id
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM mfa_pending_login_sessions WHERE id = ANY($1)`, ids)
	})
	secret := "sealed"
	hour := now.Add(time.Hour)

	if _, err := repo.GetLatestLiveEnroll(ctx, userID, now); !errors.Is(err, repository.ErrMFAPendingSessionNotFound) {
		t.Fatalf("no row: err=%v; want ErrMFAPendingSessionNotFound", err)
	}
	older := seed(userID, "enroll", &secret, now.Add(-2*time.Minute), hour, false)
	seed(userID, "enroll", nil, now, hour, false)                      // never initiated
	seed(userID, "verify", &secret, now, hour, false)                  // another kind
	seed(userID, "enroll", &secret, now, now.Add(-time.Second), false) // expired
	seed(userID, "enroll", &secret, now, hour, true)                   // used
	seed(other, "enroll", &secret, now.Add(time.Minute), hour, false)  // another user
	got, err := repo.GetLatestLiveEnroll(ctx, userID, now)
	if err != nil || got.ID != older {
		t.Fatalf("err=%v; want the one live enrolment %s", err, older)
	}
	newer := seed(userID, "enroll", &secret, now.Add(-time.Minute), hour, false)
	if got, err := repo.GetLatestLiveEnroll(ctx, userID, now); err != nil || got.ID != newer {
		t.Fatalf("after a newer initiate: err=%v; want %s", err, newer)
	}
}
