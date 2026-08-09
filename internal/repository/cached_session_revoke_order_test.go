package repository

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/infra/cache"
)

// P3-10: the cache is invalidated BEFORE the database revocation is committed.
//
// If the delegate's Revoke then FAILS, the row is still active and the cache
// entry is gone — so the very next validation repopulates the cache from a
// database that still says ACTIVE. The operator saw an error and believes the
// session is dead; the cache says it is alive, and now agrees with the DB.
//
// Invalidating AFTER a successful commit alone is not sufficient either: a
// concurrent read between commit and invalidation refills from the old value.
// The only ordering that closes both windows is invalidate, commit, invalidate.
func TestCachedSessionRepository_Revoke_FailedCommitDoesNotLeaveCacheInvalidated(t *testing.T) {
	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()

	rc, err := cache.NewRedisClient(mr.Addr(), "")
	require.NoError(t, err)

	mockRepo := new(MockSessionRepository)
	repo := NewCachedSessionRepository(mockRepo, rc)
	ctx := context.Background()

	id, orgID := uuid.New(), uuid.New()
	require.NoError(t, repo.redisClient.Set(ctx, repo.validationKey(id),
		&domain.SessionValidationInfo{}, time.Minute))

	// CONTROL: the entry really is cached before we start, otherwise the
	// assertion below would pass for the wrong reason.
	var probe domain.SessionValidationInfo
	require.NoError(t, repo.redisClient.Get(ctx, repo.validationKey(id), &probe),
		"CONTROL FAILED: the cache entry was not set, so this test proves nothing")

	// Simulate the concurrent reader. The delegate's Revoke runs AFTER the
	// wrapper has already invalidated, so a validation arriving in that window
	// reads the still-active row and repopulates the cache. Doing the Set from
	// inside the mock places it exactly in that window, deterministically.
	mockRepo.On("Revoke", ctx, id, orgID, "compromised").
		Run(func(mock.Arguments) {
			_ = repo.redisClient.Set(ctx, repo.validationKey(id),
				&domain.SessionValidationInfo{}, time.Minute)
		}).
		Return(nil).Once()

	require.NoError(t, repo.Revoke(ctx, id, orgID, "compromised"))

	// The revocation COMMITTED. Any cache entry now is the stale-active one the
	// concurrent reader wrote, and it will be served as a live session until it
	// expires on its own.
	if err := repo.redisClient.Get(ctx, repo.validationKey(id), &probe); err == nil {
		t.Fatal("after a COMMITTED revocation the cache still holds a session entry — " +
			"a read that landed between invalidation and commit repopulated it from the " +
			"not-yet-revoked row, and that entry outlives the revocation")
	}

	mockRepo.AssertExpectations(t)
}
