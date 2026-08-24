package repository

// inmemory_webauthn_session_repository_test.go — repository-layer
// tests for the OSS in-memory WebAuthn challenge store. Covered:
//
//   - Save then Get returns the persisted SessionData.
//   - Get on a missing key returns ErrWebAuthnSessionNotFound.
//   - Get on an expired key returns ErrWebAuthnSessionExpired AND
//     evicts the entry under the same lock.
//   - Delete on a missing key is idempotent (no error).
//
// The expiry test injects a frozen clock so the test does not
// sleep — the lifecycle is deterministic.

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInMemoryWebAuthnSessionRepository_SaveGetDelete(t *testing.T) {
	repo := NewInMemoryWebAuthnSessionRepository()
	ctx := context.Background()
	want := &webauthn.SessionData{Challenge: "abc"}

	require.NoError(t, repo.Save(ctx, "key1", want, time.Minute))
	got, err := repo.Get(ctx, "key1")
	require.NoError(t, err)
	assert.Equal(t, want, got)

	require.NoError(t, repo.Delete(ctx, "key1"))
	_, err = repo.Get(ctx, "key1")
	assert.ErrorIs(t, err, ErrWebAuthnSessionNotFound)
}

func TestInMemoryWebAuthnSessionRepository_MissingKeyIsNotFound(t *testing.T) {
	repo := NewInMemoryWebAuthnSessionRepository()
	_, err := repo.Get(context.Background(), "missing")
	assert.ErrorIs(t, err, ErrWebAuthnSessionNotFound)
}

func TestInMemoryWebAuthnSessionRepository_DeleteMissingKeyIsIdempotent(t *testing.T) {
	repo := NewInMemoryWebAuthnSessionRepository()
	assert.NoError(t, repo.Delete(context.Background(), "missing"))
}

func TestInMemoryWebAuthnSessionRepository_ExpiryEvictsEntry(t *testing.T) {
	repo := NewInMemoryWebAuthnSessionRepository()
	frozen := time.Unix(1_700_000_000, 0)
	repo.now = func() time.Time { return frozen }

	ctx := context.Background()
	require.NoError(t, repo.Save(ctx, "k", &webauthn.SessionData{Challenge: "c"}, time.Minute))

	// Advance past TTL.
	repo.now = func() time.Time { return frozen.Add(time.Minute + time.Second) }
	_, err := repo.Get(ctx, "k")
	assert.ErrorIs(t, err, ErrWebAuthnSessionExpired)

	// Subsequent Get must report not-found (entry was evicted).
	_, err = repo.Get(ctx, "k")
	assert.ErrorIs(t, err, ErrWebAuthnSessionNotFound)
}

func TestInMemoryWebAuthnSessionRepository_SaveOverwritesExistingKey(t *testing.T) {
	repo := NewInMemoryWebAuthnSessionRepository()
	ctx := context.Background()

	require.NoError(t, repo.Save(ctx, "k", &webauthn.SessionData{Challenge: "first"}, time.Minute))
	require.NoError(t, repo.Save(ctx, "k", &webauthn.SessionData{Challenge: "second"}, time.Minute))

	got, err := repo.Get(ctx, "k")
	require.NoError(t, err)
	assert.Equal(t, "second", got.Challenge)
}

// ---------- P2-11: atomic single-use + map bound ----------

// TestConsume_MissingAndExpiredSentinels: Consume returns the SAME opaque
// sentinels as Get, and removes on every hit.
func TestConsume_MissingAndExpiredSentinels(t *testing.T) {
	repo := NewInMemoryWebAuthnSessionRepository()
	ctx := context.Background()

	_, err := repo.Consume(ctx, "missing")
	assert.ErrorIs(t, err, ErrWebAuthnSessionNotFound)

	frozen := time.Unix(1_700_000_000, 0)
	repo.now = func() time.Time { return frozen }
	require.NoError(t, repo.Save(ctx, "k", &webauthn.SessionData{Challenge: "c"}, time.Minute))
	repo.now = func() time.Time { return frozen.Add(time.Minute + time.Second) }
	_, err = repo.Consume(ctx, "k")
	assert.ErrorIs(t, err, ErrWebAuthnSessionExpired)
	// Removed on the expired hit too.
	_, err = repo.Consume(ctx, "k")
	assert.ErrorIs(t, err, ErrWebAuthnSessionNotFound)
}

// TestConsume_ConcurrentSingleUse is the core P2-11 concurrency property:
// many goroutines Consume the SAME key at once → EXACTLY ONE gets the
// SessionData; every other gets the not-found sentinel. Many rounds per
// invocation for teeth; run under -race, 5× (see report). TEETH: revert
// Consume to a non-atomic get-then-delete and this reports >1 winner.
// RULE: WEBAUTHN-CONSUME-1
func TestConsume_ConcurrentSingleUse(t *testing.T) {
	const goroutines = 64
	const rounds = 50
	ctx := context.Background()
	for round := 0; round < rounds; round++ {
		repo := NewInMemoryWebAuthnSessionRepository()
		const key = "webauthn:login:same-session"
		require.NoError(t, repo.Save(ctx, key, &webauthn.SessionData{Challenge: "c"}, time.Minute))

		var winners int64
		var start, done sync.WaitGroup
		start.Add(1)
		done.Add(goroutines)
		for i := 0; i < goroutines; i++ {
			go func() {
				defer done.Done()
				start.Wait() // release all at once — maximize the race
				data, err := repo.Consume(ctx, key)
				switch {
				case err == nil && data != nil:
					atomic.AddInt64(&winners, 1)
				case errors.Is(err, ErrWebAuthnSessionNotFound):
					// loser — correct
				default:
					t.Errorf("round %d: unexpected Consume result: data=%v err=%v", round, data, err)
				}
			}()
		}
		start.Done()
		done.Wait()
		if winners != 1 {
			t.Fatalf("round %d: single-use VIOLATED — %d winners for one challenge, want exactly 1 (replay possible)", round, winners)
		}
	}
}

// TestSave_BoundsMapAtCap: saving far beyond the cap (none consumed, mix
// of live + already-expired) keeps the map <= maxWebAuthnSessions — an
// attacker starting endless ceremonies cannot grow memory without limit.
// TEETH: remove the cap eviction from Save and this exceeds the cap.
func TestSave_BoundsMapAtCap(t *testing.T) {
	repo := NewInMemoryWebAuthnSessionRepository()
	ctx := context.Background()
	for i := 0; i < maxWebAuthnSessions*2; i++ {
		ttl := time.Minute
		if i%3 == 0 {
			ttl = -time.Second // already expired at Save time
		}
		require.NoError(t, repo.Save(ctx, fmt.Sprintf("k-%d", i), &webauthn.SessionData{}, ttl))
		repo.mu.Lock()
		n := len(repo.sessions)
		repo.mu.Unlock()
		if n > maxWebAuthnSessions {
			t.Fatalf("map grew to %d, exceeds cap %d at i=%d (unbounded)", n, maxWebAuthnSessions, i)
		}
	}
}
