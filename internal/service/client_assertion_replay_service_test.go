package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeReplayRepo is the in-memory backing for the replay service
// tests. Insert mimics the postgres `ON CONFLICT DO NOTHING`
// shape: a duplicate (client_id, jti_hash) returns (false, nil).
type fakeReplayRepo struct {
	mu        sync.Mutex
	seen      map[string]map[string]time.Time
	insertErr error
}

func newFakeReplayRepo() *fakeReplayRepo {
	return &fakeReplayRepo{seen: map[string]map[string]time.Time{}}
}

func (r *fakeReplayRepo) Insert(_ context.Context, clientID, jtiHash string, expiresAt time.Time) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.insertErr != nil {
		return false, r.insertErr
	}
	hashes, ok := r.seen[clientID]
	if !ok {
		hashes = map[string]time.Time{}
		r.seen[clientID] = hashes
	}
	if _, exists := hashes[jtiHash]; exists {
		return false, nil
	}
	hashes[jtiHash] = expiresAt
	return true, nil
}

func (r *fakeReplayRepo) DeleteExpiredBefore(_ context.Context, cutoff time.Time) (int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var n int64
	for cid, hashes := range r.seen {
		for h, exp := range hashes {
			if !exp.After(cutoff) {
				delete(hashes, h)
				n++
			}
		}
		if len(hashes) == 0 {
			delete(r.seen, cid)
		}
	}
	return n, nil
}

// ---------- Construction ----------

func TestNewClientAssertionReplayService_NilRepoPanics(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("nil repo did not panic")
		}
	}()
	_ = NewClientAssertionReplayService(nil, nil, ClientAssertionReplayServiceOptions{})
}

// ---------- Mark ----------

func TestMark_FirstUseSucceedsReplayFails(t *testing.T) {
	repo := newFakeReplayRepo()
	svc := NewClientAssertionReplayService(nil, repo, ClientAssertionReplayServiceOptions{})
	exp := time.Now().Add(2 * time.Minute)
	first, err := svc.Mark(context.Background(), "cli-1", "jti-AAA", exp)
	if err != nil || !first {
		t.Errorf("first use: firstUse=%v err=%v", first, err)
	}
	second, err := svc.Mark(context.Background(), "cli-1", "jti-AAA", exp)
	if err != nil {
		t.Errorf("replay err = %v", err)
	}
	if second {
		t.Errorf("replay reported firstUse=true")
	}
}

func TestMark_DifferentClientSameJTIDoesNotCollide(t *testing.T) {
	repo := newFakeReplayRepo()
	svc := NewClientAssertionReplayService(nil, repo, ClientAssertionReplayServiceOptions{})
	exp := time.Now().Add(2 * time.Minute)
	if first, _ := svc.Mark(context.Background(), "cli-A", "jti-shared", exp); !first {
		t.Errorf("cli-A first use rejected")
	}
	if first, _ := svc.Mark(context.Background(), "cli-B", "jti-shared", exp); !first {
		t.Errorf("cli-B same jti collided with cli-A")
	}
}

func TestMark_EmptyInputIsProgrammerError(t *testing.T) {
	repo := newFakeReplayRepo()
	svc := NewClientAssertionReplayService(nil, repo, ClientAssertionReplayServiceOptions{})
	exp := time.Now().Add(time.Minute)
	if _, err := svc.Mark(context.Background(), "", "jti", exp); !errors.Is(err, ErrReplayInvalidInput) {
		t.Errorf("empty client_id err = %v", err)
	}
	if _, err := svc.Mark(context.Background(), "cli", "", exp); !errors.Is(err, ErrReplayInvalidInput) {
		t.Errorf("empty jti err = %v", err)
	}
}

func TestMark_StoresHashNotRawJTI(t *testing.T) {
	repo := newFakeReplayRepo()
	svc := NewClientAssertionReplayService(nil, repo, ClientAssertionReplayServiceOptions{})
	const sentinel = "RAW-JTI-MUST-NOT-LEAK"
	exp := time.Now().Add(2 * time.Minute)
	if _, err := svc.Mark(context.Background(), "cli", sentinel, exp); err != nil {
		t.Fatalf("mark: %v", err)
	}
	hashes := repo.seen["cli"]
	for stored := range hashes {
		if stored == sentinel || strings.Contains(stored, sentinel) {
			t.Errorf("repo stored raw jti sentinel %q", stored)
		}
	}
	// Recompute the expected hash and verify presence.
	sum := sha256.Sum256([]byte(sentinel))
	wantHash := hex.EncodeToString(sum[:])
	if _, ok := hashes[wantHash]; !ok {
		t.Errorf("expected hash %q not present", wantHash)
	}
}

func TestMark_RepoErrorBubblesUpFailClosed(t *testing.T) {
	repo := newFakeReplayRepo()
	repo.insertErr = errors.New("db down")
	svc := NewClientAssertionReplayService(nil, repo, ClientAssertionReplayServiceOptions{})
	first, err := svc.Mark(context.Background(), "cli", "jti", time.Now().Add(time.Minute))
	if err == nil {
		t.Errorf("expected error from repo, got nil")
	}
	if first {
		t.Errorf("repo error reported firstUse=true (would weaken replay defense)")
	}
}

// ---------- TTL clamping ----------

func TestMark_TTLBelowMinClampedUp(t *testing.T) {
	repo := newFakeReplayRepo()
	svc := NewClientAssertionReplayService(nil, repo, ClientAssertionReplayServiceOptions{TTLMin: 2 * time.Minute, TTLMax: 5 * time.Minute})
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	svc.now = func() time.Time { return now }
	// assertion exp 30s in the future — below TTLMin (2m).
	exp := now.Add(30 * time.Second)
	if _, err := svc.Mark(context.Background(), "cli", "jti", exp); err != nil {
		t.Fatalf("mark: %v", err)
	}
	stored := repo.seen["cli"][hashJTI("jti")]
	if stored.Sub(now) < 2*time.Minute {
		t.Errorf("TTL not clamped up: %v", stored.Sub(now))
	}
}

func TestMark_TTLAboveMaxClampedDown(t *testing.T) {
	repo := newFakeReplayRepo()
	svc := NewClientAssertionReplayService(nil, repo, ClientAssertionReplayServiceOptions{TTLMin: time.Minute, TTLMax: 3 * time.Minute})
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	svc.now = func() time.Time { return now }
	exp := now.Add(2 * time.Hour) // way past TTLMax.
	if _, err := svc.Mark(context.Background(), "cli", "jti", exp); err != nil {
		t.Fatalf("mark: %v", err)
	}
	stored := repo.seen["cli"][hashJTI("jti")]
	if stored.Sub(now) > 3*time.Minute {
		t.Errorf("TTL not clamped down: %v", stored.Sub(now))
	}
}

// ---------- DeleteExpired ----------

func TestReplay_DeleteExpiredPrunesPastDueRows(t *testing.T) {
	repo := newFakeReplayRepo()
	svc := NewClientAssertionReplayService(nil, repo, ClientAssertionReplayServiceOptions{TTLMin: time.Minute, TTLMax: 5 * time.Minute})
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	svc.now = func() time.Time { return now }
	_, _ = svc.Mark(context.Background(), "cli", "jti-1", now.Add(2*time.Minute))
	svc.now = func() time.Time { return now.Add(10 * time.Minute) }
	n, err := svc.DeleteExpired(context.Background())
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	if n != 1 {
		t.Errorf("n = %d, want 1", n)
	}
}
