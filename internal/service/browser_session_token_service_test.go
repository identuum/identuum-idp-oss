package service

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// inMemoryBrowserSessionTokenRepo is the test seam.
type inMemoryBrowserSessionTokenRepo struct {
	mu     sync.Mutex
	rows   map[string]*domain.BrowserSessionToken // by token_hash
	byID   map[uuid.UUID]*domain.BrowserSessionToken
	bySess map[uuid.UUID][]*domain.BrowserSessionToken
}

func newBrowserTokenRepo() *inMemoryBrowserSessionTokenRepo {
	return &inMemoryBrowserSessionTokenRepo{
		rows:   map[string]*domain.BrowserSessionToken{},
		byID:   map[uuid.UUID]*domain.BrowserSessionToken{},
		bySess: map[uuid.UUID][]*domain.BrowserSessionToken{},
	}
}

func (r *inMemoryBrowserSessionTokenRepo) Insert(_ context.Context, t *domain.BrowserSessionToken) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	cp := *t
	r.rows[t.TokenHash] = &cp
	r.byID[t.ID] = &cp
	r.bySess[t.SessionID] = append(r.bySess[t.SessionID], &cp)
	return nil
}

func (r *inMemoryBrowserSessionTokenRepo) GetByTokenHash(_ context.Context, hash string, now time.Time) (*domain.BrowserSessionToken, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	row, ok := r.rows[hash]
	if !ok {
		return nil, nil
	}
	if row.RevokedAt != nil {
		return nil, nil
	}
	if row.ExpiresAt.Before(now) {
		return nil, nil
	}
	cp := *row
	return &cp, nil
}

func (r *inMemoryBrowserSessionTokenRepo) RevokeByTokenHash(_ context.Context, hash string, at time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	row, ok := r.rows[hash]
	if !ok {
		return nil
	}
	row.RevokedAt = &at
	return nil
}

func (r *inMemoryBrowserSessionTokenRepo) RevokeBySessionID(_ context.Context, sessionID uuid.UUID, at time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, row := range r.bySess[sessionID] {
		if row.RevokedAt == nil {
			row.RevokedAt = &at
		}
	}
	return nil
}

func (r *inMemoryBrowserSessionTokenRepo) DeleteExpiredBefore(_ context.Context, cutoff time.Time) (int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var n int64
	for hash, row := range r.rows {
		if row.ExpiresAt.Before(cutoff) {
			delete(r.rows, hash)
			delete(r.byID, row.ID)
			n++
		}
	}
	return n, nil
}

// ---------- Construction ----------

func TestNewBrowserSessionTokenService_NilRepoPanics(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("nil repo did not panic")
		}
	}()
	_ = NewBrowserSessionTokenService(nil, nil, BrowserSessionTokenServiceOptions{})
}

// ---------- Issue ----------

func TestBrowserToken_IssueReturnsOpaqueWireValue(t *testing.T) {
	repo := newBrowserTokenRepo()
	svc := NewBrowserSessionTokenService(nil, repo, BrowserSessionTokenServiceOptions{TTL: time.Hour})
	issued, err := svc.Issue(context.Background(), IssueBrowserSessionTokenInput{
		SessionID: uuid.New(),
		UserID:    uuid.New(),
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if len(issued.Token) < 32 {
		t.Errorf("token too short: %d", len(issued.Token))
	}
	if strings.Contains(issued.Token, ".") {
		t.Errorf("token MUST NOT look like a refresh token (selector.validator): %q", issued.Token)
	}
	// Defense in depth: stored hash != raw token.
	//
	// PREMISE: a row must have been STORED. Sweeping an empty repo proves
	// nothing about what the store writes (V4).
	if len(repo.rows) == 0 {
		t.Fatalf("Issue stored no row — the hash sweep below would pass vacuously")
	}
	for _, row := range repo.rows {
		if row.TokenHash == issued.Token {
			t.Errorf("raw token leaked into stored hash")
		}
	}
}

func TestBrowserToken_IssueMissingInputRejected(t *testing.T) {
	svc := NewBrowserSessionTokenService(nil, newBrowserTokenRepo(), BrowserSessionTokenServiceOptions{})
	if _, err := svc.Issue(context.Background(), IssueBrowserSessionTokenInput{}); err == nil {
		t.Errorf("expected invalid_input")
	}
}

// ---------- Resolve ----------

func TestBrowserToken_ResolveValidWire(t *testing.T) {
	repo := newBrowserTokenRepo()
	svc := NewBrowserSessionTokenService(nil, repo, BrowserSessionTokenServiceOptions{TTL: time.Hour})
	sid := uuid.New()
	uid := uuid.New()
	issued, _ := svc.Issue(context.Background(), IssueBrowserSessionTokenInput{SessionID: sid, UserID: uid})

	resolved, err := svc.Resolve(context.Background(), issued.Token)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if resolved == nil {
		t.Fatalf("nil resolved")
	}
	if resolved.SessionID != sid || resolved.UserID != uid {
		t.Errorf("mismatch: %+v", resolved)
	}
}

func TestBrowserToken_ResolveRevokedReturnsNil(t *testing.T) {
	repo := newBrowserTokenRepo()
	svc := NewBrowserSessionTokenService(nil, repo, BrowserSessionTokenServiceOptions{TTL: time.Hour})
	issued, _ := svc.Issue(context.Background(), IssueBrowserSessionTokenInput{SessionID: uuid.New(), UserID: uuid.New()})
	if err := svc.Revoke(context.Background(), issued.Token); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	resolved, _ := svc.Resolve(context.Background(), issued.Token)
	if resolved != nil {
		t.Errorf("revoked token still resolved: %+v", resolved)
	}
}

func TestBrowserToken_ResolveExpiredReturnsNil(t *testing.T) {
	repo := newBrowserTokenRepo()
	svc := NewBrowserSessionTokenService(nil, repo, BrowserSessionTokenServiceOptions{TTL: time.Hour})
	frozen := time.Now()
	svc.now = func() time.Time { return frozen }
	issued, _ := svc.Issue(context.Background(), IssueBrowserSessionTokenInput{SessionID: uuid.New(), UserID: uuid.New()})
	svc.now = func() time.Time { return frozen.Add(2 * time.Hour) }
	resolved, _ := svc.Resolve(context.Background(), issued.Token)
	if resolved != nil {
		t.Errorf("expired token still resolved")
	}
}

func TestBrowserToken_ResolveMalformedReturnsNil(t *testing.T) {
	svc := NewBrowserSessionTokenService(nil, newBrowserTokenRepo(), BrowserSessionTokenServiceOptions{})
	resolved, err := svc.Resolve(context.Background(), "")
	if err != nil || resolved != nil {
		t.Errorf("empty token: resolved=%v err=%v", resolved, err)
	}
}

func TestBrowserToken_RevokeAllForSession(t *testing.T) {
	repo := newBrowserTokenRepo()
	svc := NewBrowserSessionTokenService(nil, repo, BrowserSessionTokenServiceOptions{TTL: time.Hour})
	sid := uuid.New()
	tok1, _ := svc.Issue(context.Background(), IssueBrowserSessionTokenInput{SessionID: sid, UserID: uuid.New()})
	tok2, _ := svc.Issue(context.Background(), IssueBrowserSessionTokenInput{SessionID: sid, UserID: uuid.New()})
	if err := svc.RevokeAllForSession(context.Background(), sid); err != nil {
		t.Fatalf("revoke all: %v", err)
	}
	for _, tok := range []string{tok1.Token, tok2.Token} {
		r, _ := svc.Resolve(context.Background(), tok)
		if r != nil {
			t.Errorf("token still resolved after RevokeAllForSession")
		}
	}
}

func TestBrowserToken_DeleteExpiredPrunes(t *testing.T) {
	repo := newBrowserTokenRepo()
	svc := NewBrowserSessionTokenService(nil, repo, BrowserSessionTokenServiceOptions{TTL: time.Hour})
	frozen := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	svc.now = func() time.Time { return frozen }
	_, _ = svc.Issue(context.Background(), IssueBrowserSessionTokenInput{SessionID: uuid.New(), UserID: uuid.New()})
	svc.now = func() time.Time { return frozen.Add(2 * time.Hour) }
	n, err := svc.DeleteExpired(context.Background())
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	if n != 1 {
		t.Errorf("pruned = %d", n)
	}
}
