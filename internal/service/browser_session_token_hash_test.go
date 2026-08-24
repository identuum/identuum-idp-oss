package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

type spyBrowserTokenRepo struct {
	revokedHash string
	revokeCalls int
}

func (r *spyBrowserTokenRepo) Insert(context.Context, *domain.BrowserSessionToken) error { return nil }
func (r *spyBrowserTokenRepo) GetByTokenHash(context.Context, string, time.Time) (*domain.BrowserSessionToken, error) {
	return nil, nil
}
func (r *spyBrowserTokenRepo) RevokeByTokenHash(_ context.Context, tokenHash string, _ time.Time) error {
	r.revokeCalls++
	r.revokedHash = tokenHash
	return nil
}
func (r *spyBrowserTokenRepo) RevokeBySessionID(context.Context, uuid.UUID, time.Time) error {
	return nil
}
func (r *spyBrowserTokenRepo) DeleteExpiredBefore(context.Context, time.Time) (int64, error) {
	return 0, nil
}

// The browser-session wire token is never stored or looked up in plaintext:
// revoking a wire token hands the repository the token's SHA-256 hex digest,
// never the token itself, and an empty token is a no-op.
// RULE: BROWSER-SESSION-TOKEN-1
func TestBrowserSessionToken_RevokeByHashNotPlaintext(t *testing.T) {
	// hashBrowserSessionToken is a deterministic SHA-256 hex digest.
	const wire = "opaque-browser-session-wire-token"
	sum := sha256.Sum256([]byte(wire))
	wantHash := hex.EncodeToString(sum[:])
	if got := hashBrowserSessionToken(wire); got != wantHash || len(got) != 64 {
		t.Fatalf("hashBrowserSessionToken = %q (len %d), want the sha256 hex digest", got, len(got))
	}

	spy := &spyBrowserTokenRepo{}
	svc := NewBrowserSessionTokenService(nil, spy, BrowserSessionTokenServiceOptions{})

	if err := svc.Revoke(context.Background(), wire); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if spy.revokeCalls != 1 {
		t.Fatalf("Revoke must reach the repository exactly once, got %d calls", spy.revokeCalls)
	}
	if spy.revokedHash == wire {
		t.Fatalf("the PLAINTEXT wire token reached the repository — it must be hashed first")
	}
	if spy.revokedHash != wantHash {
		t.Fatalf("Revoke passed %q, want the sha256 hash %q", spy.revokedHash, wantHash)
	}

	// An empty wire token is a no-op: nothing reaches the repository.
	spy2 := &spyBrowserTokenRepo{}
	svc2 := NewBrowserSessionTokenService(nil, spy2, BrowserSessionTokenServiceOptions{})
	if err := svc2.Revoke(context.Background(), "   "); err != nil {
		t.Fatalf("Revoke(empty): %v", err)
	}
	if spy2.revokeCalls != 0 {
		t.Fatalf("an empty wire token must be a no-op, got %d repo calls", spy2.revokeCalls)
	}
}
