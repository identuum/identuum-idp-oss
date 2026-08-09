package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// fakeRevocationRepo is an in-memory implementation of
// repository.TokenRevocationRepository. Panics on unused methods
// so tests can pin which entry points the service touches.
type fakeRevocationRepo struct {
	inserts          []domain.TokenRevocation
	insertErr        error
	exists           map[string]bool
	existsErr        error
	deletedBeforeCut time.Time
	deletedCount     int64
	deleteErr        error
}

func newFakeRevocationRepo() *fakeRevocationRepo {
	return &fakeRevocationRepo{exists: map[string]bool{}}
}

func (f *fakeRevocationRepo) Insert(_ context.Context, r *domain.TokenRevocation) error {
	if f.insertErr != nil {
		return f.insertErr
	}
	f.inserts = append(f.inserts, *r)
	f.exists[r.Jti] = true
	return nil
}

func (f *fakeRevocationRepo) Exists(_ context.Context, jti string) (bool, error) {
	if f.existsErr != nil {
		return false, f.existsErr
	}
	return f.exists[jti], nil
}

func (f *fakeRevocationRepo) DeleteExpiredBefore(_ context.Context, cutoff time.Time) (int64, error) {
	if f.deleteErr != nil {
		return 0, f.deleteErr
	}
	f.deletedBeforeCut = cutoff
	return f.deletedCount, nil
}

// ---------- Construction ----------

func TestNewTokenRevocationService_NilRepoPanics(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("NewTokenRevocationService(nil, nil) did not panic")
		}
	}()
	_ = NewTokenRevocationService(nil, nil)
}

// ---------- RevokeJTI ----------

func TestRevokeJTI_EmptyJTIRejected(t *testing.T) {
	svc := NewTokenRevocationService(nil, newFakeRevocationRepo())
	err := svc.RevokeJTI(context.Background(), "  ", time.Now().Add(time.Minute), "x", nil)
	if !errors.Is(err, ErrTokenRevocationInvalidJTI) {
		t.Errorf("err = %v, want ErrTokenRevocationInvalidJTI", err)
	}
}

func TestRevokeJTI_ZeroExpiryRejected(t *testing.T) {
	svc := NewTokenRevocationService(nil, newFakeRevocationRepo())
	err := svc.RevokeJTI(context.Background(), "jti-1", time.Time{}, "x", nil)
	if !errors.Is(err, ErrTokenRevocationInvalidExpiry) {
		t.Errorf("err = %v, want ErrTokenRevocationInvalidExpiry", err)
	}
}

func TestRevokeJTI_AlreadyExpiredIsNoOp(t *testing.T) {
	repo := newFakeRevocationRepo()
	svc := NewTokenRevocationService(nil, repo)
	err := svc.RevokeJTI(context.Background(), "jti-1", time.Now().Add(-time.Hour), "x", nil)
	if err != nil {
		t.Errorf("expired revoke err = %v, want nil", err)
	}
	if len(repo.inserts) != 0 {
		t.Errorf("repo got %d inserts for expired jti", len(repo.inserts))
	}
}

func TestRevokeJTI_PersistsRow(t *testing.T) {
	repo := newFakeRevocationRepo()
	svc := NewTokenRevocationService(nil, repo)
	exp := time.Now().Add(time.Hour).UTC()
	err := svc.RevokeJTI(context.Background(), "jti-abc", exp, "oauth_token_revoked", map[string]any{
		"client_id":     "cli-1",
		"client_kind":   "oauth_client",
		"raw_token":     "MUST-NOT-LEAK",
		"client_secret": "MUST-NOT-LEAK",
		"signing_key":   "MUST-NOT-LEAK",
	})
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if len(repo.inserts) != 1 {
		t.Fatalf("inserts = %d", len(repo.inserts))
	}
	r := repo.inserts[0]
	if r.Jti != "jti-abc" {
		t.Errorf("jti = %q", r.Jti)
	}
	if !r.ExpiresAt.Equal(exp) {
		t.Errorf("exp = %v, want %v", r.ExpiresAt, exp)
	}
	if r.Reason != "oauth_token_revoked" {
		t.Errorf("reason = %q", r.Reason)
	}
	// Sanitizer drops every key that is not on the allowlist.
	for _, banned := range []string{"raw_token", "client_secret", "signing_key"} {
		if _, ok := r.Metadata[banned]; ok {
			t.Errorf("metadata leaked banned key %q", banned)
		}
	}
	if got := r.Metadata["client_id"]; got != "cli-1" {
		t.Errorf("client_id = %v", got)
	}
	if got := r.Metadata["client_kind"]; got != "oauth_client" {
		t.Errorf("client_kind = %v", got)
	}
}

func TestRevokeJTI_DefaultReasonApplied(t *testing.T) {
	repo := newFakeRevocationRepo()
	svc := NewTokenRevocationService(nil, repo)
	_ = svc.RevokeJTI(context.Background(), "jti-2", time.Now().Add(time.Minute), "", nil)
	if got := repo.inserts[0].Reason; got != "oauth_token_revoked" {
		t.Errorf("default reason = %q", got)
	}
}

func TestRevokeJTI_RejectsNewlineLacedMetadataValue(t *testing.T) {
	repo := newFakeRevocationRepo()
	svc := NewTokenRevocationService(nil, repo)
	_ = svc.RevokeJTI(context.Background(), "jti-x", time.Now().Add(time.Minute), "x", map[string]any{
		"client_id": "ok",
		// "client_kind" carries embedded newlines — sanitizer
		// should drop it.
		"client_kind": "oauth_client\nleaked",
	})
	r := repo.inserts[0]
	if _, ok := r.Metadata["client_kind"]; ok {
		t.Errorf("metadata kept newline-laced value")
	}
	if got := r.Metadata["client_id"]; got != "ok" {
		t.Errorf("client_id = %v", got)
	}
}

func TestRevokeJTI_PropagatesRepoError(t *testing.T) {
	repo := newFakeRevocationRepo()
	repo.insertErr = errors.New("db down")
	svc := NewTokenRevocationService(nil, repo)
	err := svc.RevokeJTI(context.Background(), "jti", time.Now().Add(time.Minute), "x", nil)
	if err == nil {
		t.Errorf("expected error, got nil")
	}
}

// ---------- IsRevoked ----------

func TestIsRevoked_EmptyJTIIsFalse(t *testing.T) {
	svc := NewTokenRevocationService(nil, newFakeRevocationRepo())
	got, err := svc.IsRevoked(context.Background(), "  ")
	if err != nil || got {
		t.Errorf("empty jti: got=%v err=%v", got, err)
	}
}

func TestIsRevoked_AfterRevokeReturnsTrue(t *testing.T) {
	repo := newFakeRevocationRepo()
	svc := NewTokenRevocationService(nil, repo)
	_ = svc.RevokeJTI(context.Background(), "j-1", time.Now().Add(time.Minute), "x", nil)
	got, err := svc.IsRevoked(context.Background(), "j-1")
	if err != nil || !got {
		t.Errorf("after revoke: got=%v err=%v", got, err)
	}
}

func TestIsRevoked_UnknownReturnsFalse(t *testing.T) {
	svc := NewTokenRevocationService(nil, newFakeRevocationRepo())
	got, _ := svc.IsRevoked(context.Background(), "unknown")
	if got {
		t.Errorf("unknown jti reported revoked")
	}
}

func TestIsRevoked_PropagatesRepoError(t *testing.T) {
	repo := newFakeRevocationRepo()
	repo.existsErr = errors.New("db down")
	svc := NewTokenRevocationService(nil, repo)
	_, err := svc.IsRevoked(context.Background(), "any")
	if err == nil {
		t.Errorf("expected error, got nil")
	}
}

// ---------- DeleteExpired ----------

func TestDeleteExpired_UsesNowAsCutoff(t *testing.T) {
	repo := newFakeRevocationRepo()
	repo.deletedCount = 7
	svc := NewTokenRevocationService(nil, repo)
	fixed := time.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC)
	svc.now = func() time.Time { return fixed }
	n, err := svc.DeleteExpired(context.Background())
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	if n != 7 {
		t.Errorf("n = %d, want 7", n)
	}
	if !repo.deletedBeforeCut.Equal(fixed) {
		t.Errorf("cutoff = %v, want %v", repo.deletedBeforeCut, fixed)
	}
}
