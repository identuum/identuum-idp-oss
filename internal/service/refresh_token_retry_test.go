package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

// F3 (OSS-PRE-RELEASE-REVIEW-2026-10-10, OSS-REVIEW-FIXES-1): RevokeAllForUser
// revokes the refresh rows first and denylists their linked access JTIs
// second, with no transaction across the two stores. When the denylist write
// fails after the refresh UPDATE, the rows are already revoked, so a retry's
// "newly revoked" set is empty and, until this slice, the retry reported
// success without ever denylisting the linked access tokens — which the
// recovery command's own advice ("run it again, it is idempotent") relies on.
// Now a retry revisits the subject's already-revoked, unexpired rows whose
// linked JTI the denylist does not hold yet.
func TestRevokeAllForUser_RetryDenylistsTheLinkedJTIOfAnAlreadyRevokedRow(t *testing.T) {
	ctx := context.Background()
	repo := newInMemoryRefreshTokenRepo()
	revRepo := newFakeRevocationRepo()
	repo.denylisted = func(jti string) bool { return revRepo.exists[jti] }
	svc := NewRefreshTokenService(nil, repo, RefreshTokenServiceOptions{TTL: time.Hour}).
		WithTokenRevocationService(NewTokenRevocationService(nil, revRepo))
	target, other := uuid.New(), uuid.New()
	issued, err := svc.Issue(ctx, IssueRefreshTokenInput{ClientID: "cli", Subject: target.String(), AccessJTI: "linked-target"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Issue(ctx, IssueRefreshTokenInput{ClientID: "cli", Subject: other.String(), AccessJTI: "linked-other"}); err != nil {
		t.Fatal(err)
	}

	// First run: the denylist is down after the refresh UPDATE.
	revRepo.insertErr = errors.New("simulated denylist outage")
	if n, err := svc.RevokeAllForUser(ctx, target); err == nil || n != 1 {
		t.Fatalf("first run = (%d, %v); want 1 revoked row and the denylist error", n, err)
	}
	if repo.byID[issued.ID].RevokedAt == nil {
		t.Fatal("precondition: the refresh row was not revoked by the failed first run")
	}
	if revRepo.exists["linked-target"] {
		t.Fatal("precondition: the linked JTI was denylisted although the denylist failed")
	}

	// Retry with a healthy denylist: the already-revoked row's linked JTI is
	// denylisted now; another user's never is.
	revRepo.insertErr = nil
	n, err := svc.RevokeAllForUser(ctx, target)
	if err != nil {
		t.Fatalf("retry: %v", err)
	}
	if n != 0 {
		t.Errorf("retry revoked %d refresh rows; want 0 (the row was revoked by the first run)", n)
	}
	if !revRepo.exists["linked-target"] {
		t.Fatal("the retry did not denylist the linked access JTI of the already-revoked refresh row")
	}
	if revRepo.exists["linked-other"] {
		t.Error("the retry denylisted another user's linked access JTI")
	}
	// A third run has nothing left to do: the denylist already holds the JTI.
	before := len(revRepo.inserts)
	if _, err := svc.RevokeAllForUser(ctx, target); err != nil || len(revRepo.inserts) != before {
		t.Errorf("third run = %v with %d new denylist writes; want none", err, len(revRepo.inserts)-before)
	}
}

// An expired revoked row is not revisited: its access token is past its own
// expiry too, and the denylist would refuse the write anyway.
func TestRevokeAllForUser_RetrySkipsExpiredRevokedRows(t *testing.T) {
	ctx := context.Background()
	repo := newInMemoryRefreshTokenRepo()
	revRepo := newFakeRevocationRepo()
	repo.denylisted = func(jti string) bool { return revRepo.exists[jti] }
	svc := NewRefreshTokenService(nil, repo, RefreshTokenServiceOptions{TTL: time.Hour}).
		WithTokenRevocationService(NewTokenRevocationService(nil, revRepo))
	target := uuid.New()
	issued, _ := svc.Issue(ctx, IssueRefreshTokenInput{ClientID: "cli", Subject: target.String(), AccessJTI: "linked-expired"})
	revRepo.insertErr = errors.New("simulated denylist outage")
	_, _ = svc.RevokeAllForUser(ctx, target)
	revRepo.insertErr = nil
	past := time.Now().Add(-time.Minute)
	repo.byID[issued.ID].ExpiresAt = past
	if _, err := svc.RevokeAllForUser(ctx, target); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if revRepo.exists["linked-expired"] {
		t.Error("the retry denylisted the JTI of an expired refresh row")
	}
}
