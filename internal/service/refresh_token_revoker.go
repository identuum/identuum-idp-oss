package service

import (
	"context"
	"sync"

	"github.com/google/uuid"
)

// NoopRefreshTokenRevoker is the safe default for deployments that
// have not yet wired a refresh-token store. RevokeAllForUser
// always returns (0, nil) without touching any persistence.
//
// Concurrency: zero state, safe across goroutines.
type NoopRefreshTokenRevoker struct{}

// RevokeAllForUser implements UserRefreshTokenRevoker as a no-op.
func (NoopRefreshTokenRevoker) RevokeAllForUser(_ context.Context, _ uuid.UUID) (int64, error) {
	return 0, nil
}

// RefreshTokenRevokeCall records one invocation of
// RecorderRefreshTokenRevoker.RevokeAllForUser.
type RefreshTokenRevokeCall struct {
	UserID uuid.UUID
}

// RecorderRefreshTokenRevoker captures every RevokeAllForUser call
// in a slice. Suited for tests that need to assert "the recovery
// flow fired refresh-token revocation for this user once". Safe
// for concurrent calls.
//
// CountToReturn is the int64 returned from RevokeAllForUser; tests
// pin the audit-emitted count by setting it explicitly. Zero is
// the default so a test that does not care still gets a well-
// defined value.
//
// Err, when non-nil, is returned from every RevokeAllForUser call
// so tests can pin the warn-and-continue policy: callers MUST NOT
// fail the surrounding request on a refresh-token revoke error.
type RecorderRefreshTokenRevoker struct {
	mu            sync.Mutex
	calls         []RefreshTokenRevokeCall
	CountToReturn int64
	Err           error
}

// RevokeAllForUser appends a defensive copy of the call and
// returns (CountToReturn, Err). When Err is non-nil the count is
// still returned so the test can assert that callers do not
// trust the count after an error — but they MAY ignore it
// silently per the documented best-effort semantics.
func (r *RecorderRefreshTokenRevoker) RevokeAllForUser(_ context.Context, userID uuid.UUID) (int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, RefreshTokenRevokeCall{UserID: userID})
	return r.CountToReturn, r.Err
}

// Calls returns a copy of every recorded invocation in order.
func (r *RecorderRefreshTokenRevoker) Calls() []RefreshTokenRevokeCall {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]RefreshTokenRevokeCall, len(r.calls))
	copy(out, r.calls)
	return out
}

// Reset clears the recorded calls.
func (r *RecorderRefreshTokenRevoker) Reset() {
	r.mu.Lock()
	r.calls = nil
	r.mu.Unlock()
}

// Compile-time interface assertions.
var (
	_ UserRefreshTokenRevoker = NoopRefreshTokenRevoker{}
	_ UserRefreshTokenRevoker = (*RecorderRefreshTokenRevoker)(nil)
)
