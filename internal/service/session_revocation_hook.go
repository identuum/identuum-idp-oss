package service

import (
	"context"
	"sync"

	"github.com/google/uuid"
)

// SessionRevoker is the OSS-owned seam consumed by RBAC
// privilege-demotion mutations. Implementations are expected to
// invalidate live sessions / refresh tokens / scope caches for the
// listed user(s) so a demoted privilege no longer round-trips with
// the next request.
//
// Policy decisions baked into the seam:
//
//   - Errors are NEVER fatal to the RBAC mutation. The monolith's
//     §2.8 policy is warn-and-continue: the mutation always
//     succeeds; stale scopes expire naturally at token TTL. OSS
//     mirrors that policy exactly. Callers that want fail-fast
//     semantics should layer it inside their SessionRevoker
//     implementation.
//   - The Reason string is a stable, short identifier
//     ("rbac_role_deleted", "rbac_role_scope_removed",
//     "rbac_role_unassigned"). It is NEVER a user-controlled
//     value; OSS callers pass a fixed literal.
//   - The Metadata map carries safe auxiliary context (role id,
//     scope name, organization id). It MUST NOT contain plaintext
//     tokens, session ids, license payloads, bearer claims, MFA
//     secrets, or password material — this is enforced by
//     callers, not by the type.
type SessionRevoker interface {
	RevokeUserSessions(ctx context.Context, userID uuid.UUID, reason string, metadata map[string]any) error
}

// NoopSessionRevoker is the default OSS implementation. It records
// the call (so a CE composition that wraps it can still observe
// what was invoked), but it does not perform any I/O. Safe to use
// as the default in unit tests and in any OSS build that has not
// yet wired a real session store.
type NoopSessionRevoker struct{}

// RevokeUserSessions is the no-op implementation.
func (NoopSessionRevoker) RevokeUserSessions(_ context.Context, _ uuid.UUID, _ string, _ map[string]any) error {
	return nil
}

// RecorderSessionRevoker captures every call in a slice. Suited
// for tests that need to assert "the RBAC service called the
// revoker for these users in this order". Safe for concurrent
// RevokeUserSessions calls.
type RecorderSessionRevoker struct {
	mu    sync.Mutex
	calls []SessionRevokeCall
	// Err, when non-nil, is returned from every RevokeUserSessions
	// call so a test can pin the documented warn-and-continue
	// policy (the caller MUST swallow the error).
	Err error
}

// SessionRevokeCall records one invocation of RevokeUserSessions.
type SessionRevokeCall struct {
	UserID   uuid.UUID
	Reason   string
	Metadata map[string]any
}

// RevokeUserSessions records the invocation and returns Err (or
// nil).
func (r *RecorderSessionRevoker) RevokeUserSessions(_ context.Context, userID uuid.UUID, reason string, metadata map[string]any) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	copied := make(map[string]any, len(metadata))
	for k, v := range metadata {
		copied[k] = v
	}
	r.calls = append(r.calls, SessionRevokeCall{UserID: userID, Reason: reason, Metadata: copied})
	return r.Err
}

// Calls returns a copy of every recorded invocation, in order.
func (r *RecorderSessionRevoker) Calls() []SessionRevokeCall {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]SessionRevokeCall, len(r.calls))
	copy(out, r.calls)
	return out
}

// Reset clears the recorded calls.
func (r *RecorderSessionRevoker) Reset() {
	r.mu.Lock()
	r.calls = nil
	r.mu.Unlock()
}

// Compile-time interface assertions.
var _ SessionRevoker = NoopSessionRevoker{}
var _ SessionRevoker = (*RecorderSessionRevoker)(nil)
