// SubjectResolver is the public OSS seam for use-time principal
// liveness (A-4 Phase 6a). It answers ONE question: is the principal behind
// an already-cryptographically-verified token still allowed to use it, RIGHT
// NOW? Signature, expiry, audience and per-token (jti) revocation are all
// upstream gates and are deliberately NOT this seam's business — by the time
// a resolver runs, the token itself has already been accepted; what remains
// is whether the person or session it points at is still live (session not
// revoked, user not banned/deleted, organization still active).
//
// The seam owns the VERDICT only. The POLICY of which tokens get gated stays
// with the caller — deliberate, because the two editions gate differently:
// the OSS bearer middleware gates session-carrying tokens (M2M tokens are
// exempt, they have no session), while the CE overlay gates by subject at
// userinfo/introspect. Pushing that policy into the seam would force one
// edition's shape onto the other; keeping it out lets both share the verdict
// without sharing the gate.
//
// Like the rest of pkg/oidc, this file depends on NOTHING in the OSS
// `internal/` tree: PrincipalRef is plain data (no domain types, no uuid
// package), so the OSS leaf boundary holds and both editions can build
// against the same seam. Implementations that need session stores or domain
// types live in `internal/` and satisfy the interface from there.

package oidc

import "context"

// PrincipalRef identifies the principal behind a verified token, in the
// format-neutral terms both editions already share on the wire.
type PrincipalRef struct {
	// Subject is the token's `sub` claim, verbatim.
	Subject string
	// SessionID is the canonical uuid string of the user session the token
	// was minted under, empty when the token carries no session (M2M,
	// client-credentials, service-account tokens). Implementations that key
	// liveness on the session parse it; implementations that key on the
	// subject may ignore it.
	SessionID string
}

// SubjectResolver reports whether the principal a verified token points at
// may still use it. Implementations MUST be fail-closed: on any internal
// error they return (false, err) — a principal whose liveness cannot be
// established is never admitted. Callers treat a non-nil error exactly like
// ok == false; the error exists for logging, not for admission.
type SubjectResolver interface {
	ResolveSubject(ctx context.Context, ref PrincipalRef) (bool, error)
}
