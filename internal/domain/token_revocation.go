package domain

import "time"

// TokenRevocation is the persistent record of a single revoked
// OAuth access token, keyed by the token's jti. The struct is
// deliberately small: it carries the identity of the revoked
// token, the lifetime over which the revocation must remain
// effective, and a bounded operator-facing metadata blob.
//
// The raw access token is NEVER stored. Only the jti — which is
// already a one-way public identifier embedded in the issued JWT —
// is persisted.
//
// ExpiresAt mirrors the revoked token's `exp` claim. The cleanup
// path deletes rows whose ExpiresAt is in the past, so a revoked
// jti is consulted by introspection only while the underlying
// token could still otherwise be considered valid.
type TokenRevocation struct {
	Jti       string
	ExpiresAt time.Time
	Reason    string
	Metadata  map[string]any
	CreatedAt time.Time
}
