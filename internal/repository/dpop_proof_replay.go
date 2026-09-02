package repository

import (
	"context"
	"time"
)

// DPoPProofReplayRepository records DPoP proof identifiers (RFC 9449
// §11.1 replay protection) for the token endpoint. Rows are keyed by the
// proof key's RFC 7638 thumbprint and the SHA-256 hex of the proof jti —
// the raw jti is never stored. This is a SEPARATE store from the OAuth
// client-assertion replay table: the two identifier spaces are never
// conflated.
type DPoPProofReplayRepository interface {
	// Insert records (jkt, jtiHash). firstUse is true when THIS call
	// created the row and false when it already existed (a replay). Any
	// error is a store failure — the caller answers unavailability, never
	// a verdict.
	Insert(ctx context.Context, jkt, jtiHash string, expiresAt time.Time) (firstUse bool, err error)

	// DeleteExpiredBefore prunes rows whose expires_at < cutoff.
	DeleteExpiredBefore(ctx context.Context, cutoff time.Time) (int64, error)
}
