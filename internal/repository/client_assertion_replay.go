package repository

import (
	"context"
	"time"
)

// ClientAssertionReplayRepository persists (client_id, jti_hash)
// pairs that drive RFC 7523 / OIDC Core §9 replay detection on
// the OSS private_key_jwt path.
//
// Insert is the load-bearing method: implementations MUST treat
// a primary-key conflict on (client_id, jti_hash) as a no-op
// (i.e. INSERT … ON CONFLICT DO NOTHING) and report it via the
// firstUse return. A true firstUse means the row was new; a false
// firstUse means the same (client_id, jti_hash) was already
// present. Repository errors MUST be surfaced to the caller so
// the service layer can fail-CLOSED.
//
// DeleteExpiredBefore prunes rows whose expires_at is at or
// before the supplied cutoff. Returns the deleted-row count for
// observability.
type ClientAssertionReplayRepository interface {
	Insert(ctx context.Context, clientID, jtiHash string, expiresAt time.Time) (firstUse bool, err error)
	DeleteExpiredBefore(ctx context.Context, cutoff time.Time) (int64, error)
}
