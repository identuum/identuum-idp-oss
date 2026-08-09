package repository

import (
	"context"
	"time"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// TokenRevocationRepository persists revoked-jti rows that drive
// the OSS /api/v1/oauth/revoke + /api/v1/oauth/introspection pair.
//
// Insert is idempotent: revoking the same jti twice MUST NOT
// surface a "duplicate" error to callers — the wire contract for
// RFC 7009 §2.2 is unconditional 200, so the repository layer
// absorbs the conflict.
//
// Exists is the constant-time check called on every introspection.
// It must be cheap and return (false, nil) for unknown jtis.
//
// DeleteExpiredBefore removes rows whose ExpiresAt is at or before
// the supplied cutoff. Returns the number of deleted rows for
// operator observability.
type TokenRevocationRepository interface {
	Insert(ctx context.Context, r *domain.TokenRevocation) error
	Exists(ctx context.Context, jti string) (bool, error)
	DeleteExpiredBefore(ctx context.Context, cutoff time.Time) (int64, error)
}
