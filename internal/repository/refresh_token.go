package repository

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// RevokedRefreshTokenAccessJTI is the bounded projection returned
// when a bulk refresh-token revocation also needs to revoke linked
// access-token JTIs. It deliberately excludes raw refresh tokens,
// validator hashes, subjects, session IDs, and other credential
// material.
type RevokedRefreshTokenAccessJTI struct {
	JTI       string
	ExpiresAt time.Time
}

// RefreshTokenRepository persists rows in oauth_refresh_tokens.
//
// Insert plants a fresh row; selector is the row PK so a duplicate
// is a programmer error (UUIDv7 collisions should never happen in
// practice). The implementation MUST surface conflicts as errors,
// NOT silently swallow them.
//
// GetByID is the lookup the consume path runs against the
// caller-supplied selector. Returns (nil, nil) for unknown
// selectors.
//
// MarkRevoked plants a RevokedAt timestamp. Idempotent.
//
// MarkRotated atomically revokes the supplied selector and links
// it to its replacement row. ReplacedBy MUST point at the new
// selector. Used by RefreshTokenService.Consume during rotation.
//
// P3-1: "atomically" is now TRUE of the SQL and not merely of this
// sentence. The statement carries `AND revoked_at IS NULL`, so exactly
// one of N concurrent rotations of the same row can win. The losers get
// ErrRefreshAlreadyRotated, which Consume treats as reuse — because that
// is what it is: a second presentation of a refresh token that has
// already been exchanged.
//
// SetAccessJTI updates the row's access_jti column so subsequent
// revoke calls can cascade onto the issued access token.
//
// RevokeAllBySubject sets revoked_at on every active row whose
// subject column matches. The subject is whatever was supplied at
// issue time — for OSS-issued user-bound refresh tokens this is
// the target user's UUID string. Already-revoked rows are skipped
// at the SQL layer so the call is idempotent, and the returned
// int64 is the count of rows actually mutated (newly revoked).
// An empty subject is a no-op that returns (0, nil) so callers do
// not need to special-case it. Non-revocation columns
// (subject, client_id, scope, audience, expires_at, replaced_by,
// access_jti, metadata) are preserved.
//
// RevokeByFamily sets revoked_at on every ACTIVE row (not revoked,
// not expired) sharing family_id. It is the family-scoped analogue
// of RevokeAllBySubject used by the automated refresh-reuse response
// (RFC 9700 §4.13.2): a replayed rotated-away token revokes only its
// own rotation lineage rather than the subject's every token. Empty
// familyID is a no-op that returns (0, nil) so legacy NULL-family
// rows never match. Returns the count of rows actually mutated.
//
// DeleteExpiredBefore removes rows whose ExpiresAt has passed.
// Returns the deleted-row count for observability.
// ErrRefreshAlreadyRotated is returned by MarkRotated when the row was already
// revoked or rotated by a concurrent request — the compare-and-set matched zero
// rows. It is a RACE OUTCOME, not a storage failure, and the caller must treat
// it as token reuse rather than as an internal error.
var ErrRefreshAlreadyRotated = errors.New("repository: refresh token already rotated")

type RefreshTokenRepository interface {
	Insert(ctx context.Context, r *domain.RefreshToken) error
	GetByID(ctx context.Context, id uuid.UUID) (*domain.RefreshToken, error)
	MarkRevoked(ctx context.Context, id uuid.UUID, at time.Time) error
	MarkRotated(ctx context.Context, oldID uuid.UUID, newID uuid.UUID, at time.Time) error
	SetAccessJTI(ctx context.Context, id uuid.UUID, accessJTI string, at time.Time) error
	RevokeAllBySubject(ctx context.Context, subject string, at time.Time) (int64, error)
	RevokeByFamily(ctx context.Context, familyID string, at time.Time) (int64, error)
	DeleteExpiredBefore(ctx context.Context, cutoff time.Time) (int64, error)
}

// RefreshTokenAccessJTIRevocationRepository is an optional extension
// implemented by repositories that can atomically bulk-revoke refresh-token
// rows and return the access JTIs linked to the rows that were newly
// revoked, so the caller can cascade the revocation onto those access
// tokens' denylist.
//
// RevokeAllBySubjectReturningAccessJTIs is the subject-wide variant used by
// the deliberate account-security paths (RevokeAllForUser).
//
// RevokeByFamilyReturningAccessJTIs is the family-scoped variant used by the
// automated refresh-reuse response (RFC 9700 §4.13.2): it revokes only the
// compromised rotation lineage's ACTIVE rows and returns their access JTIs.
// Empty familyID is a no-op returning (0, nil, nil).
type RefreshTokenAccessJTIRevocationRepository interface {
	RevokeAllBySubjectReturningAccessJTIs(ctx context.Context, subject string, at time.Time) (int64, []RevokedRefreshTokenAccessJTI, error)
	RevokeByFamilyReturningAccessJTIs(ctx context.Context, familyID string, at time.Time) (int64, []RevokedRefreshTokenAccessJTI, error)
}
