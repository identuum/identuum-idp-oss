package domain

import (
	"time"

	"github.com/google/uuid"
)

// RefreshTokenKind disambiguates the kind of caller a refresh
// token is bound to. The OSS slice ships only OAuthRefreshToken
// for OAuth-client / API-resource issuance; future slices may
// add session-bound refresh-token kinds without changing the
// table shape.
type RefreshTokenKind string

const (
	// RefreshTokenKindOAuthClient is the default kind issued to
	// confidential OAuth clients authenticated via Basic / Post /
	// private_key_jwt.
	RefreshTokenKindOAuthClient RefreshTokenKind = "oauth_client"
	// RefreshTokenKindAPIResource is reserved for tokens issued
	// against an api_resource caller — same wire shape, distinct
	// metadata.
	RefreshTokenKindAPIResource RefreshTokenKind = "api_resource"
)

// RefreshToken is the persistent record of one issued refresh
// token. The struct deliberately carries NO raw token bytes —
// only the SHA-256 hex digest of the validator side of the
// selector/validator split. The wire token (selector.validator)
// is computable once at issuance time via tools.GenerateSecureRefreshToken
// and is returned to the caller exactly once.
//
// AccessJTI is the jti of the access token most recently minted
// against this refresh row. When operators revoke the refresh
// token via /api/v1/oauth/revoke the OSS handler ALSO plants a
// revocation row for that jti so subsequent introspection
// reflects the change immediately.
type RefreshToken struct {
	ID            uuid.UUID
	ValidatorHash string
	ClientID      string
	ClientKind    RefreshTokenKind
	Subject       string
	Scope         string
	Audience      string
	ExpiresAt     time.Time
	RevokedAt     *time.Time
	ReplacedBy    *uuid.UUID
	AccessJTI     string
	CreatedAt     time.Time
	LastUsedAt    *time.Time
	Metadata      map[string]any
	// FamilyID groups this token with its entire rotation lineage
	// (RFC 9700 §4.13.2). The initial grant seeds a new UUIDv7 family
	// (rendered as its string form); each rotation inherits the
	// consumed parent's FamilyID. Empty only for legacy (pre-migration)
	// rows, which fall back to subject-wide revocation on reuse. Held
	// as a string to match the selector/validator model; the pgx layer
	// maps it to the nullable family_id UUID column.
	FamilyID string
}

// Active reports whether the row may still be consumed: not
// revoked AND not past expiry. The repository surface uses the
// caller-supplied "now" so a fake clock can drive tests.
func (r *RefreshToken) Active(now time.Time) bool {
	if r == nil {
		return false
	}
	if r.RevokedAt != nil {
		return false
	}
	if r.ExpiresAt.IsZero() {
		return false
	}
	if !r.ExpiresAt.After(now) {
		return false
	}
	return true
}
