// Package oidc is the public OSS seam for access-token minting.
// It defines a FORMAT-NEUTRAL token-issuance contract — AccessTokenMinter —
// plus the plain TokenClaims carrier it consumes, so a JWT implementation
// (the OSS user/M2M token flows) and an opaque implementation (the
// identuum-idp-ce overlay) can share ONE issuance engine.
//
// The package deliberately depends on NOTHING in the OSS `internal/` tree:
// TokenClaims is plain data (no jwt.MapClaims, no domain types) and the
// interface is format-neutral, so the OSS leaf boundary holds and both
// editions can build against the same seam. Implementations that need
// signing keys or domain types live in `internal/` and satisfy the
// interface from there.
package oidc

import (
	"context"
	"time"
)

// TokenClaims is the format-neutral claim set an AccessTokenMinter turns
// into a wire token. The typed fields cover the claims every access token
// carries; Extra carries the flow-specific remainder (e.g. org_id, email,
// role, session_id, auth_time, acr, amr) verbatim, so callers can add
// claims without widening this struct. A JWT minter serialises these into
// registered/private JWT claims; an opaque minter may ignore them entirely
// and persist them out-of-band keyed by the returned storeKey.
type TokenClaims struct {
	Issuer    string
	Subject   string
	ClientID  string
	Audience  string
	Scope     string
	IssuedAt  time.Time
	ExpiresAt time.Time
	JTI       string
	ActorType string
	// Extra holds additional claims copied verbatim into the minted
	// token by format implementations that embed claims (e.g. JWT).
	// Values must be JSON-serialisable. Nil is treated as empty.
	Extra map[string]any
}

// AccessTokenMinter converts TokenClaims into a wire token. It returns:
//
//   - wireToken: the value handed to the client (a signed compact JWT for
//     the JWT impl; a random opaque string for the opaque impl).
//   - storeKey:  the value the server persists to later identify/revoke the
//     token (the jti for the JWT impl; a hash of the opaque token for the
//     opaque impl). It need NOT equal any claim.
//
// Implementations MUST NOT log the wire token. The seam is format-neutral:
// the caller builds TokenClaims once and is agnostic to whether the result
// is a JWT or an opaque reference.
type AccessTokenMinter interface {
	Mint(ctx context.Context, claims TokenClaims) (wireToken string, storeKey string, err error)
}
