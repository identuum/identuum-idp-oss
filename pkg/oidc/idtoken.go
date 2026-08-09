package oidc

import (
	"context"
	"time"
)

// IDTokenClaims is the format-neutral claim set an IDTokenIssuer turns into a
// signed OIDC ID token. Unlike an access token, an ID token has no storeKey
// and a distinct, deliberately-auditable claim contract. The typed fields
// cover the claims every ID token carries; Extra carries the flow-specific
// remainder (auth_time, acr, amr, email, email_verified, and future claims
// such as sid) verbatim, so callers can add claims without widening this
// struct.
//
// Like the rest of pkg/oidc this is plain data — no jwt.MapClaims, no domain
// types — so both the OSS JWT issuer and the identuum-idp-ce keys-backed
// issuer can implement IDTokenIssuer against the same seam.
type IDTokenClaims struct {
	Issuer    string
	Subject   string
	Audience  string
	Nonce     string
	IssuedAt  time.Time
	ExpiresAt time.Time
	JTI       string
	// Extra holds additional claims copied verbatim into the ID token.
	// Values must be JSON-serialisable. Nil is treated as empty.
	Extra map[string]any
}

// IDTokenIssuer signs IDTokenClaims into a compact OIDC ID token. It returns
// only the token (ID tokens are not persisted, so there is no storeKey).
// Implementations MUST NOT log the token. The seam is format-neutral: the
// caller builds IDTokenClaims once and is agnostic to the signing backend.
type IDTokenIssuer interface {
	IssueIDToken(ctx context.Context, claims IDTokenClaims) (idToken string, err error)
}
