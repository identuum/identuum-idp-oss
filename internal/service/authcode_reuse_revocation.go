package service

// authcode_reuse_revocation.go — the production AuthCodeReuseRevoker
// (THE-CODE-REUSE-REVOKER).
//
// RFC 6749 §4.1.2: on reuse of an authorization code the server MUST deny
// the request and SHOULD revoke all tokens previously issued based on that
// code. AuthorizationCodeService.Consume detects the replay (P0-1b) and
// fires the AuthCodeReuseRevoker seam; this type is what the seam was
// waiting for. It invents NO new mechanism: the access token goes through
// the same oauth_token_revocations path the RFC 7009 endpoint and the
// refresh-lineage cascade use (TokenRevocationService.RevokeJTI, read
// fail-closed by the bearer middleware and introspection), and the refresh
// token goes through RefreshTokenService's existing family revocation.

import (
	"context"
	"time"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// AuthCodeReuseRevocation revokes what the first exchange of a replayed
// code minted, as recorded on the code row by RecordIssuedTokens.
type AuthCodeReuseRevocation struct {
	tokenRevocations *TokenRevocationService
	refresh          *RefreshTokenService
}

// ReasonAuthorizationCodeReuse is the revocation reason stamped on the
// oauth_token_revocations row when a replayed code revokes an access token.
const ReasonAuthorizationCodeReuse = "authorization_code_reuse"

// NewAuthCodeReuseRevocation composes the revoker. Either dependency may be
// nil; a nil one simply leaves that token kind untouched (a composition
// without a RefreshTokenService never issued a refresh token to revoke).
func NewAuthCodeReuseRevocation(tokenRevocations *TokenRevocationService, refresh *RefreshTokenService) *AuthCodeReuseRevocation {
	return &AuthCodeReuseRevocation{tokenRevocations: tokenRevocations, refresh: refresh}
}

// RevokeForReusedCode implements AuthCodeReuseRevoker. Idempotent: the
// revocation store's insert is ON CONFLICT DO NOTHING and an already-revoked
// refresh family revokes nothing further, so a code replayed N times costs
// N harmless writes. A code row with nothing recorded (legacy, or an
// exchange that failed after consume) revokes nothing. The first error is
// returned; the caller deliberately does not surface it on the wire.
func (r *AuthCodeReuseRevocation) RevokeForReusedCode(ctx context.Context, code *domain.OAuthAuthorizationCode, at time.Time) error {
	if code == nil {
		return nil
	}
	var firstErr error
	if r.tokenRevocations != nil && code.IssuedAccessJTI != "" && code.IssuedAccessExpiresAt != nil {
		if err := r.tokenRevocations.RevokeJTI(ctx, code.IssuedAccessJTI, *code.IssuedAccessExpiresAt, ReasonAuthorizationCodeReuse, map[string]any{
			"reason":    ReasonAuthorizationCodeReuse,
			"client_id": code.ClientID,
		}); err != nil {
			firstErr = err
		}
	}
	if r.refresh != nil && code.IssuedRefreshTokenID != nil {
		if err := r.refresh.RevokeLineageByID(ctx, *code.IssuedRefreshTokenID, at); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
