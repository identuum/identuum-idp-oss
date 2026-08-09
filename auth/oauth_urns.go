package auth

// OAuth URN constants for the RFC 8693 token-exchange and RFC 7523 jwt-bearer
// wire surfaces, plus the SPIFFE JWT-SVID token-type URN. Centralised so the
// values appear in one place and are imported from here by the live consumers
// (5.2.c token-exchange handler, 5.2.d jwt-bearer handler, SPIFFE federation
// branch).
//
// All constants below are public IETF URN identifiers (RFC 8693, RFC 7523,
// SPIFFE), not credentials. Names contain "Token" / "Grant" because that is
// what the specs call them. Per-line `// #nosec G101` suppressions match the
// precedent at internal/service/secret_watcher.go for env-var key names
// flagged by the same gosec heuristic.

const (
	// URNGrantTypeTokenExchange is the RFC 8693 token-exchange grant_type URN.
	// Consumed by the token-exchange dispatch in
	// internal/handlers/handler_oidc_token.go (5.2.c).
	URNGrantTypeTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange" // #nosec G101 -- public IETF URN per RFC 8693, not a credential

	// URNGrantTypeJWTBearer is the RFC 7523 jwt-bearer grant_type URN.
	// Consumed by the jwt-bearer dispatch in
	// internal/handlers/handler_oidc_token.go (5.2.d).
	URNGrantTypeJWTBearer = "urn:ietf:params:oauth:grant-type:jwt-bearer" // #nosec G101 -- public IETF URN per RFC 7523, not a credential

	// URNTokenTypeAccessToken is the RFC 8693 token-type URN for a generic
	// OAuth access token. Default subject_token_type / issued_token_type on
	// the token-exchange handler.
	URNTokenTypeAccessToken = "urn:ietf:params:oauth:token-type:access_token" // #nosec G101 -- public IETF URN per RFC 8693, not a credential

	// URNTokenTypeIDToken is the RFC 8693 token-type URN for an OIDC ID
	// token. Spec-canonical token-type identifier; surfaced here for
	// completeness.
	URNTokenTypeIDToken = "urn:ietf:params:oauth:token-type:id_token" // #nosec G101 -- public IETF URN per RFC 8693, not a credential

	// URNTokenTypeRefreshToken is the RFC 8693 token-type URN for an OAuth
	// refresh token. Spec-canonical token-type identifier; surfaced here for
	// completeness.
	URNTokenTypeRefreshToken = "urn:ietf:params:oauth:token-type:refresh_token" // #nosec G101 -- public IETF URN per RFC 8693, not a credential

	// URNTokenTypeSAML2 is the RFC 8693 token-type URN for a SAML 2.0
	// assertion. Spec-canonical token-type identifier; surfaced here for
	// completeness. No SAML validation infrastructure exists in identuum-idp
	// today.
	URNTokenTypeSAML2 = "urn:ietf:params:oauth:token-type:saml2" // #nosec G101 -- public IETF URN per RFC 8693, not a credential

	// URNTokenTypeJWTSVID is the SPIFFE JWT-SVID token-type URN, accepted by
	// the token-exchange handler's SPIFFE branch. The SPIFFE handler
	// currently declares it as a function-local const (see
	// internal/handlers/handler_oidc_token.go and
	// internal/handlers/handler_spiffe_token_exchange.go); centralised here
	// for one-stop OAuth-URN reference.
	URNTokenTypeJWTSVID = "urn:ietf:params:oauth:token-type:jwt-svid" // #nosec G101 -- public IETF URN per SPIFFE, not a credential
)
