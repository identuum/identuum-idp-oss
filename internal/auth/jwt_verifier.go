// Package auth hosts OSS-owned authentication primitives that the
// Gin middleware layer (internal/mw) consumes. As of this slice,
// the package exposes a single concrete TokenVerifier backed by
// the OSS KeyRepository.
//
// Identuum signing-algorithm policy at verification time:
//
//   - EdDSA (Ed25519) and ES256 (P-256) are accepted.
//   - RS256, PS*, HS*, and the `none` alg are rejected.
//
// The same policy is enforced by the OSS JWKS publisher
// (internal/server/jwks.go::PublicKeyToJWK), so a token signed with
// a key that exists in the OSS DB will succeed iff that key is
// EdDSA or ES256.
package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/jwtpolicy"
	"github.com/identuum/identuum-idp-oss/internal/lifecycle"
	"github.com/identuum/identuum-idp-oss/internal/repository"
)

// VerifierOptions tunes claim-level validation. Zero values disable
// the corresponding check, except for ExpectedAlgs which falls back
// to {"EdDSA","ES256"}.
type VerifierOptions struct {
	// ExpectedIssuer, when non-empty, requires the iss claim to
	// match exactly. Empty disables issuer validation (useful in
	// tests and in air-gapped deployments).
	ExpectedIssuer string

	// ExpectedAudience, when non-empty, requires the aud claim to
	// contain this value. Empty disables audience validation.
	ExpectedAudience string

	// ExpectedAlgs overrides the default allowed-algorithm set
	// {"EdDSA","ES256"}. RS256 and "none" are ALWAYS rejected even
	// if listed here.
	ExpectedAlgs []string
}

// RepositoryVerifier verifies bearer tokens against the active
// signing keys in a KeyRepository.
type RepositoryVerifier struct {
	repo repository.KeyRepository
	opts VerifierOptions
}

// NewRepositoryVerifier returns a TokenVerifier backed by repo.
// opts.ExpectedAlgs defaults to {"EdDSA","ES256"} when empty.
func NewRepositoryVerifier(report *lifecycle.StartupReport, repo repository.KeyRepository, opts VerifierOptions) *RepositoryVerifier {
	if repo == nil {
		report.Fatal("NewRepositoryVerifier", "auth: NewRepositoryVerifier requires a non-nil KeyRepository")
	}
	if len(opts.ExpectedAlgs) == 0 {
		opts.ExpectedAlgs = []string{"EdDSA", "ES256"}
	}
	return &RepositoryVerifier{repo: repo, opts: opts}
}

// errTokenInvalid is the single error every verification failure
// returns. The bearer middleware ignores the message and surfaces a
// generic 401 — callers do not learn whether their token was
// expired, malformed, signed with the wrong key, or carried bad
// claims.
var errTokenInvalid = errors.New("auth: token invalid")

// VerifyBearerToken parses, signature-verifies, and claim-validates
// rawToken. Returns a *domain.Principal on success or
// errTokenInvalid on any failure.
func (v *RepositoryVerifier) VerifyBearerToken(ctx context.Context, rawToken string) (*domain.Principal, error) {
	if rawToken == "" {
		return nil, errTokenInvalid
	}

	keys, err := v.repo.GetActiveSigningKeys(ctx)
	if err != nil {
		// AUTH-503: the key STORE failed — the token was not judged. Callers
		// answer 503, never the invalid-token 401.
		return nil, domain.AuthStoreUnavailable("signing-keys", err)
	}
	// Build a kid → public key lookup of OSS-supported algorithms.
	type keyEntry struct {
		alg string
		pub any
	}
	byKID := make(map[string]keyEntry, len(keys))
	for _, k := range keys {
		alg := string(k.Algorithm)
		if !v.algAllowed(alg) {
			continue
		}
		pub, err := parsePublicKeyPEM(k.PublicKey)
		if err != nil {
			continue
		}
		byKID[k.KID] = keyEntry{alg: alg, pub: pub}
	}
	if len(byKID) == 0 {
		return nil, errTokenInvalid
	}

	// Shared parse policy (parser options + alg=none/empty + non-allowlisted-alg
	// + kid rejection), parameterized with the LOCAL allowlist (v.opts.ExpectedAlgs,
	// via v.algAllowed which ALSO hard-rejects RS256/PS*/HS* regardless of the
	// configured set) and local-key resolution. resolveKey does the byKID lookup
	// and the alg↔key binding (rejecting "kid says EdDSA, token says ES256"
	// splits) so a malicious token cannot select a verification strategy other
	// than the one its kid maps to. iss/aud stay below.
	claims, err := jwtpolicy.Parse(
		rawToken,
		v.opts.ExpectedAlgs,
		v.algAllowed,
		func(kid, alg string) (any, error) {
			entry, ok := byKID[kid]
			if !ok {
				return nil, errTokenInvalid
			}
			if entry.alg != alg {
				return nil, errTokenInvalid
			}
			return entry.pub, nil
		},
		// LOCAL tokens are minted by our own signing key and ALWAYS carry exp
		// (token_service / user_token_service). Require exp as defense-in-depth
		// so a never-expiring bearer token is rejected regardless of source. sub
		// is NOT required here: claimsToPrincipal deliberately falls back to
		// user_id/org_id for monolith/M2M tokens (unlike the upstream path).
		jwtpolicy.Required{Expiration: true},
	)
	if err != nil {
		return nil, errTokenInvalid
	}

	// Manual issuer / audience checks because golang-jwt's
	// WithIssuer / WithAudience options are present but we want
	// the silent-fail shape (single sentinel).
	if v.opts.ExpectedIssuer != "" {
		iss, _ := claims["iss"].(string)
		if iss != v.opts.ExpectedIssuer {
			return nil, errTokenInvalid
		}
	}
	if v.opts.ExpectedAudience != "" {
		if !audienceContains(claims["aud"], v.opts.ExpectedAudience) {
			return nil, errTokenInvalid
		}
	}

	return claimsToPrincipal(claims)
}

// algAllowed returns true if alg is in ExpectedAlgs AND is not one
// of the always-banned algorithms.
func (v *RepositoryVerifier) algAllowed(alg string) bool {
	switch alg {
	case "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "HS256", "HS384", "HS512", "none", "":
		return false
	}
	for _, a := range v.opts.ExpectedAlgs {
		if a == alg {
			return true
		}
	}
	return false
}

func parsePublicKeyPEM(s string) (any, error) {
	block, _ := pem.Decode([]byte(s))
	if block == nil {
		return nil, fmt.Errorf("no PEM block")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	switch pub.(type) {
	case ed25519.PublicKey, *ecdsa.PublicKey:
		return pub, nil
	default:
		return nil, fmt.Errorf("unsupported public key type %T", pub)
	}
}

func audienceContains(audClaim any, want string) bool {
	switch v := audClaim.(type) {
	case string:
		return v == want
	case []any:
		for _, e := range v {
			if s, ok := e.(string); ok && s == want {
				return true
			}
		}
	case []string:
		for _, s := range v {
			if s == want {
				return true
			}
		}
	}
	return false
}

func claimsToPrincipal(claims jwt.MapClaims) (*domain.Principal, error) {
	p := &domain.Principal{}

	if sub, _ := claims["sub"].(string); sub != "" {
		// Sub is captured INDEPENDENTLY of the uuid parse below. A `sub` that
		// is not a uuid still has to survive: it is the identifier a
		// subject-keyed resolver looks up, and dropping it there is exactly
		// the drift CONF-11 fixes. The uuid parse is a separate, best-effort
		// convenience for the internal UserID.
		p.Sub = sub
		if id, err := uuid.Parse(sub); err == nil {
			p.UserID = id
		}
	}
	// Extension claims used by the monolith. Either explicit names
	// or the OIDC "sub"/"email"/"role" trio.
	//
	// This overwrites UserID but MUST NOT touch Sub: `user_id` is an internal
	// uuid, not the token's subject, and conflating them is what let the
	// bearer path resolve a different principal than userinfo did (CONF-11).
	if v, ok := claims["user_id"].(string); ok && v != "" {
		if id, err := uuid.Parse(v); err == nil {
			p.UserID = id
		}
	}
	if v, ok := claims["org_id"].(string); ok && v != "" {
		if id, err := uuid.Parse(v); err == nil {
			p.OrganizationID = id
		}
	} else if v, ok := claims["organization_id"].(string); ok && v != "" {
		if id, err := uuid.Parse(v); err == nil {
			p.OrganizationID = id
		}
	}
	if v, ok := claims["email"].(string); ok {
		p.Email = v
	}
	if v, ok := claims["role"].(string); ok && v != "" {
		p.Role = domain.UserRole(v)
	}
	if v, ok := claims["scope"].(string); ok {
		p.Scope = v
	}
	if v, ok := claims["client_id"].(string); ok {
		p.ClientID = v
	}
	if v, ok := claims["session_id"].(string); ok && v != "" {
		if id, err := uuid.Parse(v); err == nil {
			p.SessionID = id
		}
	}
	// Retain the jti so the bearer path can enforce RFC 7009 per-token
	// revocation on EVERY token — including M2M / service-account tokens
	// that carry no session_id (P0-6). Previously dropped here.
	if v, ok := claims["jti"].(string); ok {
		p.TokenID = v
	}
	return p, nil
}
