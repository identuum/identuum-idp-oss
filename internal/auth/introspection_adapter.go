package auth

import (
	"context"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// IntrospectToken runs the same verification chain as
// VerifyBearerToken (signature, alg-allowlist, issuer + audience
// claim checks, expiry via jwt.NewParser standard validators)
// but additionally surfaces the RFC 7662 standard claims for the
// IntrospectionService.
//
// Any verification failure — bad signature, banned alg, expired,
// wrong issuer/audience, malformed JWT — returns errTokenInvalid
// unchanged. The IntrospectionService maps any error to
// `{"active":false}` per RFC 7662 §2.2: an introspection
// endpoint MUST NOT distinguish failure reasons to the caller.
//
// The raw token string is never written to a returned struct
// field, never logged, and never echoed in the error message.
func (v *RepositoryVerifier) IntrospectToken(ctx context.Context, rawToken string) (*service.IntrospectionClaims, error) {
	if rawToken == "" {
		return nil, errTokenInvalid
	}
	keys, err := v.repo.GetActiveSigningKeys(ctx)
	if err != nil {
		// AUTH-503: key STORE failure, not a token verdict (see jwt_verifier.go).
		return nil, domain.AuthStoreUnavailable("signing-keys", err)
	}
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

	keyFunc := func(t *jwt.Token) (any, error) {
		alg, _ := t.Header["alg"].(string)
		if alg == "" || alg == "none" {
			return nil, errTokenInvalid
		}
		if !v.algAllowed(alg) {
			return nil, errTokenInvalid
		}
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, errTokenInvalid
		}
		entry, ok := byKID[kid]
		if !ok {
			return nil, errTokenInvalid
		}
		if entry.alg != alg {
			return nil, errTokenInvalid
		}
		return entry.pub, nil
	}

	claims := jwt.MapClaims{}
	parser := jwt.NewParser(
		jwt.WithValidMethods(v.opts.ExpectedAlgs),
		jwt.WithIssuedAt(),
	)
	tok, err := parser.ParseWithClaims(rawToken, claims, keyFunc)
	if err != nil || tok == nil || !tok.Valid {
		return nil, errTokenInvalid
	}

	if v.opts.ExpectedIssuer != "" {
		iss, _ := claims["iss"].(string)
		if iss != v.opts.ExpectedIssuer {
			return nil, errTokenInvalid
		}
	}
	// AYGHU-4: a participant token (signed claim set carrying BOTH
	// agent_communication and cnf) is addressed to its relay audience, not
	// to this issuer; the introspection service judges its aud against the
	// stored authorization (fail closed). Every other token keeps the
	// issuer-audience equality. The bearer path (VerifyBearerToken) is
	// untouched: a relay token is never admitted to this server's own API.
	_, hasAgentComm := claims["agent_communication"]
	_, hasCnf := claims["cnf"]
	if v.opts.ExpectedAudience != "" && !(hasAgentComm && hasCnf) {
		if !audienceContains(claims["aud"], v.opts.ExpectedAudience) {
			return nil, errTokenInvalid
		}
	}

	return claimsToIntrospection(claims), nil
}

// claimsToIntrospection mirrors claimsToPrincipal's field set but
// additionally surfaces the RFC 7662 standard claims.
// introspectionExtraClaims are the non-registered claims introspection
// judges beyond the standard set (AYGHU-4 participant tokens). They are
// copied from the SIGNED claim set only.
var introspectionExtraClaims = []string{"cnf", "agent_communication", "authorization_details"}

func claimsToIntrospection(claims jwt.MapClaims) *service.IntrospectionClaims {
	out := &service.IntrospectionClaims{}
	for _, k := range introspectionExtraClaims {
		if v, ok := claims[k]; ok {
			if out.Extra == nil {
				out.Extra = map[string]any{}
			}
			out.Extra[k] = v
		}
	}
	if sub, _ := claims["sub"].(string); sub != "" {
		out.Sub = sub
		if id, err := uuid.Parse(sub); err == nil {
			out.UserID = id
		}
	}
	if v, ok := claims["user_id"].(string); ok && v != "" {
		if id, err := uuid.Parse(v); err == nil {
			out.UserID = id
		}
	}
	// Mirrors claimsToPrincipal's session_id mapping (jwt_verifier.go) so the
	// introspection path can apply the same liveness verdict as the bearer
	// path (CONF-10). Absent/unparseable leaves it zero, which the consumer
	// reads as "no session" and exempts (M2M).
	if v, ok := claims["session_id"].(string); ok && v != "" {
		if id, err := uuid.Parse(v); err == nil {
			out.SessionID = id
		}
	}
	if v, ok := claims["org_id"].(string); ok && v != "" {
		if id, err := uuid.Parse(v); err == nil {
			out.OrgID = id
		}
	} else if v, ok := claims["organization_id"].(string); ok && v != "" {
		if id, err := uuid.Parse(v); err == nil {
			out.OrgID = id
		}
	}
	if v, ok := claims["email"].(string); ok {
		out.Email = v
	}
	if v, ok := claims["role"].(string); ok && v != "" {
		out.Role = v
	}
	if v, ok := claims["actor_type"].(string); ok && v != "" {
		out.ActorType = v
	}
	if v, ok := claims["scope"].(string); ok {
		out.Scope = v
	}
	// THE-CLAIMS-PARAMETER: consented userinfo claim names ride on the
	// access token as a JSON array of strings.
	if arr, ok := claims["userinfo_claims"].([]any); ok {
		for _, item := range arr {
			if s, ok := item.(string); ok && s != "" {
				out.UserInfoClaims = append(out.UserInfoClaims, s)
			}
		}
	}
	if v, ok := claims["client_id"].(string); ok {
		out.ClientID = v
	}
	if v, ok := claims["iss"].(string); ok {
		out.Iss = v
	}
	out.Aud = audienceClaimToSlice(claims["aud"])
	if v, ok := claims["jti"].(string); ok {
		out.Jti = v
	}
	if v, ok := claims["exp"].(float64); ok {
		out.Exp = int64(v)
	}
	if v, ok := claims["iat"].(float64); ok {
		out.Iat = int64(v)
	}
	if v, ok := claims["nbf"].(float64); ok {
		out.Nbf = int64(v)
	}
	return out
}

func audienceClaimToSlice(audClaim any) []string {
	switch v := audClaim.(type) {
	case string:
		if v == "" {
			return nil
		}
		return []string{v}
	case []string:
		return append([]string(nil), v...)
	case []any:
		out := make([]string, 0, len(v))
		for _, e := range v {
			if s, ok := e.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		if len(out) == 0 {
			return nil
		}
		return out
	}
	return nil
}

// Compile-time assertion that *RepositoryVerifier satisfies the
// IntrospectionService's verifier contract. Any future change to
// either side breaks at build time here.
var _ service.TokenClaimsVerifier = (*RepositoryVerifier)(nil)
