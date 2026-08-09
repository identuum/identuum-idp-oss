// Package jwtpolicy holds the ONE shared JWT parse policy used by every OSS
// path that verifies a JWT against a set of signing keys: the OSS access-token
// verifier (internal/auth.RepositoryVerifier.VerifyBearerToken, LOCAL tokens)
// and the upstream ID-token validator
// (internal/service.OIDCCallbackService.validateIDToken, UPSTREAM tokens).
//
// It exists so the genuinely-identical parse skeleton — parser options, the
// alg=none/empty rejection, the non-allowlisted-alg rejection, and the kid
// requirement — lives in ONE place and cannot DRIFT between the two callers.
//
// It deliberately does NOT own:
//   - the alg ALLOWLIST: each caller passes its own (asymmetric-only, but
//     DIFFERENT sets — the upstream path accepts RS256 for Google/Entra, the
//     local path hard-rejects it);
//   - the alg PREDICATE: passed separately from the allowlist so each caller
//     keeps its own defensive switch (the local verifier hard-rejects RS256
//     even if it were misconfigured into its list — a list-only check would
//     silently lose that);
//   - the KEY SOURCE / alg↔key binding: local KeyRepository vs provider JWKS
//     by kid, supplied as resolveKey;
//   - the iss/aud/nonce checks and the return shape (raw claims vs principal).
//
// Keeping those with the callers is what makes this extraction strictly
// behavior-preserving: only the shared skeleton is centralized.
package jwtpolicy

import (
	"errors"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// ErrParse is the single opaque failure returned for ANY parse/policy failure
// (bad/empty/none alg, non-allowlisted alg, missing kid, key-resolution
// failure, or a signature/exp/nbf/iat failure). Callers map it to their own
// sentinel; the specific reason is never surfaced — the silent-fail shape both
// original call sites used.
var ErrParse = errors.New("jwtpolicy: token failed parse policy")

// Required declares which registered claims MUST be present, not merely
// validated-if-present. golang-jwt validates exp/nbf/iat ONLY when they appear
// and never checks sub, so a token that simply OMITS them would otherwise pass.
// Each caller states its own policy here — parameterized exactly like
// allowedMethods/algAllowed (see the package doc), NOT forced into one shared
// value — because the two callers' threat models differ:
//
//   - the UPSTREAM ID-token path requires BOTH: the token comes from a
//     third-party provider an attacker may influence, so a missing exp
//     (never-expiring) or missing/empty sub (subject-less / colliding identity)
//     must be rejected;
//   - the LOCAL bearer path requires exp (defense-in-depth against a
//     never-expiring token) but not sub, preserving the verifier's deliberate
//     user_id/org_id subject fallback for monolith/M2M tokens.
type Required struct {
	// Expiration, when true, adds jwt.WithExpirationRequired(): a token with no
	// exp claim is rejected instead of treated as non-expiring.
	Expiration bool
	// Subject, when true, rejects a token whose sub claim is absent or an empty
	// string.
	Subject bool
}

// Parse enforces the shared parse policy and returns the validated claims.
//
//   - The parser is restricted to allowedMethods (jwt.WithValidMethods) and
//     validates iat (jwt.WithIssuedAt) — exactly as both call sites did.
//   - The keyFunc rejects alg=="" and alg=="none" (case-insensitive), rejects
//     any alg for which algAllowed returns false, requires a non-empty kid,
//     THEN delegates key lookup (and any alg↔key binding) to resolveKey.
//   - Signature + exp/nbf/iat are enforced by the parser; required.Expiration
//     additionally makes a MISSING exp a failure, and required.Subject rejects
//     an absent/empty sub.
//
// iss / aud / nonce and the return shape are the CALLER's responsibility. On
// any failure Parse returns (nil, ErrParse).
//
// allowedMethods and algAllowed are BOTH supplied and are NOT derived from
// each other on purpose (see the package doc): the local verifier's predicate
// hard-rejects RS256 regardless of its configured list.
func Parse(
	rawToken string,
	allowedMethods []string,
	algAllowed func(alg string) bool,
	resolveKey func(kid, alg string) (any, error),
	required Required,
) (jwt.MapClaims, error) {
	keyFunc := func(t *jwt.Token) (any, error) {
		alg, _ := t.Header["alg"].(string)
		if alg == "" || strings.EqualFold(alg, "none") || !algAllowed(alg) {
			return nil, ErrParse
		}
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, ErrParse
		}
		return resolveKey(kid, alg)
	}

	claims := jwt.MapClaims{}
	opts := []jwt.ParserOption{
		jwt.WithValidMethods(allowedMethods),
		jwt.WithIssuedAt(),
	}
	if required.Expiration {
		opts = append(opts, jwt.WithExpirationRequired())
	}
	parser := jwt.NewParser(opts...)
	tok, err := parser.ParseWithClaims(rawToken, claims, keyFunc)
	if err != nil || tok == nil || !tok.Valid {
		return nil, ErrParse
	}
	if required.Subject {
		if sub, _ := claims["sub"].(string); sub == "" {
			return nil, ErrParse
		}
	}
	return claims, nil
}
