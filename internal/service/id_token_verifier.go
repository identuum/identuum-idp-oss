// Package service — IDTokenVerifier verifies an OIDC ID token
// issued by THIS deployment. It is the read-side counterpart of
// IDTokenService.Issue and is intended for use as the
// `id_token_hint` parser in the RP-initiated logout flow.
//
// Verification posture (same policy as the existing
// auth.RepositoryVerifier):
//
//   - EdDSA + ES256 accepted.
//   - `none`, HS*, PS*, RS* unconditionally rejected (Identuum's
//     no-RS256-issuance policy is enforced symmetrically on
//     verification of LOCALLY-issued tokens).
//   - The signing key is selected by `kid` from the live OSS
//     KeyRepository's active-key set; an unknown kid is a fatal
//     mismatch.
//   - Issuer claim MUST equal the configured issuer.
//   - `exp` enforced via the standard parser; `nbf` is respected
//     when present.
//
// External-issuer ID tokens are explicitly NOT supported by this
// verifier; the only intended caller is /api/v1/oidc/logout, which
// only ever sees tokens it issued itself. Mirrors the monolith's
// "internal issuer" code path in JWTTokenService.VerifyIDToken
// while leaving the external go-oidc path out of scope for OSS.
package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/lifecycle"
	"github.com/identuum/identuum-idp-oss/internal/repository"
)

// IDTokenVerifier verifies locally-issued ID tokens (the
// `id_token_hint` on /oidc/logout).
type IDTokenVerifier struct {
	keys   repository.KeyRepository
	issuer string
}

// IDTokenVerifierOptions parameterises the verifier. Issuer is
// required.
type IDTokenVerifierOptions struct {
	Issuer string
}

// NewIDTokenVerifier constructs the verifier. keys must be non-nil;
// opts.Issuer must be non-empty.
func NewIDTokenVerifier(report *lifecycle.StartupReport, keys repository.KeyRepository, opts IDTokenVerifierOptions) *IDTokenVerifier {
	if keys == nil {
		report.Fatal("NewIDTokenVerifier", "service: NewIDTokenVerifier requires a non-nil KeyRepository")
	}
	if opts.Issuer == "" {
		report.Fatal("NewIDTokenVerifier", "service: NewIDTokenVerifier requires a non-empty Issuer")
	}
	return &IDTokenVerifier{keys: keys, issuer: opts.Issuer}
}

// VerifiedIDTokenHint is the safe projection returned by Verify.
// It carries only the fields the logout handler needs; raw claims
// + raw token are NEVER retained.
type VerifiedIDTokenHint struct {
	// Subject is the user UUID parsed from `sub` when it parses.
	// Zero on a non-UUID `sub` (e.g. an external token that
	// somehow slipped past — the handler must NOT use Subject in
	// that case).
	Subject uuid.UUID

	// Audience is the verbatim aud claim list (multi-aud tokens
	// land all entries; the handler picks the first match against
	// a registered client_id, mirroring monolith semantics).
	Audience []string

	// SessionID is the user-session UUID parsed from the
	// `session_id` claim when present. Zero when absent — the
	// access-token issuance path stamps it, the ID-token path
	// currently does not, but accepting it here keeps the door
	// open for a future emission.
	SessionID uuid.UUID
}

// Sentinel errors. The wire-side logout handler maps every Verify
// failure to RFC 6749 §5.2 `invalid_request` (HTTP 400) — the
// granular sentinels exist for tests + operator dashboards.
var (
	ErrIDTokenHintMalformed       = errors.New("service: id_token_hint malformed")
	ErrIDTokenHintIssuerMismatch  = errors.New("service: id_token_hint issuer mismatch")
	ErrIDTokenHintExpired         = errors.New("service: id_token_hint expired")
	ErrIDTokenHintSignature       = errors.New("service: id_token_hint signature invalid")
	ErrIDTokenHintUnknownKID      = errors.New("service: id_token_hint unknown kid")
	ErrIDTokenHintBannedAlgorithm = errors.New("service: id_token_hint banned alg")
)

// Verify parses, signature-verifies, and claim-validates the
// supplied id_token_hint. Returns a VerifiedIDTokenHint on success
// or one of the sentinels above on failure.
//
// Verify NEVER logs or retains the raw token. The handler is
// responsible for ensuring the hint does not leak into wire
// responses, audit metadata, or error bodies.
func (v *IDTokenVerifier) Verify(ctx context.Context, raw string) (*VerifiedIDTokenHint, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, ErrIDTokenHintMalformed
	}
	keys, err := v.keys.GetActiveSigningKeys(ctx)
	if err != nil {
		return nil, ErrIDTokenHintSignature
	}
	type keyEntry struct {
		alg string
		pub any
	}
	byKID := make(map[string]keyEntry, len(keys))
	for _, k := range keys {
		alg := string(k.Algorithm)
		if !idTokenAlgAllowed(alg) {
			continue
		}
		pub, err := parsePEMPublicKey(k.PublicKey)
		if err != nil {
			continue
		}
		byKID[k.KID] = keyEntry{alg: alg, pub: pub}
	}
	if len(byKID) == 0 {
		return nil, ErrIDTokenHintSignature
	}

	keyFunc := func(t *jwt.Token) (any, error) {
		alg, _ := t.Header["alg"].(string)
		if !idTokenAlgAllowed(alg) {
			return nil, ErrIDTokenHintBannedAlgorithm
		}
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, ErrIDTokenHintUnknownKID
		}
		entry, ok := byKID[kid]
		if !ok {
			return nil, ErrIDTokenHintUnknownKID
		}
		if entry.alg != alg {
			return nil, ErrIDTokenHintBannedAlgorithm
		}
		return entry.pub, nil
	}

	claims := jwt.MapClaims{}
	parser := jwt.NewParser(jwt.WithValidMethods([]string{"EdDSA", "ES256"}))
	tok, err := parser.ParseWithClaims(raw, claims, keyFunc)
	if err != nil || tok == nil || !tok.Valid {
		switch {
		case errors.Is(err, jwt.ErrTokenExpired):
			return nil, ErrIDTokenHintExpired
		case errors.Is(err, jwt.ErrTokenSignatureInvalid):
			return nil, ErrIDTokenHintSignature
		case errors.Is(err, ErrIDTokenHintBannedAlgorithm),
			errors.Is(err, ErrIDTokenHintUnknownKID):
			return nil, err
		}
		return nil, ErrIDTokenHintMalformed
	}

	iss, _ := claims["iss"].(string)
	if iss != v.issuer {
		return nil, ErrIDTokenHintIssuerMismatch
	}

	out := &VerifiedIDTokenHint{
		Audience: extractAudience(claims["aud"]),
	}
	if sub, _ := claims["sub"].(string); sub != "" {
		if id, err := uuid.Parse(sub); err == nil {
			out.Subject = id
		}
	}
	if sid, _ := claims["session_id"].(string); sid != "" {
		if id, err := uuid.Parse(sid); err == nil {
			out.SessionID = id
		}
	}
	return out, nil
}

// idTokenAlgAllowed enforces the OSS issuance posture symmetrically
// on verification: EdDSA + ES256 only.
func idTokenAlgAllowed(alg string) bool {
	switch alg {
	case "EdDSA", "ES256":
		return true
	}
	return false
}

func parsePEMPublicKey(s string) (any, error) {
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

func extractAudience(v any) []string {
	switch t := v.(type) {
	case string:
		if t == "" {
			return nil
		}
		return []string{t}
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			if s, ok := e.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return t
	}
	return nil
}

// Domain-helper keep-alives so the imports linter does not flap.
var (
	_ = domain.KeyAlgorithmEdDSA
)
