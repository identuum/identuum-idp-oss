package auth

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// dpopJWTTyp is the required value of the DPoP proof JWS's typ header per
// RFC 9449 §4.2. Verification rejects any proof whose typ header is absent or
// differs from this constant.
const dpopJWTTyp = "dpop+jwt"

// dpopClockSkew bounds how far in the past a DPoP proof's iat claim can be.
// RFC 9449 recommends a small window — most implementations use 60s or less.
// The window applies in both directions; proofs too far in the future are also
// rejected (defends against skewed clocks being used for pre-minted proofs).
const dpopClockSkew = 60 * time.Second

// ErrDPoPInvalid is the sentinel returned when a DPoP proof fails any structural
// or semantic validation. Callers map it to HTTP 401 and MUST NOT surface the
// underlying reason to the presenter (oracle-safety against probing).
var ErrDPoPInvalid = errors.New("dpop: invalid proof")

// DPoPProofClaims is the subset of RFC 9449 §4.2 claims that verification
// consumes. Exposed so callers can enrich audit logs with the jti and key
// thumbprint without re-parsing the proof.
type DPoPProofClaims struct {
	// JTI is a per-proof unique identifier. RFC 9449 requires servers to
	// maintain a short-window replay cache keyed on jti+htm+htu; this
	// package does not implement that cache itself — it returns the jti so
	// the caller (e.g. the /agent/feedback handler) can plug it into its
	// own replay store.
	JTI string
	// HTM is the HTTP method the proof was minted for. Always upper-case
	// per the RFC.
	HTM string
	// HTU is the absolute request URI (scheme + authority + path) without
	// query or fragment.
	HTU string
	// IssuedAt is the proof's iat claim, converted from numeric seconds.
	IssuedAt time.Time
	// JKT is the RFC 7638 JWK SHA-256 thumbprint of the presenter's public
	// key (base64url, no padding). Pinning the presenter is the entire
	// point of DPoP — the caller cross-checks this against an allow-list
	// derived from the bearer's cnf claim or a published JWKS.
	JKT string
}

// VerifyDPoPProof parses and validates a DPoP proof per RFC 9449 §4.3.
//
// Inputs:
//   - proof: the compact-JWS string from the DPoP request header.
//   - method: the actual HTTP method of the request being authenticated.
//     Validated against the proof's htm claim.
//   - uri: the absolute request URI (scheme + authority + path, no query).
//     Validated against the proof's htu claim. Callers are responsible
//     for reconstructing this canonically — stripping query strings,
//     lower-casing the scheme and host.
//   - bearer: the Bearer token the proof is being presented alongside.
//     Used to compute the expected ath (access-token hash) claim.
//   - now: the current time — injected for testability.
//
// On success, returns DPoPProofClaims with the presenter's key thumbprint.
// Any failure — malformed JWS, bad signature, missing claim, mismatched
// htm/htu/ath, stale iat, forbidden alg — returns ErrDPoPInvalid wrapped
// with a developer-facing reason.
//
// Accepted algorithms: EdDSA (Ed25519) and ES256 (ECDSA P-256). All others,
// including "none", RS*, and HS*, are rejected.
func VerifyDPoPProof(proof, method, uri, bearer string, now time.Time) (*DPoPProofClaims, error) {
	if proof == "" {
		return nil, fmt.Errorf("%w: proof is empty", ErrDPoPInvalid)
	}
	if method == "" || uri == "" || bearer == "" {
		return nil, fmt.Errorf("%w: method/uri/bearer required", ErrDPoPInvalid)
	}

	// Parse unverified first to read the header (alg + jwk + typ) before
	// we know which public key to use for signature validation.
	parser := jwt.NewParser(jwt.WithValidMethods([]string{"EdDSA", "ES256"}))
	var raw jwt.MapClaims
	unverified, _, err := parser.ParseUnverified(proof, &raw)
	if err != nil {
		return nil, fmt.Errorf("%w: parse: %v", ErrDPoPInvalid, err)
	}

	// typ header must be "dpop+jwt" — prevents the proof from being a regular
	// JWT minted elsewhere and replayed as a DPoP proof.
	typ, _ := unverified.Header["typ"].(string)
	if typ != dpopJWTTyp {
		return nil, fmt.Errorf("%w: typ header must be %q, got %q", ErrDPoPInvalid, dpopJWTTyp, typ)
	}

	alg, _ := unverified.Header["alg"].(string)
	if alg != "EdDSA" && alg != "ES256" {
		return nil, fmt.Errorf("%w: alg %q not accepted", ErrDPoPInvalid, alg)
	}

	jwkMap, ok := unverified.Header["jwk"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("%w: jwk header missing or malformed", ErrDPoPInvalid)
	}

	pubKey, jkt, err := publicKeyFromJWK(jwkMap, alg)
	if err != nil {
		return nil, fmt.Errorf("%w: jwk->key: %v", ErrDPoPInvalid, err)
	}

	// Full signature verification with the derived public key.
	if _, err := parser.Parse(proof, func(_ *jwt.Token) (interface{}, error) {
		return pubKey, nil
	}); err != nil {
		return nil, fmt.Errorf("%w: signature: %v", ErrDPoPInvalid, err)
	}

	// Claim checks — each returns a distinct reason for logs but the
	// surfaced error is always ErrDPoPInvalid so presenters cannot probe.
	htm, _ := raw["htm"].(string)
	if htm != method {
		return nil, fmt.Errorf("%w: htm mismatch: proof=%q request=%q", ErrDPoPInvalid, htm, method)
	}
	htu, _ := raw["htu"].(string)
	if htu != uri {
		return nil, fmt.Errorf("%w: htu mismatch: proof=%q request=%q", ErrDPoPInvalid, htu, uri)
	}

	// ath binds the proof to a specific bearer. Computed as
	// base64url(sha256(bearer)) per RFC 9449 §4.2.
	ath, _ := raw["ath"].(string)
	expectedAth := base64.RawURLEncoding.EncodeToString(sha256Sum(bearer))
	if subtle.ConstantTimeCompare([]byte(ath), []byte(expectedAth)) != 1 {
		return nil, fmt.Errorf("%w: ath mismatch", ErrDPoPInvalid)
	}

	// iat clock skew: reject if the proof claims to be from the future or
	// more than dpopClockSkew seconds in the past.
	iatFloat, ok := raw["iat"].(float64)
	if !ok {
		return nil, fmt.Errorf("%w: iat missing or non-numeric", ErrDPoPInvalid)
	}
	iat := time.Unix(int64(iatFloat), 0)
	delta := now.Sub(iat)
	if delta < -dpopClockSkew || delta > dpopClockSkew {
		return nil, fmt.Errorf("%w: iat out of skew window (delta=%s)", ErrDPoPInvalid, delta)
	}

	jti, _ := raw["jti"].(string)
	if jti == "" {
		return nil, fmt.Errorf("%w: jti missing", ErrDPoPInvalid)
	}

	return &DPoPProofClaims{
		JTI:      jti,
		HTM:      htm,
		HTU:      htu,
		IssuedAt: iat,
		JKT:      jkt,
	}, nil
}

// sha256Sum returns the SHA-256 digest of s as a byte slice.
func sha256Sum(s string) []byte {
	sum := sha256.Sum256([]byte(s))
	return sum[:]
}

// publicKeyFromJWK constructs a crypto.PublicKey from a JWK header and returns
// both the key and the RFC 7638 SHA-256 thumbprint (jkt). alg MUST correspond
// to the kty — callers reject the proof if alg is not EdDSA or ES256 before
// reaching this function. Any parse or decode failure results in an error
// (wrapped by the caller as ErrDPoPInvalid).
//
// Thumbprint construction follows RFC 7638 §3.2: lex-sorted required members
// of the JWK, compact JSON encoding, SHA-256, base64url without padding.
// Required members per kty:
//   - OKP (Ed25519): crv, kty, x
//   - EC  (P-256):   crv, kty, x, y
//
// Other members (kid, use, alg, x5c, ...) are ignored for thumbprinting.
func publicKeyFromJWK(jwk map[string]interface{}, alg string) (interface{}, string, error) {
	kty, _ := jwk["kty"].(string)
	crv, _ := jwk["crv"].(string)

	switch alg {
	case "EdDSA":
		if kty != "OKP" || crv != "Ed25519" {
			return nil, "", fmt.Errorf("alg EdDSA requires kty=OKP crv=Ed25519 (got kty=%q crv=%q)", kty, crv)
		}
		xStr, _ := jwk["x"].(string)
		xBytes, err := base64.RawURLEncoding.DecodeString(xStr)
		if err != nil {
			return nil, "", fmt.Errorf("x: invalid base64url: %w", err)
		}
		if len(xBytes) != ed25519.PublicKeySize {
			return nil, "", fmt.Errorf("x: expected %d bytes, got %d", ed25519.PublicKeySize, len(xBytes))
		}
		pub := ed25519.PublicKey(xBytes)
		jkt, err := jwkThumbprintEd25519(xStr)
		if err != nil {
			return nil, "", err
		}
		return pub, jkt, nil

	case "ES256":
		if kty != "EC" || crv != "P-256" {
			return nil, "", fmt.Errorf("alg ES256 requires kty=EC crv=P-256 (got kty=%q crv=%q)", kty, crv)
		}
		xStr, _ := jwk["x"].(string)
		yStr, _ := jwk["y"].(string)
		xBytes, err := base64.RawURLEncoding.DecodeString(xStr)
		if err != nil {
			return nil, "", fmt.Errorf("x: invalid base64url: %w", err)
		}
		yBytes, err := base64.RawURLEncoding.DecodeString(yStr)
		if err != nil {
			return nil, "", fmt.Errorf("y: invalid base64url: %w", err)
		}
		curve := elliptic.P256()
		// Constrain coordinate length to the curve's field size so that
		// malformed inputs that happen to produce a point-on-curve cannot
		// sneak through.
		expected := (curve.Params().BitSize + 7) / 8
		if len(xBytes) != expected || len(yBytes) != expected {
			return nil, "", fmt.Errorf("x/y length: expected %d bytes each", expected)
		}
		// On-curve validation via crypto/ecdh. NewPublicKey decodes the
		// SEC1-uncompressed point form (0x04 || X || Y) and rejects inputs
		// that are not on the curve — replaces the deprecated
		// elliptic.Curve.IsOnCurve without losing the semantic check.
		uncompressed := make([]byte, 1+2*expected)
		uncompressed[0] = 0x04
		copy(uncompressed[1:1+expected], xBytes)
		copy(uncompressed[1+expected:], yBytes)
		// ecdsa.ParseUncompressedPublicKey (Go 1.25+) validates the point is
		// on-curve AND constructs the ecdsa.PublicKey golang-jwt expects for
		// ES256 — replacing the crypto/ecdh probe plus the manual X/Y
		// construction, which Go 1.26 deprecated.
		pub, err := ecdsa.ParseUncompressedPublicKey(curve, uncompressed)
		if err != nil {
			return nil, "", fmt.Errorf("x/y not on curve P-256: %w", err)
		}
		jkt, err := jwkThumbprintECP256(xStr, yStr)
		if err != nil {
			return nil, "", err
		}
		return pub, jkt, nil

	default:
		return nil, "", fmt.Errorf("unsupported alg %q", alg)
	}
}

// jwkThumbprintEd25519 produces the RFC 7638 thumbprint of an Ed25519 JWK.
// Canonical form: {"crv":"Ed25519","kty":"OKP","x":"<x>"}. Member order is
// lex-sorted, no whitespace.
func jwkThumbprintEd25519(x string) (string, error) {
	// Build the canonical bytes directly rather than going through json.Marshal
	// on a map (which does not guarantee deterministic output).
	canonical := fmt.Sprintf(`{"crv":"Ed25519","kty":"OKP","x":%q}`, x)
	// Sanity check that our string-built JSON is valid.
	if !json.Valid([]byte(canonical)) {
		return "", errors.New("canonical jwk JSON is invalid — programming defect")
	}
	sum := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// jwkThumbprintECP256 produces the RFC 7638 thumbprint of a P-256 EC JWK.
// Canonical form: {"crv":"P-256","kty":"EC","x":"<x>","y":"<y>"}.
func jwkThumbprintECP256(x, y string) (string, error) {
	canonical := fmt.Sprintf(`{"crv":"P-256","kty":"EC","x":%q,"y":%q}`, x, y)
	if !json.Valid([]byte(canonical)) {
		return "", errors.New("canonical jwk JSON is invalid — programming defect")
	}
	sum := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}
