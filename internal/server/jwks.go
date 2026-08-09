package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/repository"
)

// JWK is the RFC 7517 JSON Web Key shape narrowed to the algorithms
// Identuum issues with: EdDSA (OKP/Ed25519) and ES256 (EC/P-256).
// Private fields (notably d) are deliberately not modeled here; the
// PublicJWKS contract guarantees they are never serialised.
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv,omitempty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
}

// JWKS is the RFC 7517 §5 JSON Web Key Set wrapper.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// JWKSProvider yields the current public JWKS. The smoke handler
// calls this on every /.well-known/jwks.json request — caching is
// the provider's responsibility, not the handler's.
type JWKSProvider interface {
	PublicJWKS(ctx context.Context) (JWKS, error)
}

// EmptyJWKSProvider always returns an empty JWKS. Used by the smoke
// CLI when no database is configured, so /.well-known/jwks.json
// reliably returns {"keys":[]} instead of 404 or 500.
type EmptyJWKSProvider struct{}

// PublicJWKS implements JWKSProvider.
func (EmptyJWKSProvider) PublicJWKS(_ context.Context) (JWKS, error) {
	return JWKS{Keys: []JWK{}}, nil
}

// errUnsupportedAlgorithm is the sentinel returned by PublicKeyToJWK
// when asked to serialise an algorithm Identuum does not issue with.
// RS256 lands here even though Identuum may verify inbound RS256
// tokens — verification is an inbound concern; JWKS publication is
// strictly outbound issuance.
var errUnsupportedAlgorithm = errors.New("jwks: unsupported issuance algorithm")

// PublicKeyToJWK converts a single OSS signing-key row to its
// public-only JWK form. Returns errUnsupportedAlgorithm for any
// algorithm Identuum does not issue with. The caller should treat
// per-key errors as filter signals, not fatal failures, when
// building a JWKS.
func PublicKeyToJWK(kid string, alg domain.KeyAlgorithm, publicKeyPEM string) (JWK, error) {
	if publicKeyPEM == "" {
		return JWK{}, errors.New("jwks: empty public key material")
	}

	switch alg {
	case domain.KeyAlgorithmEdDSA:
		return ed25519PEMToJWK(kid, publicKeyPEM)
	case domain.KeyAlgorithmES256:
		return p256PEMToJWK(kid, publicKeyPEM)
	default:
		return JWK{}, fmt.Errorf("%w: %s", errUnsupportedAlgorithm, alg)
	}
}

func ed25519PEMToJWK(kid, publicKeyPEM string) (JWK, error) {
	pub, err := parsePublicKeyPEM(publicKeyPEM)
	if err != nil {
		return JWK{}, fmt.Errorf("jwks: parse EdDSA public key: %w", err)
	}
	ed, ok := pub.(ed25519.PublicKey)
	if !ok {
		return JWK{}, fmt.Errorf("jwks: expected ed25519.PublicKey, got %T", pub)
	}
	return JWK{
		Kty: "OKP",
		Crv: "Ed25519",
		Kid: kid,
		Use: "sig",
		Alg: "EdDSA",
		X:   base64.RawURLEncoding.EncodeToString(ed),
	}, nil
}

func p256PEMToJWK(kid, publicKeyPEM string) (JWK, error) {
	pub, err := parsePublicKeyPEM(publicKeyPEM)
	if err != nil {
		return JWK{}, fmt.Errorf("jwks: parse ES256 public key: %w", err)
	}
	ec, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return JWK{}, fmt.Errorf("jwks: expected *ecdsa.PublicKey, got %T", pub)
	}
	if ec.Curve != elliptic.P256() {
		return JWK{}, fmt.Errorf("jwks: ES256 must use P-256, got %s", ec.Curve.Params().Name)
	}

	// Extract the uncompressed-point encoding (0x04 || X || Y) via
	// crypto/ecdh to avoid the deprecated direct access to ec.X/ec.Y.
	// RFC 7518 §6.2.1 wants the bare coordinate octets — strip the
	// 0x04 tag and split into fixed-width X and Y. P-256 → 32 bytes
	// per coordinate.
	ecdhPub, err := ec.ECDH()
	if err != nil {
		return JWK{}, fmt.Errorf("jwks: convert ES256 public key to ECDH form: %w", err)
	}
	raw := ecdhPub.Bytes()
	const coordLen = 32
	if len(raw) != 1+2*coordLen || raw[0] != 0x04 {
		return JWK{}, fmt.Errorf("jwks: unexpected ES256 point encoding (len=%d)", len(raw))
	}
	xBytes := raw[1 : 1+coordLen]
	yBytes := raw[1+coordLen:]
	return JWK{
		Kty: "EC",
		Crv: "P-256",
		Kid: kid,
		Use: "sig",
		Alg: "ES256",
		X:   base64.RawURLEncoding.EncodeToString(xBytes),
		Y:   base64.RawURLEncoding.EncodeToString(yBytes),
	}, nil
}

func parsePublicKeyPEM(data string) (any, error) {
	block, _ := pem.Decode([]byte(data))
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	return x509.ParsePKIXPublicKey(block.Bytes)
}

// RepositoryJWKSProvider adapts a KeyRepository to JWKSProvider.
// PublicJWKS calls GetActiveSigningKeys (active + rotating per the
// interface contract), filters out unsupported algorithms (notably
// RS256 — verify-only, never published), and emits the public-key
// JWK set with no private material. Deprecated keys are not
// included; the verifier path uses a different repository method.
type RepositoryJWKSProvider struct {
	Repo repository.KeyRepository
}

// PublicJWKS implements JWKSProvider against a KeyRepository. A
// failure to fetch keys propagates; a failure to serialise an
// individual key is silently dropped so one bad row cannot 500 the
// whole endpoint. Drop reasons are not surfaced over HTTP.
func (p RepositoryJWKSProvider) PublicJWKS(ctx context.Context) (JWKS, error) {
	if p.Repo == nil {
		return JWKS{}, errors.New("jwks: nil KeyRepository")
	}
	rows, err := p.Repo.GetActiveSigningKeys(ctx)
	if err != nil {
		return JWKS{}, fmt.Errorf("jwks: fetch active keys: %w", err)
	}
	out := make([]JWK, 0, len(rows))
	for _, k := range rows {
		jwk, err := PublicKeyToJWK(k.KID, k.Algorithm, k.PublicKey)
		if err != nil {
			// Per-key failures (unsupported alg, malformed PEM) are
			// dropped here — exposing the error would leak details
			// about key state. The remaining keys still serve.
			continue
		}
		out = append(out, jwk)
	}
	return JWKS{Keys: out}, nil
}
