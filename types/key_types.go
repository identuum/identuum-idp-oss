package types

import (
	"time"

	"github.com/google/uuid"
)

// ============================================================================
// JWT Signing Key Types (Asymmetric Signing)
// ============================================================================

// KeyAlgorithm represents the asymmetric signing algorithm for JWT tokens
type KeyAlgorithm string

const (
	KeyAlgorithmEdDSA KeyAlgorithm = "EdDSA" // Ed25519 (recommended - fastest, simplest)
	KeyAlgorithmES256 KeyAlgorithm = "ES256" // ECDSA P-256 (widely compatible)
	KeyAlgorithmRS256 KeyAlgorithm = "RS256" // RSA 2048-bit (legacy)
)

// KeyState represents the lifecycle state of a signing key
type KeyState string

const (
	KeyStateActive     KeyState = "active"     // Currently signing new tokens
	KeyStateRotating   KeyState = "rotating"   // Overlap period, validates but doesn't sign
	KeyStateDeprecated KeyState = "deprecated" // Only validates old tokens, scheduled for deletion
)

// SigningKey represents a JWT signing key with lifecycle metadata
type SigningKey struct {
	CreatedAt   time.Time    `json:"created_at" db:"created_at"`
	ActivatedAt *time.Time   `json:"activated_at,omitempty" db:"activated_at"`
	RotatedAt   *time.Time   `json:"rotated_at,omitempty" db:"rotated_at"`
	ExpiresAt   *time.Time   `json:"expires_at,omitempty" db:"expires_at"`
	CreatedBy   *uuid.UUID   `json:"created_by,omitempty" db:"created_by"`
	KID         string       `json:"kid" db:"kid"`
	Algorithm   KeyAlgorithm `json:"algorithm" db:"algorithm"`
	PublicKey   string       `json:"public_key" db:"public_key"`
	PrivateKey  string       `json:"-" db:"private_key"`
	State       KeyState     `json:"state" db:"state"`
	ID          uuid.UUID    `json:"id" db:"id"`
}

// ============================================================================
// JWKS (JSON Web Key Set) Types
// ============================================================================

// JWKSResponse is the response format for the /.well-known/jwks.json endpoint
type JWKSResponse struct {
	Keys []JWK `json:"keys"`
}

// JWK represents a JSON Web Key in JWKS format (RFC 7517)
type JWK struct {
	// Common fields (all key types)
	KTY string `json:"kty"` // Key type: "RSA", "EC", or "OKP" (Octet Key Pair for EdDSA)
	KID string `json:"kid"` // Key ID (matches SigningKey.KID)
	ALG string `json:"alg"` // Algorithm: "EdDSA", "ES256", or "RS256"
	Use string `json:"use"` // Key usage: "sig" for signing

	// RSA-specific fields (RS256)
	N string `json:"n,omitempty"` // Modulus (base64url-encoded)
	E string `json:"e,omitempty"` // Exponent (base64url-encoded)

	// ECDSA-specific fields (ES256)
	CRV string `json:"crv,omitempty"` // Curve name: "P-256" for ES256, "Ed25519" for EdDSA
	X   string `json:"x,omitempty"`   // X coordinate (base64url-encoded) or Ed25519 public key
	Y   string `json:"y,omitempty"`   // Y coordinate (base64url-encoded, not used for EdDSA)
}
