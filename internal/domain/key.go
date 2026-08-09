package domain

import (
	"time"

	"github.com/google/uuid"
)

// KeyAlgorithm represents the asymmetric signing algorithm
type KeyAlgorithm string

const (
	KeyAlgorithmEdDSA KeyAlgorithm = "EdDSA"
	KeyAlgorithmES256 KeyAlgorithm = "ES256"
	// KeyAlgorithmRS256 is verification-capable only — Identuum signs with
	// EdDSA/ES256 only (modern crypto by default, per
	// docs/ID_JAG_DESIGN.md cross-Q finding #15). RS256 verification was
	// added in Q6 to support inbound foreign-IdP-signed assertions for
	// the ID-JAG Resource-Server-side path. The asymmetric posture is
	// enforced architecturally: parseKey rejects any RS256 key that
	// carries a non-empty PrivateKey field, and SignBytes /
	// GenerateJWTToken / GenerateIDToken / GenerateIDJagAssertion all
	// continue to refuse RS256 as their signing algorithm via their
	// default-case rejections.
	KeyAlgorithmRS256 KeyAlgorithm = "RS256"
)

// KeyState represents the lifecycle state of a signing key
type KeyState string

const (
	KeyStateActive     KeyState = "active"
	KeyStateRotating   KeyState = "rotating"
	KeyStateDeprecated KeyState = "deprecated"
)

// SigningKey represents a cryptographic key used for signing tokens
// This is the domain model, decoupled from API and Storage representations
type SigningKey struct {
	CreatedAt   time.Time
	ActivatedAt *time.Time
	RotatedAt   *time.Time
	ExpiresAt   *time.Time
	CreatedBy   *uuid.UUID
	KID         string
	Algorithm   KeyAlgorithm
	PublicKey   string
	PrivateKey  string
	State       KeyState
	ID          uuid.UUID
}
