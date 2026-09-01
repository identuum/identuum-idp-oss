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
	// KeyAlgorithmRS256: Identuum's defaults are EdDSA/ES256 (modern
	// crypto by default, per docs/ID_JAG_DESIGN.md cross-Q finding #15);
	// RS256 verification supports inbound foreign-IdP-signed assertions
	// (Q6, ID-JAG Resource-Server-side path).
	//
	// THE-PKCE-DECISION (owner ruling, verbatim): "Add RS256 into the
	// list BUT DO NOT USE except testing and put this into documentation
	// CLEARLY." RS256 SIGNING is now a real capability — key generation
	// (GenerateRS256Key), JWKS publication, id_token signing — but it is
	// NEVER the default: it fires only for a client that explicitly
	// registered id_token_signed_response_alg=RS256, the issuer default
	// key selection never picks an RSA key, AutoGenerateInitialKey never
	// generates one, and auth.KeyManager still refuses to sign with it.
	// Testing-only; see docs/TESTING-OPERATORS.md.
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
