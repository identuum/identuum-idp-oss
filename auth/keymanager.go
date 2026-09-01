package auth

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"sync"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/logger"
)

// ============================================================================
// Key Manager (Asymmetric Signing)
// ============================================================================

// KeyManager manages multiple asymmetric signing keys with thread-safe access
// Supports EdDSA (Ed25519) and ES256 (ECDSA) algorithms with key rotation
// Note: RS256 is not supported due to security and performance considerations
type KeyManager struct {
	keys       map[string]*ParsedKey // kid -> key mapping
	primaryKey *ParsedKey            // Current active key for signing new tokens
	mu         sync.RWMutex          // Thread-safe access to keys
}

// ParsedKey represents a signing key with parsed cryptographic keys
type ParsedKey struct {
	KID        string
	Algorithm  domain.KeyAlgorithm
	PrivateKey any // *ecdsa.PrivateKey or ed25519.PrivateKey
	PublicKey  any // *ecdsa.PublicKey or ed25519.PublicKey
	State      domain.KeyState
}

// ============================================================================
// Initialization Functions
// ============================================================================

// NewKeyManager initializes the key manager with signing keys from database.
//
// Key selection strategy:
// 1. Primary key = active key with preference: EdDSA > ES256
// 2. All active + rotating keys loaded for validation
//
// Returns error if no active keys found.
func NewKeyManager(dbKeys []domain.SigningKey) (*KeyManager, error) {
	if len(dbKeys) == 0 {
		return nil, fmt.Errorf("no signing keys provided")
	}

	km := &KeyManager{
		keys: make(map[string]*ParsedKey),
	}

	var activeEdDSA *ParsedKey
	var activeES256 *ParsedKey

	for _, dbKey := range dbKeys {
		parsed, err := parseKey(dbKey)
		if err != nil {
			logger.Error.WithFields(map[string]any{
				"kid":       dbKey.KID,
				"algorithm": dbKey.Algorithm,
				"error":     err.Error(),
			}).Print("Failed to parse signing key - skipping")
			continue
		}

		km.keys[dbKey.KID] = parsed

		// Track active keys by algorithm for primary selection
		if dbKey.State == domain.KeyStateActive {
			switch dbKey.Algorithm {
			case domain.KeyAlgorithmEdDSA:
				activeEdDSA = parsed
			case domain.KeyAlgorithmES256:
				activeES256 = parsed
			}
		}
	}

	// Select primary key: prefer EdDSA > ES256 (performance & simplicity)
	if activeEdDSA != nil {
		km.primaryKey = activeEdDSA
	} else if activeES256 != nil {
		km.primaryKey = activeES256
	}

	if km.primaryKey == nil {
		return nil, fmt.Errorf("no active signing key found (loaded %d keys)", len(km.keys))
	}

	// Log initialization success
	logger.Info.WithFields(map[string]any{
		"total_keys":  len(km.keys),
		"primary_kid": km.primaryKey.KID,
		"primary_alg": km.primaryKey.Algorithm,
	}).Print("Key manager initialized successfully")

	return km, nil
}

// Reload updates the KeyManager with new keys safely
func (km *KeyManager) Reload(dbKeys []domain.SigningKey) error {
	newKM, err := NewKeyManager(dbKeys)
	if err != nil {
		return err
	}

	km.mu.Lock()
	defer km.mu.Unlock()
	km.keys = newKM.keys
	km.primaryKey = newKM.primaryKey
	return nil
}

// SignBytes produces a raw signature over an arbitrary byte payload using the
// current primary key. Used by the audit hash-chain row-signing path (§8) to
// commit each shard's head_hash with a key any external auditor can verify
// out-of-band against the public JWKS.
//
// Returned tuple:
//   - signature : raw bytes (64 for Ed25519, ASN.1 DER for ECDSA P-256)
//   - kid       : the key id that produced the signature; the verifier uses
//     this to select the right key from JWKS even after rotation
//   - err       : non-nil on any failure (no primary key, unknown algorithm,
//     underlying crypto error)
//
// The signature scheme is deliberately the same as the JWT signing scheme so
// existing JWKS infrastructure (publication, rotation, multi-key verifier)
// is reused without parallel key plumbing.
func (km *KeyManager) SignBytes(payload []byte) ([]byte, string, error) {
	km.mu.RLock()
	defer km.mu.RUnlock()
	if km.primaryKey == nil {
		return nil, "", fmt.Errorf("KeyManager.SignBytes: no primary key")
	}
	switch km.primaryKey.Algorithm {
	case domain.KeyAlgorithmEdDSA:
		priv, ok := km.primaryKey.PrivateKey.(ed25519.PrivateKey)
		if !ok {
			return nil, "", fmt.Errorf("KeyManager.SignBytes: primary key is not Ed25519 despite EdDSA algorithm")
		}
		return ed25519.Sign(priv, payload), km.primaryKey.KID, nil
	case domain.KeyAlgorithmES256:
		priv, ok := km.primaryKey.PrivateKey.(*ecdsa.PrivateKey)
		if !ok {
			return nil, "", fmt.Errorf("KeyManager.SignBytes: primary key is not ECDSA despite ES256 algorithm")
		}
		// SHA-256 hash of the payload — matches ES256's JWT signing semantics
		// so the same JWKS public key verifies both JWTs and audit signatures.
		digest := sha256.Sum256(payload)
		sig, err := ecdsa.SignASN1(rand.Reader, priv, digest[:])
		if err != nil {
			return nil, "", fmt.Errorf("KeyManager.SignBytes: ECDSA sign: %w", err)
		}
		return sig, km.primaryKey.KID, nil
	default:
		return nil, "", fmt.Errorf("KeyManager.SignBytes: unsupported algorithm %q", km.primaryKey.Algorithm)
	}
}

// VerifyBytes checks a signature against a payload using the key identified
// by kid. The key need not be the current primary; the verifier accepts any
// key the manager has loaded (including rotating keys), so a chain head
// signed by a previously-active key still verifies after rotation.
//
// Returns nil on a valid signature, non-nil on any failure (unknown kid,
// algorithm mismatch, signature does not match payload).
func (km *KeyManager) VerifyBytes(payload, signature []byte, kid string) error {
	km.mu.RLock()
	defer km.mu.RUnlock()
	key, ok := km.keys[kid]
	if !ok {
		return fmt.Errorf("KeyManager.VerifyBytes: unknown kid %q", kid)
	}
	switch key.Algorithm {
	case domain.KeyAlgorithmEdDSA:
		pub, ok := key.PublicKey.(ed25519.PublicKey)
		if !ok {
			return fmt.Errorf("KeyManager.VerifyBytes: kid %q public key is not Ed25519 despite EdDSA algorithm", kid)
		}
		if !ed25519.Verify(pub, payload, signature) {
			return fmt.Errorf("KeyManager.VerifyBytes: signature does not match payload")
		}
		return nil
	case domain.KeyAlgorithmES256:
		pub, ok := key.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("KeyManager.VerifyBytes: kid %q public key is not ECDSA despite ES256 algorithm", kid)
		}
		digest := sha256.Sum256(payload)
		if !ecdsa.VerifyASN1(pub, digest[:], signature) {
			return fmt.Errorf("KeyManager.VerifyBytes: signature does not match payload")
		}
		return nil
	default:
		return fmt.Errorf("KeyManager.VerifyBytes: unsupported algorithm %q", key.Algorithm)
	}
}

// parseKey converts a database SigningKey to a ParsedKey with crypto primitives.
//
// RS256 remains verify-only IN THIS MANAGER: an RS256 row parses its PUBLIC
// key only, and the ParsedKey never carries RSA signing capability — the
// KeyManager's primary-key selection stays EdDSA/ES256. Since
// THE-PKCE-DECISION an RS256 row MAY carry a private key (the id_token
// minter in internal/service signs with it, testing-only, on an explicit
// per-client registration); this manager deliberately does not load it.
// This branch lands BEFORE the private-key PEM decode below because EdDSA /
// ES256 keys are required to carry a private key for signing, but RS256
// keys never sign here.
func parseKey(dbKey domain.SigningKey) (*ParsedKey, error) {
	parsed := &ParsedKey{
		KID:       dbKey.KID,
		Algorithm: dbKey.Algorithm,
		State:     dbKey.State,
	}

	if dbKey.Algorithm == domain.KeyAlgorithmRS256 {
		pubBlock, _ := pem.Decode([]byte(dbKey.PublicKey))
		if pubBlock == nil {
			return nil, fmt.Errorf("invalid RS256 public key PEM format")
		}
		pubKey, err := x509.ParsePKIXPublicKey(pubBlock.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse RS256 public key: %w", err)
		}
		rsaPub, ok := pubKey.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("PKIX key is not RSA type (got %T)", pubKey)
		}
		// Reject keys below 2048-bit modulus — defense against
		// underspecified-sized keys slipping in.
		if rsaPub.N.BitLen() < 2048 {
			return nil, fmt.Errorf("RS256 public key must be ≥ 2048 bits (got %d)", rsaPub.N.BitLen())
		}
		parsed.PrivateKey = nil // explicit: no signing capability
		parsed.PublicKey = rsaPub
		return parsed, nil
	}

	// Parse private key from PEM format
	privBlock, _ := pem.Decode([]byte(dbKey.PrivateKey))
	if privBlock == nil {
		return nil, fmt.Errorf("invalid private key PEM format")
	}

	switch dbKey.Algorithm {
	case domain.KeyAlgorithmEdDSA:
		// Ed25519 keys are simpler - direct parsing
		privKey, err := x509.ParsePKCS8PrivateKey(privBlock.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse Ed25519 private key: %w", err)
		}
		ed25519Priv, ok := privKey.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("PKCS8 key is not Ed25519 type")
		}
		parsed.PrivateKey = ed25519Priv
		parsed.PublicKey = ed25519Priv.Public().(ed25519.PublicKey)

	case domain.KeyAlgorithmES256:
		// Try EC-specific format first (openssl ecparam)
		privKey, err := x509.ParseECPrivateKey(privBlock.Bytes)
		if err != nil {
			// Fallback to PKCS8 format
			privKey2, err2 := x509.ParsePKCS8PrivateKey(privBlock.Bytes)
			if err2 != nil {
				return nil, fmt.Errorf("failed to parse ECDSA private key (tried EC and PKCS8): %w", err)
			}
			var ok bool
			privKey, ok = privKey2.(*ecdsa.PrivateKey)
			if !ok {
				return nil, fmt.Errorf("PKCS8 key is not ECDSA type")
			}
		}

		// Validate curve is P-256 (required for ES256)
		if privKey.Curve.Params().Name != "P-256" {
			return nil, fmt.Errorf("ECDSA key must use P-256 curve, got: %s", privKey.Curve.Params().Name)
		}

		parsed.PrivateKey = privKey
		parsed.PublicKey = &privKey.PublicKey

	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", dbKey.Algorithm)
	}

	return parsed, nil
}
