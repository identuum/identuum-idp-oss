package auth

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/logger"
)

// GenerateEdDSAKey generates a new Ed25519 key pair and returns it as a SigningKey struct
func GenerateEdDSAKey() (*domain.SigningKey, error) {
	// Generate Ed25519 key pair
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate Ed25519 key: %w", err)
	}

	// Convert to PKCS8 format for private key
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}

	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	// Convert to PKIX format for public key
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	// Generate key ID with timestamp
	kid := fmt.Sprintf("eddsa-%s", time.Now().UTC().Format("20060102-150405"))

	return &domain.SigningKey{
		KID:        kid,
		Algorithm:  domain.KeyAlgorithmEdDSA,
		PublicKey:  string(publicKeyPEM),
		PrivateKey: string(privateKeyPEM),
		State:      domain.KeyStateActive,
		CreatedBy:  nil, // system-generated, no user ID
	}, nil
}

// GenerateES256Key generates a new ECDSA P-256 key pair
func GenerateES256Key() (*domain.SigningKey, error) {
	// Generate ECDSA P-256 key pair
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ECDSA P-256 key: %w", err)
	}

	// Convert to PKCS8 format for private key
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}

	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	// Convert to PKIX format for public key
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	// Generate key ID with timestamp
	kid := fmt.Sprintf("es256-%s", time.Now().UTC().Format("20060102-150405"))

	return &domain.SigningKey{
		KID:        kid,
		Algorithm:  domain.KeyAlgorithmES256,
		PublicKey:  string(publicKeyPEM),
		PrivateKey: string(privateKeyPEM),
		State:      domain.KeyStateActive,
		CreatedBy:  nil, // system-generated, no user ID
	}, nil
}

// GenerateRS256Key generates a new RSA-2048 key pair.
//
// THE-PKCE-DECISION (owner ruling 2026-09-01): RS256 is a REAL capability —
// key, JWKS publication, id_token signing on EXPLICIT client request — so
// discovery advertises nothing it cannot do. It is NEVER the default: the
// primary signer stays EdDSA (KeyManager's primary selection never picks
// RSA, AutoGenerateInitialKey never generates it), and it exists for
// conformance/interop TESTING, not operation. See
// docs/TESTING-OPERATORS.md ("RS256 — testing only").
func GenerateRS256Key() (*domain.SigningKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA-2048 key: %w", err)
	}

	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	kid := fmt.Sprintf("rs256-%s", time.Now().UTC().Format("20060102-150405"))

	return &domain.SigningKey{
		KID:        kid,
		Algorithm:  domain.KeyAlgorithmRS256,
		PublicKey:  string(publicKeyPEM),
		PrivateKey: string(privateKeyPEM),
		State:      domain.KeyStateActive,
		CreatedBy:  nil, // system-generated, no user ID
	}, nil
}

// AutoGenerateInitialKey generates an initial signing key based on the specified algorithm
// This is called on application startup to ensure the service can sign tokens
// Supported algorithms: EdDSA, ES256 (defaults to EdDSA if invalid)
// Note: RS256 is not supported due to security and performance considerations
func AutoGenerateInitialKey(algorithm string) (*domain.SigningKey, error) {
	logger.Info.WithFields(map[string]any{
		"algorithm": algorithm,
	}).Print("Generating initial signing key...")

	var key *domain.SigningKey
	var err error

	// Generate key based on algorithm
	switch algorithm {
	case string(domain.KeyAlgorithmEdDSA):
		key, err = GenerateEdDSAKey()
	case string(domain.KeyAlgorithmES256):
		key, err = GenerateES256Key()
	default:
		logger.Warning.WithFields(map[string]any{
			"requested_algorithm": algorithm,
			"default_algorithm":   domain.KeyAlgorithmEdDSA,
		}).Print("Invalid algorithm specified, defaulting to EdDSA")
		key, err = GenerateEdDSAKey()
	}

	if err != nil {
		return nil, fmt.Errorf("failed to generate initial %s key: %w", algorithm, err)
	}

	logger.Info.WithFields(map[string]any{
		"kid":       key.KID,
		"algorithm": key.Algorithm,
		"state":     key.State,
	}).Print("Generated initial signing key automatically")

	return key, nil
}
