package auth

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
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
