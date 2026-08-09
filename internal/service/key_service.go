package service

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/identuum/identuum-idp-oss/auth"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/repository"
)

// KeyService encapsulates signing key management operations.
// Handlers must use this service instead of accessing KeyRepository directly.
type KeyService struct {
	keyRepo repository.KeyRepository
}

// NewKeyService creates a new KeyService.
func NewKeyService(keyRepo repository.KeyRepository) *KeyService {
	return &KeyService{keyRepo: keyRepo}
}

// ListAll returns all signing keys including deprecated ones.
func (s *KeyService) ListAll(ctx context.Context) ([]domain.SigningKey, error) {
	keys, err := s.keyRepo.GetAllSigningKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("list all signing keys: %w", err)
	}
	return keys, nil
}

// ListActive returns all keys that can validate tokens (active + rotating).
func (s *KeyService) ListActive(ctx context.Context) ([]domain.SigningKey, error) {
	keys, err := s.keyRepo.GetActiveSigningKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("list active signing keys: %w", err)
	}
	return keys, nil
}

// GenerateKeyOptions contains parameters for key generation.
type GenerateKeyOptions struct {
	Algorithm string
	State     domain.KeyState
	CreatedBy *uuid.UUID
}

// Generate creates a new signing key and persists it.
func (s *KeyService) Generate(ctx context.Context, opts GenerateKeyOptions) (*domain.SigningKey, error) {
	var key *domain.SigningKey
	var err error

	switch opts.Algorithm {
	case string(domain.KeyAlgorithmEdDSA):
		key, err = auth.GenerateEdDSAKey()
	case string(domain.KeyAlgorithmES256):
		key, err = auth.GenerateES256Key()
	default:
		return nil, domain.ErrInvalidRequest
	}
	if err != nil {
		return nil, fmt.Errorf("generate signing key: %w", err)
	}

	key.State = opts.State
	key.CreatedBy = opts.CreatedBy

	if err := s.keyRepo.CreateSigningKey(ctx, key); err != nil {
		return nil, fmt.Errorf("persist signing key: %w", err)
	}
	return key, nil
}

// Rotate performs atomic key rotation from oldKID to newKID.
func (s *KeyService) Rotate(ctx context.Context, oldKID, newKID string, expiresAt *time.Time) error {
	if err := s.keyRepo.RotateSigningKey(ctx, oldKID, newKID, expiresAt); err != nil {
		return fmt.Errorf("rotate signing key: %w", err)
	}
	return nil
}

// Deprecate marks a key for deprecation with an expiration date.
func (s *KeyService) Deprecate(ctx context.Context, kid string, expiresAt time.Time) error {
	if err := s.keyRepo.DeprecateSigningKey(ctx, kid, expiresAt); err != nil {
		return fmt.Errorf("deprecate signing key: %w", err)
	}
	return nil
}

// DeleteExpired removes deprecated keys past their expiration timestamp.
func (s *KeyService) DeleteExpired(ctx context.Context) (int, error) {
	count, err := s.keyRepo.DeleteExpiredKeys(ctx)
	if err != nil {
		return 0, fmt.Errorf("delete expired signing keys: %w", err)
	}
	return count, nil
}

// GetByKID retrieves a signing key by its Key ID.
// Used by handlers to resolve key metadata (e.g. algorithm) for audit logging.
func (s *KeyService) GetByKID(ctx context.Context, kid string) (*domain.SigningKey, error) {
	key, err := s.keyRepo.GetSigningKeyByKID(ctx, kid)
	if err != nil {
		return nil, fmt.Errorf("get signing key by kid: %w", err)
	}
	return key, nil
}
