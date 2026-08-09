package repository

import (
	"context"
	"time"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// KeyRepository handles storage operations for signing keys
type KeyRepository interface {
	// GetActiveSigningKeys returns all keys that can validate tokens (active + rotating)
	GetActiveSigningKeys(ctx context.Context) ([]domain.SigningKey, error)

	// GetAllSigningKeys returns all keys including deprecated
	GetAllSigningKeys(ctx context.Context) ([]domain.SigningKey, error)

	// GetSigningKeyByKID retrieves a specific key by its Key ID
	GetSigningKeyByKID(ctx context.Context, kid string) (*domain.SigningKey, error)

	// CreateSigningKey inserts a new signing key
	CreateSigningKey(ctx context.Context, key *domain.SigningKey) error

	// ActivateSigningKey activates a key (makes it the primary signing key)
	ActivateSigningKey(ctx context.Context, kid string) error

	// RotateSigningKey performs atomic key rotation
	RotateSigningKey(ctx context.Context, oldKID, newKID string, expiresAt *time.Time) error

	// DeprecateSigningKey marks a key as deprecated
	DeprecateSigningKey(ctx context.Context, kid string, expiresAt time.Time) error

	// DeleteExpiredKeys removes deprecated keys past their expiration timestamp
	DeleteExpiredKeys(ctx context.Context) (int, error)
}
