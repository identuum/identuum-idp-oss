package repository

import (
	"context"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// AuthCodeRepository defines the interface for authorization code data access
type AuthCodeRepository interface {
	// Store saves a new authorization code
	Store(ctx context.Context, code *domain.AuthCode) error

	// Get retrieves an authorization code by its value
	Get(ctx context.Context, code string) (*domain.AuthCode, error)

	// Delete removes an authorization code (used after exchange)
	Delete(ctx context.Context, code string) error
}
