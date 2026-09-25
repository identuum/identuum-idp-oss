package repository

import (
	"context"

	"github.com/google/uuid"
	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// ClaimRepository defines the interface for organization claim data access
type ClaimRepository interface {
	// Create stores a new organization claim
	Create(ctx context.Context, claim *domain.OrganizationClaim) error

	// GetByTokenHash retrieves a claim by its token hash
	GetByTokenHash(ctx context.Context, hash string) (*domain.OrganizationClaim, error)

	// Delete removes a claim permanently (e.g., after it's been consumed)
	Delete(ctx context.Context, id uuid.UUID) error

	// DeleteExpired removes expired claim tokens (maintenance sweep) and
	// returns the affected-row count. Only rows past their expiry are
	// deleted, on the DB clock; a live token is never removed.
	DeleteExpired(ctx context.Context) (int64, error)

	// IncrementAttemptCount atomically increments the attempt_count for the given
	// claim and returns the new value. Returns an error if the claim no longer exists
	// (e.g. it was deleted by a concurrent request).
	IncrementAttemptCount(ctx context.Context, id uuid.UUID) (int, error)
}

// ClaimConsumeTx is one claim consume's view of the database. In production
// it is bound to a single transaction (ClaimConsumeTransactor): the claim row
// is locked by LockByTokenHash, and the attempt count, the burn and the new
// org_admin commit or roll back together (OSS-SEC).
type ClaimConsumeTx interface {
	// LockByTokenHash reads the claim and holds its row until the
	// transaction ends. domain.ErrClaimNotFound when there is none.
	LockByTokenHash(ctx context.Context, hash string) (*domain.OrganizationClaim, error)
	IncrementAttemptCount(ctx context.Context, id uuid.UUID) (int, error)
	Delete(ctx context.Context, id uuid.UUID) error
	FindUsersByEmail(ctx context.Context, email string) ([]*domain.User, error)
	CreateUser(ctx context.Context, user *domain.User) (*domain.User, error)
}

// ClaimConsumeTransactor runs fn in one transaction: committed when fn
// returns nil, rolled back when it returns an error. PgClaimRepository
// implements it.
type ClaimConsumeTransactor interface {
	ConsumeInTx(ctx context.Context, fn func(ClaimConsumeTx) error) error
}
