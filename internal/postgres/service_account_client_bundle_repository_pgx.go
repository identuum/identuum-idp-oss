package postgres

import (
	"context"
	"fmt"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/repository"
	"github.com/identuum/identuum-idp-oss/logger"
	"go.uber.org/zap"
)

// PgxServiceAccountClientBundleRepository creates a service account and a
// confidential OAuth client bound to it atomically, in one transaction.
// It mirrors PgxOrganizationRepository.CreateWithAdmin: begin a tx, run
// the two existing sub-repositories against that same tx, and commit only
// if BOTH inserts succeed. Any error rolls the whole tx back, so a failed
// client insert can never leave an orphan service account (P2-16b).
type PgxServiceAccountClientBundleRepository struct {
	db DBTX
}

// NewPgxServiceAccountClientBundleRepository constructs the repository
// over a pool (or any DBTX).
func NewPgxServiceAccountClientBundleRepository(db DBTX) *PgxServiceAccountClientBundleRepository {
	return &PgxServiceAccountClientBundleRepository{db: db}
}

var _ repository.ServiceAccountClientBundleRepository = (*PgxServiceAccountClientBundleRepository)(nil)

// CreateWithClient persists sa then client in a single transaction. The
// client's ServiceAccountID is bound to the just-created SA's id inside
// the tx, so the binding is valid by construction. On any error nothing
// is committed and both returned pointers are nil.
func (r *PgxServiceAccountClientBundleRepository) CreateWithClient(ctx context.Context, sa *domain.ServiceAccount, client *domain.Client) (*domain.ServiceAccount, *domain.Client, error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // rollback on any non-commit path

	createdSA, err := (&PgxServiceAccountRepository{db: tx}).Create(ctx, sa)
	if err != nil {
		return nil, nil, fmt.Errorf("bundle: create service account: %w", err)
	}

	// Bind the client to the SA created in THIS tx — valid by construction
	// (the SA row is guaranteed to exist and share the org at commit time).
	client.ServiceAccountID = &createdSA.ID
	if err := (&PgxClientRepository{db: tx}).RegisterClient(ctx, client); err != nil {
		return nil, nil, fmt.Errorf("bundle: register client: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, nil, fmt.Errorf("failed to commit bundle transaction: %w", err)
	}

	logger.InfoContext(ctx, "Atomically created service account with bound client",
		zap.String("service_account_id", createdSA.ID.String()),
		zap.String("client_uuid", client.ID.String()),
		zap.String("org_id", createdSA.OrganizationID.String()),
	)
	return createdSA, client, nil
}
