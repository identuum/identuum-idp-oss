package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/metrics"
	"github.com/identuum/identuum-idp-oss/internal/repository"
	"github.com/identuum/identuum-idp-oss/internal/utils/uuidgen"
	"github.com/jackc/pgx/v5"
	"github.com/prometheus/client_golang/prometheus"
)

// PgxAPIResourceRepository implements APIResourceRepository using pgx
type PgxAPIResourceRepository struct {
	db DBTX
}

// NewPgxAPIResourceRepository creates a new pgx api_resource repository
func NewPgxAPIResourceRepository(db DBTX) *PgxAPIResourceRepository {
	return &PgxAPIResourceRepository{db: db}
}

// Compile-time check
var _ repository.APIResourceRepository = (*PgxAPIResourceRepository)(nil)

func (r *PgxAPIResourceRepository) Create(ctx context.Context, resource *domain.APIResource, scopes []domain.APIScope) error {
	timer := prometheus.NewTimer(metrics.DBQueryDuration.WithLabelValues("api_resource_repo", "create", "all"))
	defer timer.ObserveDuration()

	if resource.ID == uuid.Nil {
		id, err := uuidgen.NewV7()
		if err != nil {
			return fmt.Errorf("failed to generate id: %w", err)
		}
		resource.ID = id
	}

	tx, err := r.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	query := `
		INSERT INTO api_resources (id, org_id, name, audience, active, token_ttl_secs, resource_secret_hash, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`
	_, err = tx.Exec(ctx, query,
		resource.ID,
		resource.OrganizationID,
		resource.Name,
		resource.Audience,
		resource.Active,
		resource.TokenTTLSecs,
		resource.ResourceSecretHash,
		resource.CreatedAt,
		resource.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to insert resource: %w", err)
	}

	for i := range scopes {
		if scopes[i].ID == uuid.Nil {
			id, err := uuidgen.NewV7()
			if err != nil {
				return fmt.Errorf("failed to generate scope id: %w", err)
			}
			scopes[i].ID = id
		}
		scopes[i].ResourceID = resource.ID
		scopeQuery := `INSERT INTO api_resource_scopes (id, resource_id, name, description) VALUES ($1, $2, $3, $4)`
		if _, err := tx.Exec(ctx, scopeQuery, scopes[i].ID, scopes[i].ResourceID, scopes[i].Name, scopes[i].Description); err != nil {
			return fmt.Errorf("failed to insert scope: %w", err)
		}
	}
	resource.Scopes = scopes

	if err := tx.Commit(ctx); err != nil {
		return err
	}

	return nil
}

func (r *PgxAPIResourceRepository) scanResourceFast(row pgx.Row) (*domain.APIResource, error) {
	var res domain.APIResource
	err := row.Scan(
		&res.ID,
		&res.OrganizationID,
		&res.Name,
		&res.Audience,
		&res.Active,
		&res.TokenTTLSecs,
		&res.ResourceSecretHash,
		&res.CreatedAt,
		&res.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to scan api_resource: %w", err)
	}
	return &res, nil
}

func (r *PgxAPIResourceRepository) fetchScopes(ctx context.Context, res *domain.APIResource) error {
	rows, err := r.db.Query(ctx, "SELECT id, resource_id, name, description FROM api_resource_scopes WHERE resource_id = $1", res.ID)
	if err != nil {
		return err
	}
	defer rows.Close()

	var scopes []domain.APIScope
	for rows.Next() {
		var s domain.APIScope
		if err := rows.Scan(&s.ID, &s.ResourceID, &s.Name, &s.Description); err != nil {
			return err
		}
		scopes = append(scopes, s)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	res.Scopes = scopes
	return nil
}

func (r *PgxAPIResourceRepository) GetByID(ctx context.Context, id uuid.UUID, orgID *uuid.UUID) (*domain.APIResource, error) {
	query := `SELECT id, org_id, name, audience, active, token_ttl_secs, resource_secret_hash, created_at, updated_at FROM api_resources WHERE id = $1`
	var row pgx.Row
	if orgID != nil {
		query += ` AND org_id = $2`
		row = r.db.QueryRow(ctx, query, id, *orgID)
	} else {
		row = r.db.QueryRow(ctx, query, id)
	}

	res, err := r.scanResourceFast(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil // not found
	}
	if err != nil {
		return nil, err
	}

	if err := r.fetchScopes(ctx, res); err != nil {
		return nil, err
	}
	return res, nil
}

func (r *PgxAPIResourceRepository) GetByAudienceGlobal(ctx context.Context, audience string) (*domain.APIResource, error) {
	// An API resource whose parent organization is not operational MUST NOT
	// authenticate — tenant deletion is an authentication boundary. The org
	// predicate mirrors domain.Organization.IsOperational() (deleted_at IS
	// NULL AND active). NOTE: api_resources has no deleted_at column today,
	// so row-level soft-delete + an org-delete cascade for api_resources are
	// deferred to the org-delete cascade slice (reported, not implemented).
	query := `SELECT id, org_id, name, audience, active, token_ttl_secs, resource_secret_hash, created_at, updated_at
		FROM api_resources ar
		WHERE ar.audience = $1
		  AND EXISTS (SELECT 1 FROM organizations o WHERE o.id = ar.org_id AND o.deleted_at IS NULL AND o.active)
		LIMIT 1`
	res, err := r.scanResourceFast(r.db.QueryRow(ctx, query, audience))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil // not found
	}
	if err != nil {
		return nil, err
	}
	if err := r.fetchScopes(ctx, res); err != nil {
		return nil, err
	}
	return res, nil
}

func (r *PgxAPIResourceRepository) Update(ctx context.Context, res *domain.APIResource) error {
	query := `UPDATE api_resources SET name = $1, audience = $2, active = $3, token_ttl_secs = $4, resource_secret_hash = $5, updated_at = $6 WHERE id = $7`
	_, err := r.db.Exec(ctx, query, res.Name, res.Audience, res.Active, res.TokenTTLSecs, res.ResourceSecretHash, res.UpdatedAt, res.ID)
	return err
}

func (r *PgxAPIResourceRepository) Delete(ctx context.Context, id uuid.UUID, orgID *uuid.UUID) error {
	var err error
	if orgID != nil {
		_, err = r.db.Exec(ctx, `DELETE FROM api_resources WHERE id = $1 AND org_id = $2`, id, *orgID)
	} else {
		_, err = r.db.Exec(ctx, `DELETE FROM api_resources WHERE id = $1`, id)
	}
	return err
}

func (r *PgxAPIResourceRepository) List(ctx context.Context, pagination repository.Pagination, orgID *uuid.UUID) ([]*domain.APIResource, int, error) {
	var totalCount int
	countQuery := "SELECT COUNT(*) FROM api_resources"
	whereClause := ""
	args := []any{}

	if orgID != nil {
		whereClause = " WHERE org_id = $1"
		args = append(args, *orgID)
	}

	if err := r.db.QueryRow(ctx, countQuery+whereClause, args...).Scan(&totalCount); err != nil {
		return nil, 0, err
	}

	query := `SELECT id, org_id, name, audience, active, token_ttl_secs, resource_secret_hash, created_at, updated_at FROM api_resources ` + whereClause + ` ORDER BY created_at DESC LIMIT $` + fmt.Sprintf("%d", len(args)+1) + ` OFFSET $` + fmt.Sprintf("%d", len(args)+2)
	args = append(args, pagination.PageSize, (pagination.Page-1)*pagination.PageSize)

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var list []*domain.APIResource
	for rows.Next() {
		res, err := r.scanResourceFast(rows)
		if err != nil {
			return nil, 0, err
		}
		list = append(list, res)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}

	for _, res := range list {
		if err := r.fetchScopes(ctx, res); err != nil {
			return nil, 0, err
		}
	}

	return list, totalCount, nil
}

func (r *PgxAPIResourceRepository) AddScopes(ctx context.Context, resourceID uuid.UUID, scopes []domain.APIScope) error {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	for _, s := range scopes {
		if s.ID == uuid.Nil {
			id, _ := uuidgen.NewV7()
			s.ID = id
		}
		_, err := tx.Exec(ctx, `INSERT INTO api_resource_scopes (id, resource_id, name, description) VALUES ($1, $2, $3, $4)`, s.ID, resourceID, s.Name, s.Description)
		if err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func (r *PgxAPIResourceRepository) RemoveScope(ctx context.Context, resourceID, scopeID uuid.UUID) error {
	_, err := r.db.Exec(ctx, `DELETE FROM api_resource_scopes WHERE resource_id = $1 AND id = $2`, resourceID, scopeID)
	return err
}

// ReplaceScopes atomically replaces the scope set for a resource. Used by
// APIResourceService.Update so a PUT body with a new `scopes` array actually
// lands in the DB; without this the top-level Update SQL leaves
// api_resource_scopes untouched (the §2.11 F-2.11-B silent-drop bug).
func (r *PgxAPIResourceRepository) ReplaceScopes(ctx context.Context, resourceID uuid.UUID, scopes []domain.APIScope) error {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("replace_scopes: begin: %w", err)
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, `DELETE FROM api_resource_scopes WHERE resource_id = $1`, resourceID); err != nil {
		return fmt.Errorf("replace_scopes: delete: %w", err)
	}

	for i := range scopes {
		if scopes[i].ID == uuid.Nil {
			id, err := uuidgen.NewV7()
			if err != nil {
				return fmt.Errorf("replace_scopes: generate id: %w", err)
			}
			scopes[i].ID = id
		}
		scopes[i].ResourceID = resourceID
		if _, err := tx.Exec(ctx,
			`INSERT INTO api_resource_scopes (id, resource_id, name, description) VALUES ($1, $2, $3, $4)`,
			scopes[i].ID, scopes[i].ResourceID, scopes[i].Name, scopes[i].Description,
		); err != nil {
			return fmt.Errorf("replace_scopes: insert: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("replace_scopes: commit: %w", err)
	}
	return nil
}

// UpdateWithScopes applies the resource field update AND replaces its full
// scope set in ONE transaction (P2-16), mirroring Create's internal-tx shape:
// the field UPDATE and the scope DELETE+INSERT commit together, so a failure
// in either step (e.g. a UNIQUE(resource_id, name) violation) rolls BOTH back
// — never a partial write (fields committed, scopes stale, or vice versa).
func (r *PgxAPIResourceRepository) UpdateWithScopes(ctx context.Context, res *domain.APIResource, scopes []domain.APIScope) error {
	timer := prometheus.NewTimer(metrics.DBQueryDuration.WithLabelValues("api_resource_repo", "update_with_scopes", "all"))
	defer timer.ObserveDuration()

	tx, err := r.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("update_with_scopes: begin: %w", err)
	}
	defer tx.Rollback(ctx)

	// 1. Field update (same SQL as Update).
	if _, err := tx.Exec(ctx,
		`UPDATE api_resources SET name = $1, audience = $2, active = $3, token_ttl_secs = $4, resource_secret_hash = $5, updated_at = $6 WHERE id = $7`,
		res.Name, res.Audience, res.Active, res.TokenTTLSecs, res.ResourceSecretHash, res.UpdatedAt, res.ID,
	); err != nil {
		return fmt.Errorf("update_with_scopes: update: %w", err)
	}

	// 2. Scope replacement (same DELETE+INSERT as ReplaceScopes) in the SAME tx.
	if _, err := tx.Exec(ctx, `DELETE FROM api_resource_scopes WHERE resource_id = $1`, res.ID); err != nil {
		return fmt.Errorf("update_with_scopes: delete scopes: %w", err)
	}
	for i := range scopes {
		if scopes[i].ID == uuid.Nil {
			id, err := uuidgen.NewV7()
			if err != nil {
				return fmt.Errorf("update_with_scopes: generate scope id: %w", err)
			}
			scopes[i].ID = id
		}
		scopes[i].ResourceID = res.ID
		if _, err := tx.Exec(ctx,
			`INSERT INTO api_resource_scopes (id, resource_id, name, description) VALUES ($1, $2, $3, $4)`,
			scopes[i].ID, scopes[i].ResourceID, scopes[i].Name, scopes[i].Description,
		); err != nil {
			return fmt.Errorf("update_with_scopes: insert scope: %w", err)
		}
	}
	res.Scopes = scopes

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("update_with_scopes: commit: %w", err)
	}
	return nil
}
