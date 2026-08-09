package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/repository"
	"github.com/identuum/identuum-idp-oss/internal/utils/uuidgen"
	"github.com/jackc/pgx/v5"
)

// PgxScopeTemplateRepository implements ScopeTemplateRepository using pgx.
type PgxScopeTemplateRepository struct {
	db DBTX
}

// NewPgxScopeTemplateRepository creates a new PGX scope template repository.
func NewPgxScopeTemplateRepository(db DBTX) *PgxScopeTemplateRepository {
	return &PgxScopeTemplateRepository{db: db}
}

// Compile-time interface check
var _ repository.ScopeTemplateRepository = (*PgxScopeTemplateRepository)(nil)

func (r *PgxScopeTemplateRepository) Create(ctx context.Context, t *domain.ScopeTemplate) error {
	if t.ID == uuid.Nil {
		id, err := uuidgen.NewV7()
		if err != nil {
			return fmt.Errorf("scope_template create: generate id: %w", err)
		}
		t.ID = id
	}
	now := time.Now().UTC()
	t.CreatedAt = now
	t.UpdatedAt = now

	_, err := r.db.Exec(ctx,
		`INSERT INTO scope_templates (id, org_id, name, description, scopes, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		t.ID, t.OrganizationID, t.Name, t.Description, t.Scopes, t.CreatedAt, t.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("scope_template create: %w", err)
	}
	return nil
}

func (r *PgxScopeTemplateRepository) GetByID(ctx context.Context, id, orgID uuid.UUID) (*domain.ScopeTemplate, error) {
	row := r.db.QueryRow(ctx,
		`SELECT id, org_id, name, description, scopes, created_at, updated_at
		 FROM scope_templates WHERE id = $1 AND org_id = $2`,
		id, orgID,
	)
	t, err := scanScopeTemplate(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("scope_template get_by_id: %w", err)
	}
	return t, nil
}

func (r *PgxScopeTemplateRepository) List(ctx context.Context, orgID uuid.UUID) ([]*domain.ScopeTemplate, error) {
	rows, err := r.db.Query(ctx,
		`SELECT id, org_id, name, description, scopes, created_at, updated_at
		 FROM scope_templates WHERE org_id = $1 ORDER BY name ASC`,
		orgID,
	)
	if err != nil {
		return nil, fmt.Errorf("scope_template list: %w", err)
	}
	defer rows.Close()

	var list []*domain.ScopeTemplate
	for rows.Next() {
		t, err := scanScopeTemplate(rows)
		if err != nil {
			return nil, fmt.Errorf("scope_template list scan: %w", err)
		}
		list = append(list, t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("scope_template list iteration: %w", err)
	}
	return list, nil
}

func (r *PgxScopeTemplateRepository) Update(ctx context.Context, t *domain.ScopeTemplate) error {
	t.UpdatedAt = time.Now().UTC()
	_, err := r.db.Exec(ctx,
		`UPDATE scope_templates SET name = $1, description = $2, scopes = $3, updated_at = $4
		 WHERE id = $5 AND org_id = $6`,
		t.Name, t.Description, t.Scopes, t.UpdatedAt, t.ID, t.OrganizationID,
	)
	if err != nil {
		return fmt.Errorf("scope_template update: %w", err)
	}
	return nil
}

func (r *PgxScopeTemplateRepository) Delete(ctx context.Context, id, orgID uuid.UUID) error {
	_, err := r.db.Exec(ctx,
		`DELETE FROM scope_templates WHERE id = $1 AND org_id = $2`,
		id, orgID,
	)
	if err != nil {
		return fmt.Errorf("scope_template delete: %w", err)
	}
	return nil
}

// scanScopeTemplate is a helper that works with both pgx.Row and pgx.Rows.
type pgxScanner interface {
	Scan(dest ...any) error
}

func scanScopeTemplate(row pgxScanner) (*domain.ScopeTemplate, error) {
	var t domain.ScopeTemplate
	err := row.Scan(
		&t.ID,
		&t.OrganizationID,
		&t.Name,
		&t.Description,
		&t.Scopes,
		&t.CreatedAt,
		&t.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &t, nil
}
