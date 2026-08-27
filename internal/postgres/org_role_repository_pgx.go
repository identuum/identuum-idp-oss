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
	"github.com/jackc/pgx/v5/pgconn"
)

// PgxOrgRoleRepository implements OrgRoleRepository using pgx.
type PgxOrgRoleRepository struct {
	db DBTX
}

// NewPgxOrgRoleRepository creates a new pgx org role repository.
func NewPgxOrgRoleRepository(db DBTX) *PgxOrgRoleRepository {
	return &PgxOrgRoleRepository{db: db}
}

// Compile-time check
var _ repository.OrgRoleRepository = (*PgxOrgRoleRepository)(nil)

// Create inserts a new org role.
func (r *PgxOrgRoleRepository) Create(ctx context.Context, role *domain.OrgRole) error {
	if role.ID == uuid.Nil {
		id, err := uuidgen.NewV7()
		if err != nil {
			return fmt.Errorf("org_role: failed to generate id: %w", err)
		}
		role.ID = id
	}
	now := time.Now()
	role.CreatedAt = now
	role.UpdatedAt = now

	_, err := r.db.Exec(ctx,
		`INSERT INTO org_roles (id, org_id, name, description, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		role.ID, role.OrgID, role.Name, role.Description, role.CreatedAt, role.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("org_role: create: %w", err)
	}
	return nil
}

// GetByID retrieves a role by ID, populating Scopes via a join.
func (r *PgxOrgRoleRepository) GetByID(ctx context.Context, id uuid.UUID) (*domain.OrgRole, error) {
	role, err := r.scanRole(r.db.QueryRow(ctx,
		`SELECT id, org_id, name, description, created_at, updated_at FROM org_roles WHERE id = $1`,
		id,
	))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("org_role: get_by_id: %w", err)
	}
	if err := r.fetchScopes(ctx, role); err != nil {
		return nil, err
	}
	return role, nil
}

// ListByOrg returns all roles belonging to an organization, with scopes populated.
func (r *PgxOrgRoleRepository) ListByOrg(ctx context.Context, orgID uuid.UUID) ([]*domain.OrgRole, error) {
	rows, err := r.db.Query(ctx,
		`SELECT id, org_id, name, description, created_at, updated_at
		 FROM org_roles WHERE org_id = $1 ORDER BY created_at ASC`,
		orgID,
	)
	if err != nil {
		return nil, fmt.Errorf("org_role: list_by_org: %w", err)
	}
	defer rows.Close()

	var roles []*domain.OrgRole
	for rows.Next() {
		role, err := r.scanRole(rows)
		if err != nil {
			return nil, err
		}
		roles = append(roles, role)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("org_role: list_by_org rows: %w", err)
	}

	for _, role := range roles {
		if err := r.fetchScopes(ctx, role); err != nil {
			return nil, err
		}
	}
	return roles, nil
}

// Update updates name and description of a role.
func (r *PgxOrgRoleRepository) Update(ctx context.Context, role *domain.OrgRole) error {
	role.UpdatedAt = time.Now()
	_, err := r.db.Exec(ctx,
		`UPDATE org_roles SET name = $1, description = $2, updated_at = $3 WHERE id = $4`,
		role.Name, role.Description, role.UpdatedAt, role.ID,
	)
	if err != nil {
		// UNIQUE (org_id, name): renaming into a collision is a client
		// conflict, not an unknown fault (THE-SIXTEEN-ELSES).
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return domain.ErrOrgRoleAlreadyExists
		}
		return fmt.Errorf("org_role: update: %w", err)
	}
	return nil
}

// Delete removes a role and cascades to org_role_scopes and user_roles.
func (r *PgxOrgRoleRepository) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.Exec(ctx, `DELETE FROM org_roles WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("org_role: delete: %w", err)
	}
	return nil
}

// AddScope inserts a scope binding for a role.
func (r *PgxOrgRoleRepository) AddScope(ctx context.Context, roleID, resourceID uuid.UUID, scopeName string) error {
	id, err := uuidgen.NewV7()
	if err != nil {
		return fmt.Errorf("org_role: add_scope: failed to generate id: %w", err)
	}
	_, err = r.db.Exec(ctx,
		`INSERT INTO org_role_scopes (id, role_id, resource_id, scope_name)
		 VALUES ($1, $2, $3, $4)
		 ON CONFLICT (role_id, scope_name) DO NOTHING`,
		id, roleID, resourceID, scopeName,
	)
	if err != nil {
		return fmt.Errorf("org_role: add_scope: %w", err)
	}
	return nil
}

// RemoveScope removes a scope binding from a role.
func (r *PgxOrgRoleRepository) RemoveScope(ctx context.Context, roleID uuid.UUID, scopeName string) error {
	_, err := r.db.Exec(ctx,
		`DELETE FROM org_role_scopes WHERE role_id = $1 AND scope_name = $2`,
		roleID, scopeName,
	)
	if err != nil {
		return fmt.Errorf("org_role: remove_scope: %w", err)
	}
	return nil
}

// AssignRoleToUser creates a user-role binding.
func (r *PgxOrgRoleRepository) AssignRoleToUser(ctx context.Context, userID, roleID, assignedBy uuid.UUID) error {
	id, err := uuidgen.NewV7()
	if err != nil {
		return fmt.Errorf("org_role: assign_role_to_user: failed to generate id: %w", err)
	}
	var assignedByPtr *uuid.UUID
	if assignedBy != uuid.Nil {
		assignedByPtr = &assignedBy
	}
	_, err = r.db.Exec(ctx,
		`INSERT INTO user_roles (id, user_id, role_id, assigned_by, assigned_at)
		 VALUES ($1, $2, $3, $4, $5)
		 ON CONFLICT (user_id, role_id) DO NOTHING`,
		id, userID, roleID, assignedByPtr, time.Now(),
	)
	if err != nil {
		return fmt.Errorf("org_role: assign_role_to_user: %w", err)
	}
	return nil
}

// RemoveRoleFromUser removes a user-role binding.
func (r *PgxOrgRoleRepository) RemoveRoleFromUser(ctx context.Context, userID, roleID uuid.UUID) error {
	_, err := r.db.Exec(ctx,
		`DELETE FROM user_roles WHERE user_id = $1 AND role_id = $2`,
		userID, roleID,
	)
	if err != nil {
		return fmt.Errorf("org_role: remove_role_from_user: %w", err)
	}
	return nil
}

// ListUserIDsForRole returns the user IDs of every user currently assigned to a role.
// Used by RemoveScope / DeleteRole to dispatch synchronous session revocation on demotion.
func (r *PgxOrgRoleRepository) ListUserIDsForRole(ctx context.Context, roleID uuid.UUID) ([]uuid.UUID, error) {
	rows, err := r.db.Query(ctx,
		`SELECT user_id FROM user_roles WHERE role_id = $1`,
		roleID,
	)
	if err != nil {
		return nil, fmt.Errorf("org_role: list_user_ids_for_role: %w", err)
	}
	defer rows.Close()

	var userIDs []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("org_role: list_user_ids_for_role scan: %w", err)
		}
		userIDs = append(userIDs, id)
	}
	return userIDs, rows.Err()
}

// ListRolesForUser returns all roles assigned to a user, with scopes populated.
func (r *PgxOrgRoleRepository) ListRolesForUser(ctx context.Context, userID uuid.UUID) ([]*domain.OrgRole, error) {
	rows, err := r.db.Query(ctx,
		`SELECT r.id, r.org_id, r.name, r.description, r.created_at, r.updated_at
		 FROM org_roles r
		 JOIN user_roles ur ON ur.role_id = r.id
		 WHERE ur.user_id = $1
		 ORDER BY r.created_at ASC`,
		userID,
	)
	if err != nil {
		return nil, fmt.Errorf("org_role: list_roles_for_user: %w", err)
	}
	defer rows.Close()

	var roles []*domain.OrgRole
	for rows.Next() {
		role, err := r.scanRole(rows)
		if err != nil {
			return nil, err
		}
		roles = append(roles, role)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("org_role: list_roles_for_user rows: %w", err)
	}

	for _, role := range roles {
		if err := r.fetchScopes(ctx, role); err != nil {
			return nil, err
		}
	}
	return roles, nil
}

// GetScopesForUser is the hot path used during token issuance.
// Returns the distinct union of all scope_name values from org_role_scopes
// for every role assigned to the user.
// When resourceID is non-nil, only scopes belonging to that API Resource are returned
// (audience filtering — prevents scope leakage across APIs).
func (r *PgxOrgRoleRepository) GetScopesForUser(ctx context.Context, userID uuid.UUID, resourceID *uuid.UUID) ([]string, error) {
	var (
		rows pgx.Rows
		err  error
	)
	if resourceID != nil {
		rows, err = r.db.Query(ctx,
			`SELECT DISTINCT ors.scope_name
			 FROM user_roles ur
			 JOIN org_role_scopes ors ON ors.role_id = ur.role_id
			 WHERE ur.user_id = $1 AND ors.resource_id = $2`,
			userID, *resourceID,
		)
	} else {
		rows, err = r.db.Query(ctx,
			`SELECT DISTINCT ors.scope_name
			 FROM user_roles ur
			 JOIN org_role_scopes ors ON ors.role_id = ur.role_id
			 WHERE ur.user_id = $1`,
			userID,
		)
	}
	if err != nil {
		return nil, fmt.Errorf("org_role: get_scopes_for_user: %w", err)
	}
	defer rows.Close()

	var scopes []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, fmt.Errorf("org_role: get_scopes_for_user scan: %w", err)
		}
		scopes = append(scopes, s)
	}
	return scopes, rows.Err()
}

// --- helpers ---

type scannable interface {
	Scan(dest ...any) error
}

func (r *PgxOrgRoleRepository) scanRole(row scannable) (*domain.OrgRole, error) {
	var role domain.OrgRole
	if err := row.Scan(
		&role.ID,
		&role.OrgID,
		&role.Name,
		&role.Description,
		&role.CreatedAt,
		&role.UpdatedAt,
	); err != nil {
		return nil, fmt.Errorf("org_role: scan: %w", err)
	}
	return &role, nil
}

func (r *PgxOrgRoleRepository) fetchScopes(ctx context.Context, role *domain.OrgRole) error {
	rows, err := r.db.Query(ctx,
		`SELECT scope_name FROM org_role_scopes WHERE role_id = $1 ORDER BY scope_name`,
		role.ID,
	)
	if err != nil {
		return fmt.Errorf("org_role: fetch_scopes: %w", err)
	}
	defer rows.Close()

	var scopes []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return fmt.Errorf("org_role: fetch_scopes scan: %w", err)
		}
		scopes = append(scopes, s)
	}
	role.Scopes = scopes
	return rows.Err()
}
