package postgres

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/repository"
)

// instanceSettingsID is migration 0043's singleton row.
const instanceSettingsID = "00000000-0000-7000-0000-000000000020"

// PgRegistrationRepository is repository.RegistrationRepository over pgx.
type PgRegistrationRepository struct{ db DBTX }

func NewPgRegistrationRepository(db DBTX) *PgRegistrationRepository {
	return &PgRegistrationRepository{db: db}
}

var _ repository.RegistrationRepository = (*PgRegistrationRepository)(nil)

func (r *PgRegistrationRepository) InstanceEnabled(ctx context.Context) (bool, error) {
	var on bool
	err := r.db.QueryRow(ctx, `SELECT self_registration_enabled FROM instance_settings WHERE id = $1`, instanceSettingsID).Scan(&on)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	return on, err
}

func (r *PgRegistrationRepository) SetInstanceEnabled(ctx context.Context, enabled bool) error {
	_, err := r.db.Exec(ctx, `
		INSERT INTO instance_settings (id, self_registration_enabled, updated_at) VALUES ($1, $2, NOW())
		ON CONFLICT (id) DO UPDATE SET self_registration_enabled = EXCLUDED.self_registration_enabled, updated_at = NOW()`,
		instanceSettingsID, enabled)
	return err
}

func (r *PgRegistrationRepository) OrgSettings(ctx context.Context, orgID uuid.UUID) (*domain.OrgRegistrationSettings, error) {
	var s domain.OrgRegistrationSettings
	err := r.db.QueryRow(ctx, `
		SELECT allow_public_registration, require_registration_approval, registration_verify_email, registration_email_domains
		FROM organizations WHERE id = $1 AND deleted_at IS NULL`, orgID).
		Scan(&s.Allow, &s.RequireApproval, &s.VerifyEmail, &s.EmailDomains)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrOrganizationNotFound
	}
	if err != nil {
		return nil, err
	}
	if s.EmailDomains == nil {
		s.EmailDomains = []string{}
	}
	return &s, nil
}

func (r *PgRegistrationRepository) UpdateOrgSettings(ctx context.Context, orgID uuid.UUID, s domain.OrgRegistrationSettings) error {
	if s.EmailDomains == nil {
		s.EmailDomains = []string{}
	}
	tag, err := r.db.Exec(ctx, `
		UPDATE organizations
		SET allow_public_registration = $2, require_registration_approval = $3,
		    registration_verify_email = $4, registration_email_domains = $5, updated_at = NOW()
		WHERE id = $1 AND deleted_at IS NULL`,
		orgID, s.Allow, s.RequireApproval, s.VerifyEmail, s.EmailDomains)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrOrganizationNotFound
	}
	return nil
}

func (r *PgRegistrationRepository) SetUserState(ctx context.Context, userID uuid.UUID, state string) error {
	tag, err := r.db.Exec(ctx, `UPDATE users SET registration_state = $2, updated_at = NOW() WHERE id = $1 AND deleted_at IS NULL`, userID, state)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrUserNotFound
	}
	return nil
}

func (r *PgRegistrationRepository) UserState(ctx context.Context, userID uuid.UUID) (string, bool, error) {
	var state *string
	var verify bool
	err := r.db.QueryRow(ctx, `
		SELECT u.registration_state, o.registration_verify_email
		FROM users u JOIN organizations o ON o.id = u.organization_id
		WHERE u.id = $1`, userID).Scan(&state, &verify)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, domain.ErrUserNotFound
	}
	if err != nil {
		return "", false, err
	}
	if state == nil {
		return "", verify, nil
	}
	return *state, verify, nil
}

func (r *PgRegistrationRepository) ListPending(ctx context.Context, orgID uuid.UUID) ([]domain.PendingRegistration, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, email, COALESCE(name, ''), created_at FROM users
		WHERE organization_id = $1 AND registration_state = 'pending_approval' AND deleted_at IS NULL
		ORDER BY created_at`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []domain.PendingRegistration{}
	for rows.Next() {
		var p domain.PendingRegistration
		if err := rows.Scan(&p.UserID, &p.Email, &p.Name, &p.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}
