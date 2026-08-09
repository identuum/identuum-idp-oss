package postgres

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/metrics"
	"github.com/identuum/identuum-idp-oss/internal/repository"
	"github.com/identuum/identuum-idp-oss/logger"
	"github.com/identuum/identuum-idp-oss/tools"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
)

// fallbackMaxSessionsPerUser is the safe default applied when an organization
// is created without an explicit positive MaxSessionsPerUser and the
// DEFAULT_MAX_SESSIONS_PER_USER environment override is unset / invalid.
const fallbackMaxSessionsPerUser = 5

// resolveDefaultMaxSessionsPerUser resolves the fallback per-org "max sessions
// per user" value from the DEFAULT_MAX_SESSIONS_PER_USER environment variable,
// defaulting to fallbackMaxSessionsPerUser (5) when the var is missing,
// non-numeric, or non-positive.
//
// Previously this value was read via viper.GetInt("DEFAULT_MAX_SESSIONS_PER_USER").
// viper was only ever configured inside the OSS config-loader package
// (since removed), which had no production caller (F1), so at runtime
// viper.AutomaticEnv was never invoked and the read
// always returned 0 — silently ignoring the operator's env override and pinning
// the effective value to the hardcoded 5 fallback. Reading os.Getenv directly
// makes the DEFAULT_MAX_SESSIONS_PER_USER knob actually take effect while
// preserving the same safe default. P-018: never panics; always returns a
// usable positive value.
func resolveDefaultMaxSessionsPerUser() int {
	if raw := os.Getenv("DEFAULT_MAX_SESSIONS_PER_USER"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			return n
		}
	}
	return fallbackMaxSessionsPerUser
}

// PgxOrganizationRepository implements repository.OrganizationRepository with pgx
type PgxOrganizationRepository struct {
	db DBTX
}

// NewPgxOrganizationRepository creates a new organization repository instance
func NewPgxOrganizationRepository(db DBTX) *PgxOrganizationRepository {
	return &PgxOrganizationRepository{
		db: db,
	}
}

// Compile-time interface checks
var _ repository.OrganizationRepository = (*PgxOrganizationRepository)(nil)
var _ repository.AdminOrganizationRepository = (*PgxOrganizationRepository)(nil)

// Create creates a new organization.
//
// Policy-field semantics (corrected 2026-06-24 by slice
// agent-a-20260716-idp-oss-orgrepo-create-honors-policy-fields):
//
//   - MaxSessionsPerUser: honored when the supplied struct value is > 0.
//     Zero or negative falls back to viper's DEFAULT_MAX_SESSIONS_PER_USER
//     env-config (which itself falls back to 5 when unset). The
//     domain.Organization.Validate() helper rejects values < 1, so a
//     service-layer caller will always pass a positive value here; only
//     test fixtures that call the repo directly + want the viper default
//     leave the field at zero.
//   - AuthPolicy: honored when non-empty; defaults to AuthPolicyLocalOnly.
//   - ApiAuthorizationPolicy: honored when non-empty; defaults to STRICT.
//   - All other policy fields (MFAPolicy, AllowPublicRegistration,
//     RequireRegistrationApproval, ServiceAccountExpiryDays,
//     M2MAnomalyLimit, M2MAnomalyWindowSeconds, RequireStrictReauth,
//     LocalAdminOnly, PasswordComplexityEnabled, ComplianceContactEmail)
//     are persisted verbatim from the struct.
//
// Known limitation: bool fields (LocalAdminOnly, PasswordComplexityEnabled,
// AllowPublicRegistration, RequireRegistrationApproval, RequireStrictReauth,
// Active) cannot distinguish "explicit false" from "omitted (zero-value
// false)" at the repository layer because the domain type uses bool rather
// than *bool. The migration's NOT NULL DEFAULT applies only when the
// INSERT omits the column — not when the INSERT supplies an explicit
// `false`. Callers who need the migration default for a bool field MUST
// either set the field explicitly OR use the Update path after Create.
// See Decision D-015 §4 LANDED + §9 LANDED for the per-field context.
// insertPrimaryDomainRow materializes the organization's OWN domain into
// organization_domains as the primary, verified row (v0.3.2 gap D). The
// domain was named at creation by the authority creating the org — trusted by
// construction, so it is recorded verified, exactly as migration 0029
// backfills existing orgs. MUST run inside the same transaction as the org
// insert: a committed org without its primary row recreates the gap.
func insertPrimaryDomainRow(ctx context.Context, tx pgx.Tx, orgID uuid.UUID, domainStr string) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO organization_domains
			(organization_id, domain, is_primary, verified_at, created_at, updated_at)
		VALUES ($1, $2, true, NOW(), NOW(), NOW())`,
		orgID, domainStr,
	)
	if err != nil {
		return fmt.Errorf("failed to materialize primary organization domain: %w", err)
	}
	return nil
}

func (r *PgxOrganizationRepository) Create(ctx context.Context, org *domain.Organization) (*domain.Organization, error) {
	maxSessions := org.MaxSessionsPerUser
	if maxSessions <= 0 {
		maxSessions = resolveDefaultMaxSessionsPerUser()
	}

	// Default to org name if slug not provided
	if org.OrgSlug == "" {
		org.OrgSlug = tools.GenerateSlug(org.Name)
	}

	// Default auth policy
	if org.AuthPolicy == "" {
		org.AuthPolicy = domain.AuthPolicyLocalOnly
	}

	if org.ApiAuthorizationPolicy == "" {
		org.ApiAuthorizationPolicy = domain.APIAuthPolicyStrict
	}

	// Start Timer
	timer := prometheus.NewTimer(metrics.DBQueryDuration.WithLabelValues("org_repo", "create", "all"))
	defer timer.ObserveDuration()

	// Transaction: the org insert and its primary-domain materialization
	// (gap D) commit or roll back together.
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to begin organization create transaction: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // rollback on any non-commit path

	// Insert and return all columns
	created, err := r.scanOrganization(tx.QueryRow(ctx, `
		INSERT INTO organizations (name, domain, org_slug, active, deleted_at, max_sessions_per_user, mfa_policy, auth_policy, api_authorization_policy, allow_public_registration, require_registration_approval, service_account_expiry_days, m2m_anomaly_limit, m2m_anomaly_window_seconds, require_strict_reauth, tier, local_admin_only, password_complexity_enabled, compliance_contact_email, created_at)
		VALUES ($1, $2, $3, $4, NULL, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, NOW())
		RETURNING id, name, domain, org_slug, active, deleted_at, max_sessions_per_user, mfa_policy, auth_policy, api_authorization_policy, allow_public_registration, require_registration_approval, service_account_expiry_days, m2m_anomaly_limit, m2m_anomaly_window_seconds, require_strict_reauth, tier, local_admin_only, password_complexity_enabled, compliance_contact_email, created_at, updated_at, last_scim_sync_at`,
		org.Name, org.Domain, org.OrgSlug, org.Active, maxSessions, org.MFAPolicy, org.AuthPolicy, org.ApiAuthorizationPolicy, org.AllowPublicRegistration, org.RequireRegistrationApproval, org.ServiceAccountExpiryDays, org.M2MAnomalyLimit, org.M2MAnomalyWindowSeconds, org.RequireStrictReauth, org.Tier.String(), org.LocalAdminOnly, org.PasswordComplexityEnabled, org.ComplianceContactEmail,
	))

	if err != nil {
		metrics.DBQueryDuration.WithLabelValues("org_repo", "create", "error").Observe(timer.ObserveDuration().Seconds())
		// Check for unique constraint violation
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			if strings.Contains(pgErr.ConstraintName, "org_slug") || strings.Contains(pgErr.Message, "org_slug") {
				return nil, domain.ErrOrganizationSlugAlreadyExists
			}
			if strings.Contains(pgErr.ConstraintName, "domain") || strings.Contains(pgErr.Message, "domain") {
				return nil, domain.ErrOrganizationAlreadyExists
			}
		}
		return nil, fmt.Errorf("failed to create organization: %w", err)
	}
	if err := insertPrimaryDomainRow(ctx, tx, created.ID, created.Domain); err != nil {
		metrics.DBQueryDuration.WithLabelValues("org_repo", "create", "error").Observe(timer.ObserveDuration().Seconds())
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("failed to commit organization create transaction: %w", err)
	}
	metrics.DBQueryDuration.WithLabelValues("org_repo", "create", "success").Observe(timer.ObserveDuration().Seconds())

	logger.InfoContext(ctx, "Created organization",
		zap.String("name", created.Name),
		zap.String("domain", created.Domain),
		zap.String("slug", created.OrgSlug),
	)
	return created, nil
}

// CreateWithAdmin atomically creates an organization and its first admin user in a single
// Postgres transaction. If the user INSERT fails, the org INSERT is rolled back, preventing
// dangling shell organizations.
func (r *PgxOrganizationRepository) CreateWithAdmin(ctx context.Context, org *domain.Organization, adminUser *domain.User) (*domain.Organization, *domain.User, error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // rollback on any non-commit path

	// --- Insert organization ---
	// Same policy-field semantics as Create (see Create doc-comment for the
	// per-field rules + the bool-zero-distinguishability limitation).
	maxSessions := org.MaxSessionsPerUser
	if maxSessions <= 0 {
		maxSessions = resolveDefaultMaxSessionsPerUser()
	}
	if org.OrgSlug == "" {
		org.OrgSlug = tools.GenerateSlug(org.Name)
	}
	if org.AuthPolicy == "" {
		org.AuthPolicy = domain.AuthPolicyLocalOnly
	}
	if org.ApiAuthorizationPolicy == "" {
		org.ApiAuthorizationPolicy = domain.APIAuthPolicyStrict
	}

	txOrgRepo := &PgxOrganizationRepository{db: tx}
	createdOrg, err := txOrgRepo.scanOrganization(tx.QueryRow(ctx, `
		INSERT INTO organizations (name, domain, org_slug, active, deleted_at, max_sessions_per_user, mfa_policy, auth_policy, api_authorization_policy, allow_public_registration, require_registration_approval, service_account_expiry_days, m2m_anomaly_limit, m2m_anomaly_window_seconds, require_strict_reauth, tier, local_admin_only, password_complexity_enabled, compliance_contact_email, created_at)
		VALUES ($1, $2, $3, $4, NULL, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, NOW())
		RETURNING id, name, domain, org_slug, active, deleted_at, max_sessions_per_user, mfa_policy, auth_policy, api_authorization_policy, allow_public_registration, require_registration_approval, service_account_expiry_days, m2m_anomaly_limit, m2m_anomaly_window_seconds, require_strict_reauth, tier, local_admin_only, password_complexity_enabled, compliance_contact_email, created_at, updated_at, last_scim_sync_at`,
		org.Name, org.Domain, org.OrgSlug, org.Active, maxSessions, org.MFAPolicy, org.AuthPolicy, org.ApiAuthorizationPolicy, org.AllowPublicRegistration, org.RequireRegistrationApproval, org.ServiceAccountExpiryDays, org.M2MAnomalyLimit, org.M2MAnomalyWindowSeconds, org.RequireStrictReauth, org.Tier.String(), org.LocalAdminOnly, org.PasswordComplexityEnabled, org.ComplianceContactEmail,
	))
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			if strings.Contains(pgErr.ConstraintName, "org_slug") || strings.Contains(pgErr.Message, "org_slug") {
				return nil, nil, domain.ErrOrganizationSlugAlreadyExists
			}
			if strings.Contains(pgErr.ConstraintName, "domain") || strings.Contains(pgErr.Message, "domain") {
				return nil, nil, domain.ErrOrganizationAlreadyExists
			}
		}
		return nil, nil, fmt.Errorf("failed to create organization: %w", err)
	}

	// Bind admin user to the newly created org
	adminUser.OrganizationID = createdOrg.ID

	// --- Insert admin user (same SQL as PgxUserRepository.Create) ---
	if adminUser.AuthSource == "" {
		adminUser.AuthSource = "local"
	}
	var orgIDArg *uuid.UUID
	if adminUser.OrganizationID != uuid.Nil {
		orgIDArg = &adminUser.OrganizationID
	}

	createdUser, err := (&PgxUserRepository{db: tx}).scanUser(tx.QueryRow(ctx, `
		INSERT INTO users (id, email, name, password_hash, role, organization_id, banned, email_verified, deleted_at, created_at, updated_at, auth_source, external_id, requires_password_change, oidc_linked, oidc_issuer, activation_token_expires_at, activation_token_hash, mfa_enabled, mfa_secret)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW(), NOW(), $10, $11, $12, $13, $14, $15, $16, $17, $18)
		RETURNING id, email, name, organization_id, role, banned, email_verified, deleted_at, created_at, updated_at, last_login_at, mfa_enabled, mfa_secret, mfa_recovery_codes, auth_source, external_id, requires_password_change, oidc_linked, oidc_issuer, activation_token_expires_at, activation_token_hash, verification_token_hash`,
		adminUser.ID, adminUser.Email, adminUser.Name, adminUser.PasswordHash,
		string(adminUser.Role), orgIDArg, adminUser.Banned, adminUser.EmailVerified, adminUser.DeletedAt,
		adminUser.AuthSource, adminUser.ExternalID, adminUser.RequiresPasswordChange,
		adminUser.OIDCLinked, adminUser.OIDCIssuer, adminUser.ActivationTokenExpiresAt,
		adminUser.ActivationTokenHash,
		adminUser.MFAEnabled, adminUser.MFASecret,
	))
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return nil, nil, domain.ErrUserAlreadyExists
		}
		return nil, nil, fmt.Errorf("failed to create admin user: %w", err)
	}

	// Gap D: the org's primary domain row commits with the org itself.
	if err := insertPrimaryDomainRow(ctx, tx, createdOrg.ID, createdOrg.Domain); err != nil {
		return nil, nil, err
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, nil, fmt.Errorf("failed to commit organization provisioning transaction: %w", err)
	}

	logger.InfoContext(ctx, "Atomically created organization with admin user",
		zap.String("org_id", createdOrg.ID.String()),
		zap.String("org_name", createdOrg.Name),
		zap.String("admin_email", createdUser.Email),
	)
	return createdOrg, createdUser, nil
}

func (r *PgxOrganizationRepository) GetByID(ctx context.Context, id uuid.UUID) (*domain.Organization, error) {
	// Start Timer
	timer := prometheus.NewTimer(metrics.DBQueryDuration.WithLabelValues("org_repo", "get_by_id", "all"))
	defer timer.ObserveDuration()

	org, err := r.scanOrganization(r.db.QueryRow(ctx, `
		SELECT id, name, domain, org_slug, active, deleted_at, max_sessions_per_user, mfa_policy, auth_policy, api_authorization_policy, allow_public_registration, require_registration_approval, service_account_expiry_days, m2m_anomaly_limit, m2m_anomaly_window_seconds, require_strict_reauth, tier, local_admin_only, password_complexity_enabled, compliance_contact_email, created_at, updated_at, last_scim_sync_at
		FROM organizations
		WHERE id = $1 AND active = true AND deleted_at IS NULL
	`, id))

	if err != nil {
		metrics.DBQueryDuration.WithLabelValues("org_repo", "get_by_id", "error").Observe(timer.ObserveDuration().Seconds())
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrOrganizationNotFound
		}
		return nil, fmt.Errorf("failed to get organization: %w", err)
	}
	metrics.DBQueryDuration.WithLabelValues("org_repo", "get_by_id", "success").Observe(timer.ObserveDuration().Seconds())

	return org, nil
}

// GetByDomain retrieves an organization by domain (only not deleted)
func (r *PgxOrganizationRepository) GetByDomain(ctx context.Context, domainName string) (*domain.Organization, error) {
	org, err := r.scanOrganization(r.db.QueryRow(ctx, `
		SELECT id, name, domain, org_slug, active, deleted_at, max_sessions_per_user, mfa_policy, auth_policy, api_authorization_policy, allow_public_registration, require_registration_approval, service_account_expiry_days, m2m_anomaly_limit, m2m_anomaly_window_seconds, require_strict_reauth, tier, local_admin_only, password_complexity_enabled, compliance_contact_email, created_at, updated_at, last_scim_sync_at
		FROM organizations
		WHERE domain = $1 AND deleted_at IS NULL`,
		domainName,
	))

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrOrganizationNotFound
		}
		return nil, fmt.Errorf("failed to get organization by domain: %w", err)
	}

	return org, nil
}

// GetBySlug retrieves an organization by slug (only not deleted)
func (r *PgxOrganizationRepository) GetBySlug(ctx context.Context, slug string) (*domain.Organization, error) {
	org, err := r.scanOrganization(r.db.QueryRow(ctx, `
		SELECT id, name, domain, org_slug, active, deleted_at, max_sessions_per_user, mfa_policy, auth_policy, api_authorization_policy, allow_public_registration, require_registration_approval, service_account_expiry_days, m2m_anomaly_limit, m2m_anomaly_window_seconds, require_strict_reauth, tier, local_admin_only, password_complexity_enabled, compliance_contact_email, created_at, updated_at, last_scim_sync_at
		FROM organizations
		WHERE org_slug = $1 AND deleted_at IS NULL`,
		slug,
	))

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrOrganizationNotFound
		}
		return nil, fmt.Errorf("failed to get organization by slug: %w", err)
	}

	return org, nil
}

// Update updates an organization
func (r *PgxOrganizationRepository) Update(ctx context.Context, id uuid.UUID, opts repository.UpdateOrganizationOptions) (*domain.Organization, error) {

	// Build dynamic update query
	setParts := []string{}
	args := []any{}
	argIndex := 1

	if opts.Name != nil {
		setParts = append(setParts, fmt.Sprintf("name = $%d", argIndex))
		args = append(args, *opts.Name)
		argIndex++
	}

	if opts.Domain != nil {
		setParts = append(setParts, fmt.Sprintf("domain = $%d", argIndex))
		args = append(args, *opts.Domain)
		argIndex++
	}

	if opts.Active != nil {
		setParts = append(setParts, fmt.Sprintf("active = $%d", argIndex))
		args = append(args, *opts.Active)
		argIndex++
	}

	if opts.MaxSessionsPerUser != nil {
		setParts = append(setParts, fmt.Sprintf("max_sessions_per_user = $%d", argIndex))
		args = append(args, *opts.MaxSessionsPerUser)
		argIndex++
	}

	if opts.MFAPolicy != nil {
		setParts = append(setParts, fmt.Sprintf("mfa_policy = $%d", argIndex))
		args = append(args, *opts.MFAPolicy)
		argIndex++
	}

	if opts.AuthPolicy != nil {
		setParts = append(setParts, fmt.Sprintf("auth_policy = $%d", argIndex))
		args = append(args, *opts.AuthPolicy)
		argIndex++
	}

	if opts.ApiAuthorizationPolicy != nil {
		setParts = append(setParts, fmt.Sprintf("api_authorization_policy = $%d", argIndex))
		args = append(args, *opts.ApiAuthorizationPolicy)
		argIndex++
	}

	if opts.ServiceAccountExpiryDays != nil {
		setParts = append(setParts, fmt.Sprintf("service_account_expiry_days = $%d", argIndex))
		args = append(args, *opts.ServiceAccountExpiryDays)
		argIndex++
	}

	if opts.AllowPublicRegistration != nil {
		setParts = append(setParts, fmt.Sprintf("allow_public_registration = $%d", argIndex))
		args = append(args, *opts.AllowPublicRegistration)
		argIndex++
	}

	if opts.RequireRegistrationApproval != nil {
		setParts = append(setParts, fmt.Sprintf("require_registration_approval = $%d", argIndex))
		args = append(args, *opts.RequireRegistrationApproval)
		argIndex++
	}

	if opts.M2MAnomalyLimit != nil {
		setParts = append(setParts, fmt.Sprintf("m2m_anomaly_limit = $%d", argIndex))
		args = append(args, *opts.M2MAnomalyLimit)
		argIndex++
	}

	if opts.M2MAnomalyWindowSeconds != nil {
		setParts = append(setParts, fmt.Sprintf("m2m_anomaly_window_seconds = $%d", argIndex))
		args = append(args, *opts.M2MAnomalyWindowSeconds)
		argIndex++
	}

	if opts.RequireStrictReauth != nil {
		setParts = append(setParts, fmt.Sprintf("require_strict_reauth = $%d", argIndex))
		args = append(args, *opts.RequireStrictReauth)
		argIndex++
	}

	if opts.Tier != nil {
		setParts = append(setParts, fmt.Sprintf("tier = $%d", argIndex))
		args = append(args, opts.Tier.String())
		argIndex++
	}

	if opts.LocalAdminOnly != nil {
		setParts = append(setParts, fmt.Sprintf("local_admin_only = $%d", argIndex))
		args = append(args, *opts.LocalAdminOnly)
		argIndex++
	}

	if opts.PasswordComplexityEnabled != nil {
		setParts = append(setParts, fmt.Sprintf("password_complexity_enabled = $%d", argIndex))
		args = append(args, *opts.PasswordComplexityEnabled)
		argIndex++
	}

	if opts.ComplianceContactEmail != nil {
		setParts = append(setParts, fmt.Sprintf("compliance_contact_email = $%d", argIndex))
		args = append(args, *opts.ComplianceContactEmail)
		argIndex++
	}

	// 4.4g.4b re-narrowing: AG branches dropped (third-party agent issuance,
	// user-initiated agents, consent-per-session, CBAA poll, agent issuance
	// rate-limit overrides, agent webhook domain allowlist, reviewer-side ACR
	// floor / freshness, ADC chain-depth override, ID-JAG issuance/consumption,
	// ID-JAG assertion lifetime, default max input/session tokens, ITDR
	// Cluster 1/2/Phase-1 columns, default consent IdP pointer). The IdP
	// organizations schema does not carry these columns; AG carries the
	// per-org agentic-settings update path.

	// If no fields to update, just return the current org
	if len(setParts) == 0 {
		return r.GetByID(ctx, id)
	}

	query := fmt.Sprintf(`
		UPDATE organizations
		SET %s
		WHERE id = $%d
		RETURNING id, name, domain, org_slug, active, deleted_at, max_sessions_per_user, mfa_policy, auth_policy, api_authorization_policy, allow_public_registration, require_registration_approval, service_account_expiry_days, m2m_anomaly_limit, m2m_anomaly_window_seconds, require_strict_reauth, tier, local_admin_only, password_complexity_enabled, compliance_contact_email, created_at, updated_at, last_scim_sync_at`,
		strings.Join(setParts, ", "), argIndex)
	args = append(args, id)

	org, err := r.scanOrganization(r.db.QueryRow(ctx, query, args...))

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrOrganizationNotFound
		}
		return nil, fmt.Errorf("failed to update organization: %w", err)
	}

	logger.InfoContext(ctx, "Updated organization",
		zap.String("name", org.Name),
		zap.String("org_id", id.String()),
	)
	return org, nil
}

// Delete soft deletes an organization and all its users in a transaction
func (r *PgxOrganizationRepository) Delete(ctx context.Context, id uuid.UUID) error {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	now := time.Now()

	// Users
	_, err = tx.Exec(ctx, `
		UPDATE users 
		SET deleted_at = $1
		WHERE organization_id = $2 AND deleted_at IS NULL`, now, id)
	if err != nil {
		return fmt.Errorf("failed to delete organization users: %w", err)
	}

	// Service Accounts
	_, err = tx.Exec(ctx, `
		UPDATE service_accounts
		SET deleted_at = $1
		WHERE organization_id = $2 AND deleted_at IS NULL`, now, id)
	if err != nil {
		return fmt.Errorf("failed to cascade-delete service accounts: %w", err)
	}

	// Identity Providers
	_, err = tx.Exec(ctx, `
		UPDATE identity_providers
		SET deleted_at = $1
		WHERE organization_id = $2 AND deleted_at IS NULL`, now, id)
	if err != nil {
		return fmt.Errorf("failed to cascade-delete identity providers: %w", err)
	}

	// OAuth Clients
	_, err = tx.Exec(ctx, `
		UPDATE oauth_clients
		SET deleted_at = $1
		WHERE organization_id = $2 AND deleted_at IS NULL`, now, id)
	if err != nil {
		return fmt.Errorf("failed to cascade-delete oauth clients: %w", err)
	}

	// P0-3b: proactively REVOKE the org's live long-lived credentials as
	// defense-in-depth, ATOMIC with the cascade above (any error rolls the
	// whole tx back via the deferred Rollback). Without this, sessions
	// (days) and refresh tokens (30d) survived a soft-delete to their own
	// expiry, leaving use-time org-liveness (P0-3/4/5) as the single layer.
	// These tables have no deleted_at, so they are org-scoped via the org's
	// user set (sessions/refresh: no org column) or their own organization_id
	// column (oidc_states/auth codes). The users were soft-deleted above, but
	// the org-scoping subqueries key on organization_id (not deleted_at), so
	// they still resolve the org's user ids.

	// Sessions — mirror PgxSessionRepository.RevokeByOrganizationID exactly.
	_, err = tx.Exec(ctx, `
		UPDATE sessions
		SET revoked_at = NOW(),
		    revoked_reason = 'organization_deleted',
		    is_valid = false
		WHERE user_id IN (SELECT id FROM users WHERE organization_id = $1)
		  AND revoked_at IS NULL`, id)
	if err != nil {
		return fmt.Errorf("failed to revoke organization sessions: %w", err)
	}

	// Refresh tokens — subject-keyed (subject = user UUID string); no org col.
	_, err = tx.Exec(ctx, `
		UPDATE oauth_refresh_tokens
		SET revoked_at = NOW()
		WHERE subject IN (SELECT id::text FROM users WHERE organization_id = $1)
		  AND revoked_at IS NULL`, id)
	if err != nil {
		return fmt.Errorf("failed to revoke organization refresh tokens: %w", err)
	}

	// OIDC states — has organization_id. (The FK's ON DELETE CASCADE never
	// fires because this is a SOFT delete, so the rows must be removed here.)
	_, err = tx.Exec(ctx, `DELETE FROM oidc_states WHERE organization_id = $1`, id)
	if err != nil {
		return fmt.Errorf("failed to delete organization oidc states: %w", err)
	}

	// Authorization codes — org-scopable (has organization_id); burn any
	// live (unconsumed) codes via the table's own consumed_at lifecycle so a
	// leaked code cannot be exchanged after the org is deleted. Short-TTL, so
	// this is belt-and-braces alongside use-time liveness.
	_, err = tx.Exec(ctx, `
		UPDATE oauth_authorization_codes
		SET consumed_at = NOW()
		WHERE organization_id = $1 AND consumed_at IS NULL`, id)
	if err != nil {
		return fmt.Errorf("failed to invalidate organization authorization codes: %w", err)
	}

	// Finally mark the organization itself as deleted
	result, err := tx.Exec(ctx, `
		UPDATE organizations
		SET deleted_at = $1
		WHERE id = $2 AND deleted_at IS NULL`,
		now, id,
	)

	if err != nil {
		return fmt.Errorf("failed to delete organization: %w", err)
	}

	rowsAffected := result.RowsAffected()

	if rowsAffected == 0 {
		return domain.ErrOrganizationNotFound
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("failed to commit delete transaction: %w", err)
	}

	logger.InfoContext(ctx, "Deleted organization", zap.String("org_id", id.String()))
	return nil
}

// Undelete undeletes an organization and its users in a transaction
func (r *PgxOrganizationRepository) Undelete(ctx context.Context, id uuid.UUID) error {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	// Fetch the org's deleted_at — the SINGLE shared instant Delete stamped
	// on the org AND every child it cascaded (Delete writes one Go
	// time.Now() to the org + users/service_accounts/identity_providers/
	// oauth_clients in one tx, so org.deleted_at == every cascade-child's
	// deleted_at EXACTLY). Restoring children on an EXACT match of that
	// instant is the precise inverse of the cascade: it resurrects exactly
	// the set Delete soft-deleted, and no more.
	//
	// P2-14: the prior `deleted_at BETWEEN orgDeletedAt-2s AND +2s` window
	// was over-inclusive and had no basis — a child INDEPENDENTLY deleted
	// within 2s of the org delete (a DIFFERENT instant) was wrongly
	// resurrected. Exact match leaves any independently-deleted child
	// (different deleted_at, near or far) untouched — it STAYS deleted.
	var orgDeletedAt *time.Time
	err = tx.QueryRow(ctx, "SELECT deleted_at FROM organizations WHERE id = $1", id).Scan(&orgDeletedAt)
	if err != nil {
		if err.Error() == "no rows in result set" {
			return domain.ErrOrganizationNotFound
		}
		return fmt.Errorf("failed to fetch organization deleted_at: %w", err)
	}

	if orgDeletedAt == nil {
		return fmt.Errorf("organization is not deleted")
	}

	// Users
	result, err := tx.Exec(ctx, `
		UPDATE users
		SET deleted_at = NULL
		WHERE organization_id = $1 AND deleted_at = $2`, id, *orgDeletedAt)
	if err != nil {
		return fmt.Errorf("failed to undelete users: %w", err)
	}
	rowsAffected := result.RowsAffected()

	// Service Accounts
	_, err = tx.Exec(ctx, `
		UPDATE service_accounts
		SET deleted_at = NULL
		WHERE organization_id = $1 AND deleted_at = $2`, id, *orgDeletedAt)
	if err != nil {
		return fmt.Errorf("failed to cascade-undelete service accounts: %w", err)
	}

	// Identity Providers
	_, err = tx.Exec(ctx, `
		UPDATE identity_providers
		SET deleted_at = NULL
		WHERE organization_id = $1 AND deleted_at = $2`, id, *orgDeletedAt)
	if err != nil {
		return fmt.Errorf("failed to cascade-undelete identity providers: %w", err)
	}

	// OAuth Clients
	_, err = tx.Exec(ctx, `
		UPDATE oauth_clients
		SET deleted_at = NULL
		WHERE organization_id = $1 AND deleted_at = $2`, id, *orgDeletedAt)
	if err != nil {
		return fmt.Errorf("failed to cascade-undelete oauth clients: %w", err)
	}

	// Finally undelete the organization
	_, err = tx.Exec(ctx, `
		UPDATE organizations 
		SET deleted_at = NULL 
		WHERE id = $1 AND deleted_at IS NOT NULL`, id)
	if err != nil {
		return fmt.Errorf("failed to undelete organization: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("failed to commit undelete transaction: %w", err)
	}

	logger.InfoContext(ctx, "Undeleted organization",
		zap.String("org_id", id.String()),
		zap.Int64("users_restored", rowsAffected),
	)

	return nil
}

// List retrieves organizations with filters and pagination
func (r *PgxOrganizationRepository) List(ctx context.Context, filter repository.OrganizationFilter,
	pagination repository.Pagination, sort repository.Sort) ([]*domain.Organization, int, error) {

	var conditions []string
	var args []any
	argIndex := 1

	// Build WHERE conditions
	if filter.Search != "" {
		conditions = append(conditions, fmt.Sprintf("(name ILIKE $%d OR domain ILIKE $%d)", argIndex, argIndex))
		args = append(args, "%"+filter.Search+"%")
		argIndex++
	}

	if filter.Name != "" {
		conditions = append(conditions, fmt.Sprintf("name ILIKE $%d", argIndex))
		args = append(args, "%"+filter.Name+"%")
		argIndex++
	}

	if filter.Domain != "" {
		conditions = append(conditions, fmt.Sprintf("domain ILIKE $%d", argIndex))
		args = append(args, "%"+filter.Domain+"%")
		argIndex++
	}

	if filter.Active != nil {
		conditions = append(conditions, fmt.Sprintf("active = $%d", argIndex))
		args = append(args, *filter.Active)
		argIndex++
	} else if !filter.IncludeInactive {
		conditions = append(conditions, fmt.Sprintf("active = $%d", argIndex))
		args = append(args, true)
		argIndex++
	}

	if filter.Deleted != nil {
		if *filter.Deleted {
			conditions = append(conditions, "deleted_at IS NOT NULL")
		} else {
			conditions = append(conditions, "deleted_at IS NULL")
		}
	} else if !filter.IncludeDeleted {
		conditions = append(conditions, "deleted_at IS NULL")
	}

	// Always exclude System Organization from general lists
	conditions = append(conditions, fmt.Sprintf("id != $%d", argIndex))
	args = append(args, domain.SystemOrgID)
	argIndex++

	// Build WHERE clause
	whereClause := ""
	if len(conditions) > 0 {
		whereClause = " WHERE " + strings.Join(conditions, " AND ")
	}

	// Build ORDER BY clause
	orderBy := "updated_at DESC" // default: most recently modified first
	if sort.Field != "" {
		// Validate sort field to prevent SQL injection
		validSortFields := map[string]bool{
			"id": true, "name": true, "domain": true,
			"active": true, "deleted_at": true, "created_at": true, "updated_at": true,
		}

		if validSortFields[sort.Field] {
			orderDirection := "ASC"
			if sort.Desc {
				orderDirection = "DESC"
			}
			orderBy = fmt.Sprintf("%s %s", sort.Field, orderDirection)
		} else {
			logger.Warning.Printf("Invalid sort field ignored: %s", sort.Field)
		}
	}

	// Build main query with Window Function for Total Count
	var sb strings.Builder
	sb.WriteString("SELECT id, name, domain, org_slug, active, deleted_at, max_sessions_per_user, mfa_policy, auth_policy, api_authorization_policy, allow_public_registration, require_registration_approval, service_account_expiry_days, m2m_anomaly_limit, m2m_anomaly_window_seconds, require_strict_reauth, tier, local_admin_only, password_complexity_enabled, compliance_contact_email, created_at, updated_at, last_scim_sync_at, COUNT(*) OVER() AS total_count FROM organizations")
	sb.WriteString(whereClause)
	sb.WriteString(" ORDER BY ")
	sb.WriteString(orderBy)
	query := sb.String()

	// Add pagination
	if pagination.PageSize > 0 {
		query += fmt.Sprintf(" LIMIT $%d OFFSET $%d", argIndex, argIndex+1)
		args = append(args, pagination.PageSize, pagination.Offset)
	}

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list organizations: %w", err)
	}
	defer rows.Close()

	organizations := []*domain.Organization{}
	var totalCount int

	for rows.Next() {
		var org domain.Organization
		var tierStr string

		// We scan all organization fields + total_count
		err := rows.Scan(
			&org.ID, &org.Name, &org.Domain, &org.OrgSlug, &org.Active, &org.DeletedAt,
			&org.MaxSessionsPerUser, &org.MFAPolicy, &org.AuthPolicy, &org.ApiAuthorizationPolicy,
			&org.AllowPublicRegistration, &org.RequireRegistrationApproval, &org.ServiceAccountExpiryDays,
			&org.M2MAnomalyLimit, &org.M2MAnomalyWindowSeconds, &org.RequireStrictReauth, &tierStr,
			&org.LocalAdminOnly, &org.PasswordComplexityEnabled, &org.ComplianceContactEmail,
			&org.CreatedAt, &org.UpdatedAt, &org.LastSCIMSyncAt,
			&totalCount,
		)
		org.Tier = domain.ParseTier(tierStr)

		if err != nil {
			return nil, 0, fmt.Errorf("failed to scan organization: %w", err)
		}
		organizations = append(organizations, &org)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error iterating organizations: %w", err)
	}

	return organizations, totalCount, nil
}

// ListAll lists all organizations including deleted (for admin use)
func (r *PgxOrganizationRepository) ListAll(ctx context.Context, filter repository.OrganizationFilter,
	pagination repository.Pagination, sort repository.Sort) ([]*domain.Organization, int, error) {
	// Enable wildcard defaults for admin view
	filter.IncludeDeleted = true
	filter.IncludeInactive = true
	return r.List(ctx, filter, pagination, sort)
}

// ListDeleted retrieves deleted organizations with pagination
func (r *PgxOrganizationRepository) ListDeleted(ctx context.Context, pagination repository.Pagination) ([]*domain.Organization, int, error) {
	// Build query with Window Function
	query := `
		SELECT id, name, domain, org_slug, active, deleted_at, max_sessions_per_user, mfa_policy, auth_policy, api_authorization_policy, allow_public_registration, require_registration_approval, service_account_expiry_days, m2m_anomaly_limit, m2m_anomaly_window_seconds, require_strict_reauth, tier, local_admin_only, password_complexity_enabled, compliance_contact_email, created_at, updated_at, last_scim_sync_at, COUNT(*) OVER() AS total_count
		FROM organizations
		WHERE deleted_at IS NOT NULL
		ORDER BY updated_at DESC`

	var args []any
	if pagination.PageSize > 0 {
		query += " LIMIT $1 OFFSET $2"
		args = append(args, pagination.PageSize, pagination.Offset)
	}

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list deleted organizations: %w", err)
	}
	defer rows.Close()

	orgs := []*domain.Organization{}
	var totalCount int

	for rows.Next() {
		var org domain.Organization
		var tierStr string
		// Scan all fields + total_count
		err := rows.Scan(
			&org.ID, &org.Name, &org.Domain, &org.OrgSlug, &org.Active, &org.DeletedAt,
			&org.MaxSessionsPerUser, &org.MFAPolicy, &org.AuthPolicy, &org.ApiAuthorizationPolicy,
			&org.AllowPublicRegistration, &org.RequireRegistrationApproval, &org.ServiceAccountExpiryDays,
			&org.M2MAnomalyLimit, &org.M2MAnomalyWindowSeconds, &org.RequireStrictReauth, &tierStr,
			&org.LocalAdminOnly, &org.PasswordComplexityEnabled, &org.ComplianceContactEmail,
			&org.CreatedAt, &org.UpdatedAt, &org.LastSCIMSyncAt,
			&totalCount,
		)
		org.Tier = domain.ParseTier(tierStr)

		if err != nil {
			return nil, 0, fmt.Errorf("failed to scan deleted organization: %w", err)
		}
		orgs = append(orgs, &org)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error iterating deleted organizations: %w", err)
	}

	return orgs, totalCount, nil
}

// CountUsers counts users in an organization
func (r *PgxOrganizationRepository) CountUsers(ctx context.Context, id uuid.UUID) (int, error) {
	var count int
	err := r.db.QueryRow(ctx, `
		SELECT COUNT(*) FROM users WHERE organization_id = $1 AND deleted_at IS NULL`,
		id,
	).Scan(&count)

	if err != nil {
		return 0, fmt.Errorf("failed to count users in organization: %w", err)
	}

	return count, nil
}

// CountSessions counts sessions in an organization
func (r *PgxOrganizationRepository) CountSessions(ctx context.Context, id uuid.UUID) (int, error) {
	var count int
	err := r.db.QueryRow(ctx, `
		SELECT COUNT(*) 
		FROM sessions s 
		JOIN users u ON s.user_id = u.id 
		WHERE u.organization_id = $1 AND s.is_valid = true AND s.revoked_at IS NULL AND s.expires_at > NOW()`,
		id,
	).Scan(&count)

	if err != nil {
		return 0, fmt.Errorf("failed to count sessions in organization: %w", err)
	}

	return count, nil
}

// GetDetails retrieves organization with statistics
func (r *PgxOrganizationRepository) GetDetails(ctx context.Context, id uuid.UUID) (*domain.Organization, map[string]int, error) {
	org, err := r.GetByID(ctx, id)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get organization details: %w", err)
	}

	userCount, err := r.CountUsers(ctx, id)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get organization user count: %w", err)
	}

	sessionCount, _ := r.CountSessions(ctx, id)
	// Ignore session count error for now

	stats := map[string]int{
		"user_count":    userCount,
		"session_count": sessionCount,
	}

	return org, stats, nil
}

// === AdminOrganizationRepository interface implementation ===

// GetDetailsAdmin retrieves organization details including statistics (admin only, includes inactive/deleted)
func (r *PgxOrganizationRepository) GetDetailsAdmin(ctx context.Context, id uuid.UUID) (*domain.Organization, map[string]int, error) {
	org, err := r.GetByIDAdmin(ctx, id)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get organization details (admin): %w", err)
	}

	userCount, err := r.CountUsers(ctx, id)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get organization user count: %w", err)
	}

	sessionCount, _ := r.CountSessions(ctx, id)

	stats := map[string]int{
		"user_count":    userCount,
		"session_count": sessionCount,
	}

	return org, stats, nil
}

// GetByIDAdmin retrieves an organization by ID without filtering by active status
func (r *PgxOrganizationRepository) GetByIDAdmin(ctx context.Context, id uuid.UUID) (*domain.Organization, error) {
	org, err := r.scanOrganization(r.db.QueryRow(ctx, `
		SELECT id, name, domain, org_slug, active, deleted_at, max_sessions_per_user, mfa_policy, auth_policy, api_authorization_policy, allow_public_registration, require_registration_approval, service_account_expiry_days, m2m_anomaly_limit, m2m_anomaly_window_seconds, require_strict_reauth, tier, local_admin_only, password_complexity_enabled, compliance_contact_email, created_at, updated_at, last_scim_sync_at
		FROM organizations
		WHERE id = $1
	`, id))

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrOrganizationNotFound
		}
		return nil, fmt.Errorf("failed to get organization: %w", err)
	}

	return org, nil
}

// HardDelete is not supported - use soft delete instead
func (r *PgxOrganizationRepository) HardDelete(_ context.Context, _ uuid.UUID) error {
	return fmt.Errorf("hard delete not supported, use soft delete instead")
}

// HardDeleteE2EFixtureOrganization is a LOCAL/TEST-ONLY hard-delete primitive
// used exclusively by the --e2e-purge-org-fixture CLI command. It refuses to
// delete any row whose e2e_fixture_marker column does not exactly match the
// expected literal. The marker check is enforced in the SQL WHERE clause
// itself, so a Go-side bypass of the marker check cannot trigger this delete
// for a real production organization.
//
// All dependent rows (users, sessions, audit_events.actor_organization_id,
// etc.) cascade automatically via the FK ON DELETE CASCADE clauses defined
// in migrations 0001–0025 (audit_events.actor_organization_id gained its
// ON DELETE CASCADE FK in 0025). See LOCAL_DOCKER_COMPOSE.md for the audit-cascade
// contract.
//
// Returns ErrOrganizationNotFound when RowsAffected == 0 (org does not exist
// OR marker does not match). The caller MUST check ErrOrganizationNotFound
// and refuse to delete the fixture file when this error returns.
//
// SAFETY: this method MUST NOT be exposed through any service-layer or
// public-API path. It is package-public only because internal/cli lives in
// a different Go package; it should never be called from any other call
// site than the fixture CLI.
func (r *PgxOrganizationRepository) HardDeleteE2EFixtureOrganization(ctx context.Context, id uuid.UUID, marker string) error {
	if marker == "" {
		return fmt.Errorf("hard-delete refusal: empty fixture marker")
	}
	tag, err := r.db.Exec(ctx,
		`DELETE FROM organizations WHERE id = $1 AND e2e_fixture_marker = $2`,
		id, marker,
	)
	if err != nil {
		return fmt.Errorf("e2e fixture hard-delete failed: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrOrganizationNotFound
	}
	return nil
}

// scanOrganization helper to scan consistent organization columns.
//
// 4.4g.4b re-narrowing: AG-only columns dropped from the scan. The IdP
// organizations schema does not carry these columns.
func (r *PgxOrganizationRepository) scanOrganization(row pgx.Row) (*domain.Organization, error) {
	var org domain.Organization
	var tierStr string
	err := row.Scan(
		&org.ID, &org.Name, &org.Domain, &org.OrgSlug, &org.Active, &org.DeletedAt,
		&org.MaxSessionsPerUser, &org.MFAPolicy, &org.AuthPolicy, &org.ApiAuthorizationPolicy,
		&org.AllowPublicRegistration, &org.RequireRegistrationApproval, &org.ServiceAccountExpiryDays,
		&org.M2MAnomalyLimit, &org.M2MAnomalyWindowSeconds, &org.RequireStrictReauth, &tierStr,
		&org.LocalAdminOnly, &org.PasswordComplexityEnabled, &org.ComplianceContactEmail,
		&org.CreatedAt, &org.UpdatedAt, &org.LastSCIMSyncAt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to scan organization: %w", err)
	}

	org.Tier = domain.ParseTier(tierStr)

	return &org, nil
}

// UpdateID updates an organization's ID (Admin Only - Danger)
func (r *PgxOrganizationRepository) UpdateID(ctx context.Context, oldID, newID uuid.UUID) error {
	// 1. Check if new ID already exists
	var count int
	err := r.db.QueryRow(ctx, "SELECT COUNT(*) FROM organizations WHERE id = $1", newID).Scan(&count)
	if err != nil {
		return fmt.Errorf("failed to check for existing new ID: %w", err)
	}
	if count > 0 {
		return fmt.Errorf("target ID %s already exists", newID)
	}

	// 2. Perform Update in Transaction
	result, err := r.db.Exec(ctx, "UPDATE organizations SET id = $1 WHERE id = $2", newID, oldID)
	if err != nil {
		logger.Error.Printf("Failed to update organization ID from %s to %s: %v", oldID, newID, err)
		return fmt.Errorf("failed to update organization ID: %w", err)
	}

	rows := result.RowsAffected()
	if rows == 0 {
		return domain.ErrOrganizationNotFound
	}

	logger.Info.Printf("Migrated Organization ID %s -> %s", oldID, newID)
	return nil
}
