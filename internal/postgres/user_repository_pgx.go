package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/identuum/identuum-idp-oss/internal/crypto"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/metrics"
	"github.com/identuum/identuum-idp-oss/internal/repository"
	"github.com/identuum/identuum-idp-oss/logger"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
)

// PgxUserRepository implements UserRepository with pgx
type PgxUserRepository struct {
	db DBTX
}

// NewPgxUserRepository creates a new pgx user repository
func NewPgxUserRepository(db DBTX) *PgxUserRepository {
	return &PgxUserRepository{
		db: db,
	}
}

// Compile-time interface checks
var _ repository.UserRepository = (*PgxUserRepository)(nil)
var _ repository.AdminUserRepository = (*PgxUserRepository)(nil)

// scanUser helper for consistent user scanning (standard fields)
func (r *PgxUserRepository) scanUser(row pgx.Row) (*domain.User, error) {
	var user domain.User
	var orgID *uuid.UUID
	var roleStr string
	var mfaRecoveryCodes []byte
	var externalID *string

	err := row.Scan(
		&user.ID,
		&user.Email,
		&user.Name,
		&orgID,
		&roleStr,
		&user.Banned,
		&user.EmailVerified,
		&user.DeletedAt,
		&user.CreatedAt,
		&user.UpdatedAt,
		&user.LastLoginAt,
		&user.MFAEnabled,
		&user.MFASecret,
		&mfaRecoveryCodes,
		&user.AuthSource,
		&externalID,
		&user.RequiresPasswordChange,
		&user.OIDCLinked,
		&user.OIDCIssuer,
		&user.ActivationTokenExpiresAt,
		&user.ActivationTokenHash,
		&user.VerificationTokenHash,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrUserNotFound
		}
		return nil, fmt.Errorf("failed to scan user: %w", err)
	}

	if len(mfaRecoveryCodes) > 0 {
		if err := json.Unmarshal(mfaRecoveryCodes, &user.MFARecoveryCodes); err != nil {
			logger.Warning.Printf("failed to parse MFA recovery codes for user %s: %v", user.ID.String(), err)
		}
	}

	if orgID != nil {
		user.OrganizationID = *orgID
	}
	if externalID != nil {
		user.ExternalID = externalID
	}
	user.Role = domain.UserRole(roleStr)

	return &user, nil
}

// scanUserWithPassword includes password_hash in the scan
func (r *PgxUserRepository) scanUserWithPassword(row pgx.Row) (*domain.User, error) {
	var user domain.User
	var orgID *uuid.UUID
	var roleStr string
	var mfaRecoveryCodes []byte
	var passwordHash string
	var externalID *string

	err := row.Scan(
		&user.ID,
		&user.Email,
		&user.Name,
		&orgID,
		&roleStr,
		&passwordHash,
		&user.Banned,
		&user.EmailVerified,
		&user.DeletedAt,
		&user.CreatedAt,
		&user.UpdatedAt,
		&user.LastLoginAt,
		&user.MFAEnabled,
		&user.MFASecret,
		&mfaRecoveryCodes,
		&user.AuthSource,
		&externalID,
		&user.RequiresPasswordChange,
		&user.OIDCLinked,
		&user.OIDCIssuer,
		&user.ActivationTokenExpiresAt,
		&user.ActivationTokenHash,
		&user.VerificationTokenHash,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrUserNotFound
		}
		return nil, fmt.Errorf("failed to scan user with password: %w", err)
	}

	if len(mfaRecoveryCodes) > 0 {
		if err := json.Unmarshal(mfaRecoveryCodes, &user.MFARecoveryCodes); err != nil {
			logger.Warning.Printf("failed to parse MFA recovery codes for user %s: %v", user.ID.String(), err)
		}
	}

	if orgID != nil {
		user.OrganizationID = *orgID
	}
	if externalID != nil {
		user.ExternalID = externalID
	}
	user.Role = domain.UserRole(roleStr)
	user.PasswordHash = passwordHash

	return &user, nil
}

// scanUserWithOrg helper for scanning user + organization details
func (r *PgxUserRepository) scanUserWithOrg(row pgx.Row) (*domain.User, error) {
	var user domain.User
	var orgID *uuid.UUID
	var roleStr string
	var mfaRecoveryCodes []byte
	var orgDomain, orgName, orgMfaPolicy, orgAuthPolicy *string
	var orgMaxSessionsPerUser *int
	var orgPasswordComplexityEnabled *bool
	var externalID *string

	err := row.Scan(
		&user.ID,
		&user.Email,
		&user.Name,
		&orgID,
		&roleStr,
		&user.PasswordHash,
		&user.Banned,
		&user.EmailVerified,
		&user.DeletedAt,
		&user.CreatedAt,
		&user.UpdatedAt,
		&user.LastLoginAt,
		&user.MFAEnabled,
		&user.MFASecret,
		&mfaRecoveryCodes,
		&user.AuthSource,
		&externalID,
		&user.RequiresPasswordChange,
		&user.OIDCLinked,
		&user.OIDCIssuer,
		&user.ActivationTokenExpiresAt,
		&user.ActivationTokenHash,
		&user.VerificationTokenHash,
		&orgDomain,
		&orgName,
		&orgMfaPolicy,
		&orgAuthPolicy,
		&orgMaxSessionsPerUser,
		&orgPasswordComplexityEnabled,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrUserNotFound
		}
		return nil, fmt.Errorf("failed to scan user with org: %w", err)
	}

	if len(mfaRecoveryCodes) > 0 {
		if err := json.Unmarshal(mfaRecoveryCodes, &user.MFARecoveryCodes); err != nil {
			logger.Warning.Printf("failed to parse MFA recovery codes for user %s: %v", user.ID.String(), err)
		}
	}

	if orgID != nil {
		user.OrganizationID = *orgID
	}
	user.Role = domain.UserRole(roleStr)

	if externalID != nil {
		user.ExternalID = externalID
	}
	if orgDomain != nil {
		user.Domain = orgDomain
	}
	if orgName != nil {
		user.OrganizationName = orgName
	}
	if orgMfaPolicy != nil {
		user.MFAPolicy = orgMfaPolicy
	}
	if orgAuthPolicy != nil {
		user.OrgAuthPolicy = orgAuthPolicy
	}
	if orgMaxSessionsPerUser != nil {
		user.OrgMaxSessionsPerUser = orgMaxSessionsPerUser
	}
	if orgPasswordComplexityEnabled != nil {
		user.OrgPasswordComplexityEnabled = orgPasswordComplexityEnabled
	}

	return &user, nil
}

// Create creates a new user
func (r *PgxUserRepository) Create(ctx context.Context, user *domain.User) (*domain.User, error) {
	var hashedPassword string
	switch {
	case user.PasswordHash == domain.NoPasswordSentinel:
		hashedPassword = user.PasswordHash
	case strings.HasPrefix(user.PasswordHash, "$argon2id$"):
		// Already a valid argon2id hash — store verbatim to avoid double-hashing.
		hashedPassword = user.PasswordHash
	case strings.HasPrefix(user.PasswordHash, "$"):
		// Any other PHC-shaped prefix is fail-loud territory: storing it
		// verbatim would create an unloginable account because
		// crypto.CompareHashAndPassword only accepts $argon2id$. Re-hashing
		// it would silently produce an argon2id-of-a-hash, which is also
		// wrong. Refuse the write.
		return nil, fmt.Errorf("password hash format not supported (only argon2id is accepted)")
	default:
		hash, err := crypto.GenerateHash([]byte(user.PasswordHash))
		if err != nil {
			return nil, fmt.Errorf("failed to hash password: %w", err)
		}
		hashedPassword = hash
	}

	var orgIDArg *uuid.UUID
	if user.OrganizationID != uuid.Nil {
		orgIDArg = &user.OrganizationID
	}

	if user.AuthSource == "" {
		user.AuthSource = "local"
	}

	// contact_email is NULL, not "", for a user who has none — the column
	// exists for the site_admin's operator address (G9/G15), and an empty
	// string would make "unset" indistinguishable from "set to nothing".
	var contactArg any
	if strings.TrimSpace(user.ContactEmail) != "" {
		contactArg = strings.TrimSpace(user.ContactEmail)
	}

	query := `
		INSERT INTO users (id, email, name, password_hash, role, organization_id, banned, email_verified, deleted_at, created_at, updated_at, auth_source, external_id, requires_password_change, oidc_linked, oidc_issuer, activation_token_expires_at, activation_token_hash, mfa_enabled, mfa_secret, contact_email)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW(), NOW(), $10, $11, $12, $13, $14, $15, $16, $17, $18, $19)
		RETURNING id, email, name, organization_id, role, banned, email_verified, deleted_at, created_at, updated_at, last_login_at, mfa_enabled, mfa_secret, mfa_recovery_codes, auth_source, external_id, requires_password_change, oidc_linked, oidc_issuer, activation_token_expires_at, activation_token_hash, verification_token_hash`

	timer := prometheus.NewTimer(metrics.DBQueryDuration.WithLabelValues("user_repo", "create", "all"))
	defer timer.ObserveDuration()

	createdUser, err := r.scanUser(r.db.QueryRow(ctx, query,
		user.ID,
		user.Email,
		user.Name,
		hashedPassword,
		string(user.Role),
		orgIDArg,
		user.Banned,
		user.EmailVerified,
		user.DeletedAt,
		user.AuthSource,
		user.ExternalID,
		user.RequiresPasswordChange,
		user.OIDCLinked,
		user.OIDCIssuer,
		user.ActivationTokenExpiresAt,
		user.ActivationTokenHash,
		user.MFAEnabled,
		user.MFASecret,
		contactArg,
	))

	if err != nil {
		metrics.DBQueryDuration.WithLabelValues("user_repo", "create", "error").Observe(timer.ObserveDuration().Seconds())
		// Translate Postgres unique-violation (SQLSTATE 23505) to the
		// domain sentinel so service-layer callers can distinguish a
		// concurrent-insert race from a real infrastructure error.
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return nil, domain.ErrUserAlreadyExists
		}
		return nil, fmt.Errorf("failed to create user: %w", err)
	}
	metrics.DBQueryDuration.WithLabelValues("user_repo", "create", "success").Observe(timer.ObserveDuration().Seconds())

	created := *createdUser

	if created.OrganizationID != uuid.Nil {
		var orgDomain string
		var orgName string
		orgQuery := `SELECT domain, name FROM organizations WHERE id = $1`
		err := r.db.QueryRow(ctx, orgQuery, created.OrganizationID).Scan(&orgDomain, &orgName)
		if err == nil {
			created.Domain = &orgDomain
			created.OrganizationName = &orgName
		}
	}

	logger.InfoContext(ctx, "Created user",
		zap.String("email", user.Email),
		zap.String("role", string(user.Role)),
		zap.String("org_id", user.OrganizationID.String()),
	)
	return &created, nil
}

// GetByID retrieves a user by ID
func (r *PgxUserRepository) GetByID(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	query := `
		SELECT id, email, name, organization_id, role, banned, email_verified, deleted_at, created_at, updated_at, last_login_at, mfa_enabled, mfa_secret, mfa_recovery_codes, auth_source, external_id, requires_password_change, oidc_linked, oidc_issuer, activation_token_expires_at, activation_token_hash, verification_token_hash
		FROM users
		WHERE id = $1 AND banned = false AND deleted_at IS NULL`

	timer := prometheus.NewTimer(metrics.DBQueryDuration.WithLabelValues("user_repo", "get_by_id", "all"))
	defer timer.ObserveDuration()

	user, err := r.scanUser(r.db.QueryRow(ctx, query, id))
	if err != nil {
		metrics.DBQueryDuration.WithLabelValues("user_repo", "get_by_id", "error").Observe(timer.ObserveDuration().Seconds())
		return nil, err
	}
	metrics.DBQueryDuration.WithLabelValues("user_repo", "get_by_id", "success").Observe(timer.ObserveDuration().Seconds())

	return user, nil
}

// FindUsersByEmail finds users by email
func (r *PgxUserRepository) FindUsersByEmail(ctx context.Context, email string) ([]*domain.User, error) {
	query := `
		SELECT
			u.id, u.email, u.name, u.organization_id, u.role, u.password_hash, u.banned, u.email_verified, u.deleted_at, u.created_at, u.updated_at, u.last_login_at, u.mfa_enabled, u.mfa_secret, u.mfa_recovery_codes,
			u.auth_source, u.external_id, u.requires_password_change, u.oidc_linked, u.oidc_issuer, u.activation_token_expires_at, u.activation_token_hash, u.verification_token_hash,
			o.domain, o.name AS organization_name, o.mfa_policy, o.auth_policy, o.max_sessions_per_user, o.password_complexity_enabled
		FROM users u
		LEFT JOIN organizations o ON u.organization_id = o.id
		WHERE u.email = $1 AND u.banned = false AND u.deleted_at IS NULL AND (u.organization_id IS NULL OR (o.active = true AND o.deleted_at IS NULL))`

	rows, err := r.db.Query(ctx, query, email)
	if err != nil {
		return nil, fmt.Errorf("failed to find users by email: %w", err)
	}
	defer rows.Close()

	var users []*domain.User
	for rows.Next() {
		user, err := r.scanUserWithOrg(rows)
		if err != nil {
			return nil, fmt.Errorf("failed to scan user in FindUsersByEmail: %w", err)
		}
		users = append(users, user)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating found users: %w", err)
	}

	return users, nil
}

// GetByEmailAndOrgID retrieves a user by email and organization ID
func (r *PgxUserRepository) GetByEmailAndOrgID(ctx context.Context, orgID uuid.UUID, email string) (*domain.User, error) {
	if orgID == uuid.Nil {
		query := `
		SELECT id, email, name, organization_id, role, password_hash, banned, email_verified, deleted_at, created_at, updated_at, last_login_at, mfa_enabled, mfa_secret, mfa_recovery_codes, auth_source, external_id, requires_password_change, oidc_linked, oidc_issuer, activation_token_expires_at, activation_token_hash, verification_token_hash
		FROM users
		WHERE organization_id IS NULL AND email = $1 AND banned = false AND deleted_at IS NULL`
		return r.scanUserWithPassword(r.db.QueryRow(ctx, query, email))
	}

	query := `
		SELECT id, email, name, organization_id, role, password_hash, banned, email_verified, deleted_at, created_at, updated_at, last_login_at, mfa_enabled, mfa_secret, mfa_recovery_codes, auth_source, external_id, requires_password_change, oidc_linked, oidc_issuer, activation_token_expires_at, activation_token_hash, verification_token_hash
		FROM users
		WHERE organization_id = $1 AND email = $2 AND banned = false AND deleted_at IS NULL`

	return r.scanUserWithPassword(r.db.QueryRow(ctx, query, orgID, email))
}

// FindByActivationTokenHash returns the user row whose
// activation_token_hash matches the supplied SHA-256 hex digest.
// Used by the OrganizationActivationService to resolve the org_admin
// behind an opaque activation token. The query DOES NOT filter on
// `organization_id` (orgs in pre-activation state are not active);
// it DOES filter on the soft-delete + banned guards so a banned or
// deleted org_admin's token cannot resolve.
//
// Returns (nil, nil) when no row matches. The service layer
// collapses both onto the opaque "invalid token" sentinel.
func (r *PgxUserRepository) FindByActivationTokenHash(ctx context.Context, hash string) (*domain.User, error) {
	const query = `
		SELECT id, email, name, organization_id, role, banned, email_verified, deleted_at, created_at, updated_at, last_login_at, mfa_enabled, mfa_secret, mfa_recovery_codes, auth_source, external_id, requires_password_change, oidc_linked, oidc_issuer, activation_token_expires_at, activation_token_hash, verification_token_hash
		FROM users
		WHERE activation_token_hash = $1 AND deleted_at IS NULL AND banned = false`
	user, err := r.scanUser(r.db.QueryRow(ctx, query, hash))
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to find user by activation token hash: %w", err)
	}
	return user, nil
}

// GetByExternalID retrieves a user by external ID and organization ID
func (r *PgxUserRepository) GetByExternalID(ctx context.Context, orgID uuid.UUID, externalID string) (*domain.User, error) {
	if orgID == uuid.Nil {
		query := `
		SELECT id, email, name, organization_id, role, password_hash, banned, email_verified, deleted_at, created_at, updated_at, last_login_at, mfa_enabled, mfa_secret, mfa_recovery_codes, auth_source, external_id, requires_password_change, oidc_linked, oidc_issuer, activation_token_expires_at, activation_token_hash, verification_token_hash
		FROM users
		WHERE organization_id IS NULL AND external_id = $1 AND banned = false AND deleted_at IS NULL`
		return r.scanUserWithPassword(r.db.QueryRow(ctx, query, externalID))
	}

	query := `
		SELECT id, email, name, organization_id, role, password_hash, banned, email_verified, deleted_at, created_at, updated_at, last_login_at, mfa_enabled, mfa_secret, mfa_recovery_codes, auth_source, external_id, requires_password_change, oidc_linked, oidc_issuer, activation_token_expires_at, activation_token_hash, verification_token_hash
		FROM users
		WHERE organization_id = $1 AND external_id = $2 AND banned = false AND deleted_at IS NULL`

	return r.scanUserWithPassword(r.db.QueryRow(ctx, query, orgID, externalID))
}

// Update updates a user's information
func (r *PgxUserRepository) Update(ctx context.Context, id uuid.UUID, orgID uuid.UUID, opts repository.UpdateUserOptions) (*domain.User, error) {
	setParts := []string{}
	args := []any{}
	argIndex := 1

	if opts.AuthSource != nil {
		setParts = append(setParts, fmt.Sprintf("auth_source = $%d", argIndex))
		args = append(args, *opts.AuthSource)
		argIndex++
	}

	if opts.ExternalID != nil {
		setParts = append(setParts, fmt.Sprintf("external_id = $%d", argIndex))
		args = append(args, *opts.ExternalID)
		argIndex++
	}

	if opts.Email != nil {
		setParts = append(setParts, fmt.Sprintf("email = $%d", argIndex))
		args = append(args, *opts.Email)
		argIndex++
	}

	if opts.Password != nil {
		switch {
		case *opts.Password == domain.NoPasswordSentinel:
			setParts = append(setParts, fmt.Sprintf("password_hash = $%d", argIndex))
			args = append(args, *opts.Password)
			argIndex++
		case strings.HasPrefix(*opts.Password, "$argon2id$"):
			// Already a valid argon2id hash — store verbatim to avoid double-hashing.
			setParts = append(setParts, fmt.Sprintf("password_hash = $%d", argIndex))
			args = append(args, *opts.Password)
			argIndex++
		case strings.HasPrefix(*opts.Password, "$"):
			// Fail-loud on any other PHC-shaped prefix — see the Create path
			// for the rationale. Persisting a non-argon2id hash would create
			// an unloginable user.
			return nil, fmt.Errorf("password hash format not supported (only argon2id is accepted)")
		default:
			hash, err := crypto.GenerateHash([]byte(*opts.Password))
			if err != nil {
				return nil, fmt.Errorf("failed to hash password: %w", err)
			}
			setParts = append(setParts, fmt.Sprintf("password_hash = $%d", argIndex))
			args = append(args, hash)
			argIndex++
		}
	}

	if opts.Name != nil {
		setParts = append(setParts, fmt.Sprintf("name = $%d", argIndex))
		args = append(args, *opts.Name)
		argIndex++
	}

	if opts.Role != nil {
		setParts = append(setParts, fmt.Sprintf("role = $%d", argIndex))
		args = append(args, string(*opts.Role))
		argIndex++
	}

	if opts.Banned != nil {
		setParts = append(setParts, fmt.Sprintf("banned = $%d", argIndex))
		args = append(args, *opts.Banned)
		argIndex++
	}

	if opts.EmailVerified != nil {
		setParts = append(setParts, fmt.Sprintf("email_verified = $%d", argIndex))
		args = append(args, *opts.EmailVerified)
		argIndex++
	}

	if opts.MFAEnabled != nil {
		setParts = append(setParts, fmt.Sprintf("mfa_enabled = $%d", argIndex))
		args = append(args, *opts.MFAEnabled)
		argIndex++
	}

	if opts.MFASecret != nil {
		setParts = append(setParts, fmt.Sprintf("mfa_secret = $%d", argIndex))
		args = append(args, *opts.MFASecret)
		argIndex++
	}

	if opts.MFARecoveryCodes != nil {
		codesJSON, err := json.Marshal(opts.MFARecoveryCodes)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal recovery codes: %w", err)
		}
		setParts = append(setParts, fmt.Sprintf("mfa_recovery_codes = $%d", argIndex))
		args = append(args, string(codesJSON))
		argIndex++
	}

	if opts.RequiresPasswordChange != nil {
		setParts = append(setParts, fmt.Sprintf("requires_password_change = $%d", argIndex))
		args = append(args, *opts.RequiresPasswordChange)
		argIndex++
	}

	if opts.OIDCLinked != nil {
		setParts = append(setParts, fmt.Sprintf("oidc_linked = $%d", argIndex))
		args = append(args, *opts.OIDCLinked)
		argIndex++
	}

	if opts.OIDCIssuer != nil {
		setParts = append(setParts, fmt.Sprintf("oidc_issuer = $%d", argIndex))
		args = append(args, *opts.OIDCIssuer)
		argIndex++
	}

	if opts.ActivationTokenExpiresAt != nil {
		setParts = append(setParts, fmt.Sprintf("activation_token_expires_at = $%d", argIndex))
		args = append(args, *opts.ActivationTokenExpiresAt)
		argIndex++
	}

	if opts.ActivationTokenHash != nil {
		if *opts.ActivationTokenHash == "" {
			// Clear the hash (burn: token consumed)
			setParts = append(setParts, "activation_token_hash = NULL")
		} else {
			setParts = append(setParts, fmt.Sprintf("activation_token_hash = $%d", argIndex))
			args = append(args, *opts.ActivationTokenHash)
			argIndex++
		}
	}

	if opts.VerificationTokenHash != nil {
		if *opts.VerificationTokenHash == "" {
			// Clear the hash (burn: token consumed after first use)
			setParts = append(setParts, "verification_token_hash = NULL")
		} else {
			setParts = append(setParts, fmt.Sprintf("verification_token_hash = $%d", argIndex))
			args = append(args, *opts.VerificationTokenHash)
			argIndex++
		}
	}

	if len(setParts) == 0 {
		return nil, fmt.Errorf("no fields to update")
	}

	setParts = append(setParts, "updated_at = NOW()")
	args = append(args, id)

	whereClause := fmt.Sprintf("WHERE id = $%d", argIndex)
	argIndex++

	if orgID != uuid.Nil {
		whereClause += fmt.Sprintf(" AND organization_id = $%d", argIndex)
		args = append(args, orgID)
	}

	// §1.15 race gate: concurrent invitation consumption loses the race at SQL,
	// not in application code. Zero rows returned → scanUser maps to ErrUserNotFound
	// and the service surfaces "already used".
	if opts.RequireEmailVerifiedFalse {
		whereClause += " AND email_verified = false"
	}

	query := fmt.Sprintf(`
		UPDATE users
		SET %s
		%s
		RETURNING id, email, name, organization_id, role, banned, email_verified, deleted_at, created_at, updated_at, last_login_at, mfa_enabled, mfa_secret, mfa_recovery_codes, auth_source, external_id, requires_password_change, oidc_linked, oidc_issuer, activation_token_expires_at, activation_token_hash, verification_token_hash`,
		strings.Join(setParts, ", "), whereClause)

	updated, err := r.scanUser(r.db.QueryRow(ctx, query, args...))
	if err != nil {
		// Translate Postgres unique-violation (SQLSTATE 23505) to the
		// domain sentinel, mirroring Create — an email UPDATE onto an
		// existing address was reaching the handler as an unknown error
		// (THE-DEFAULT-THAT-LIES).
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return nil, domain.ErrUserAlreadyExists
		}
		return nil, err
	}
	return updated, nil
}

// ConsumeRecoveryCode atomically removes a SINGLE MFA recovery code (identified
// by its stored SHA-256 hash) from the user's mfa_recovery_codes JSONB array,
// but ONLY while that hash is still present. The presence-guard and the removal
// are one statement, so a concurrent redeemer that already removed the code
// finds the EXISTS guard false, updates zero rows, and gets ok=false — the same
// recovery code cannot be redeemed twice, even by two DISTINCT pending handles
// (P0-11). Returns (updatedUser, true, nil) on success, (nil, false, nil) when
// the code was not present (already redeemed / never existed).
func (r *PgxUserRepository) ConsumeRecoveryCode(ctx context.Context, id uuid.UUID, codeHash string) (*domain.User, bool, error) {
	const q = `
		UPDATE users
		SET mfa_recovery_codes = COALESCE(
		        (SELECT jsonb_agg(e) FROM jsonb_array_elements_text(mfa_recovery_codes) AS e WHERE e <> $2),
		        '[]'::jsonb),
		    updated_at = NOW()
		WHERE id = $1
		  AND deleted_at IS NULL
		  AND EXISTS (SELECT 1 FROM jsonb_array_elements_text(mfa_recovery_codes) AS e WHERE e = $2)
		RETURNING id, email, name, organization_id, role, banned, email_verified, deleted_at, created_at, updated_at, last_login_at, mfa_enabled, mfa_secret, mfa_recovery_codes, auth_source, external_id, requires_password_change, oidc_linked, oidc_issuer, activation_token_expires_at, activation_token_hash, verification_token_hash`
	user, err := r.scanUser(r.db.QueryRow(ctx, q, id, codeHash))
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			return nil, false, nil // guard failed: code already redeemed / not present
		}
		return nil, false, err
	}
	return user, true, nil
}

// ConsumeActivationToken atomically claims an org-activation token and applies
// the admin setup in ONE transaction (P0-10). It (1) claims the token — clearing
// activation_token_hash ONLY while it still equals the presented hash (the WHERE
// guard IS the atomic single-use claim, so a concurrent consumer matches zero
// rows and is rejected) AND sets the admin password_hash + email_verified in the
// SAME statement — then (2) activates the organization. A failure in either
// write rolls the whole transaction back, so a valid activation link is never
// burned by a failed attempt. newPasswordHash MUST be a pre-computed argon2id
// hash. Returns (updatedUser, true, nil) on success, (nil, false, nil) when the
// token was not claimable (already consumed / unknown).
func (r *PgxUserRepository) ConsumeActivationToken(ctx context.Context, activationTokenHash, newPasswordHash string) (*domain.User, bool, error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, false, fmt.Errorf("failed to begin activation transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	const claim = `
		UPDATE users
		SET activation_token_hash = NULL,
		    password_hash = $2,
		    email_verified = true,
		    updated_at = NOW()
		WHERE activation_token_hash = $1
		  AND deleted_at IS NULL
		RETURNING id, email, name, organization_id, role, banned, email_verified, deleted_at, created_at, updated_at, last_login_at, mfa_enabled, mfa_secret, mfa_recovery_codes, auth_source, external_id, requires_password_change, oidc_linked, oidc_issuer, activation_token_expires_at, activation_token_hash, verification_token_hash`
	user, err := r.scanUser(tx.QueryRow(ctx, claim, activationTokenHash, newPasswordHash))
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			return nil, false, nil // token not claimable: already consumed / unknown
		}
		return nil, false, fmt.Errorf("claim activation token: %w", err)
	}
	// Activate the owning organization in the SAME transaction.
	ct, err := tx.Exec(ctx, `UPDATE organizations SET active = true, updated_at = NOW() WHERE id = $1 AND deleted_at IS NULL`, user.OrganizationID)
	if err != nil {
		return nil, false, fmt.Errorf("activate organization: %w", err)
	}
	if ct.RowsAffected() != 1 {
		return nil, false, fmt.Errorf("activate organization: organization not found or deleted")
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, false, fmt.Errorf("commit activation transaction: %w", err)
	}
	return user, true, nil
}

// Delete permanently deletes a user (soft delete really, logic uses Exec)
func (r *PgxUserRepository) Delete(ctx context.Context, id uuid.UUID, orgID uuid.UUID) error {
	query := `UPDATE users SET deleted_at = NOW() WHERE id = $1`
	args := []any{id}
	if orgID != uuid.Nil {
		query += ` AND organization_id = $2`
		args = append(args, orgID)
	}

	result, err := r.db.Exec(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	if result.RowsAffected() == 0 {
		return domain.ErrUserNotFound
	}

	return nil
}

// Undelete undeletes a user
func (r *PgxUserRepository) Undelete(ctx context.Context, id uuid.UUID, orgID uuid.UUID) error {
	query := `UPDATE users SET deleted_at = NULL WHERE id = $1`
	args := []any{id}
	if orgID != uuid.Nil {
		query += ` AND organization_id = $2`
		args = append(args, orgID)
	}

	result, err := r.db.Exec(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("failed to undelete user: %w", err)
	}

	if result.RowsAffected() == 0 {
		return domain.ErrUserNotFound
	}

	return nil
}

// GetByIDWithOrg retrieves a user with their org info
func (r *PgxUserRepository) GetByIDWithOrg(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	query := `
		SELECT
			u.id, u.email, u.name, u.organization_id, u.role, u.password_hash, u.banned, u.email_verified, u.deleted_at, u.created_at, u.updated_at, u.last_login_at, u.mfa_enabled, u.mfa_secret, u.mfa_recovery_codes,
			u.auth_source, u.external_id, u.requires_password_change, u.oidc_linked, u.oidc_issuer, u.activation_token_expires_at, u.activation_token_hash, u.verification_token_hash,
			o.domain, o.name AS organization_name, o.mfa_policy, o.auth_policy, o.max_sessions_per_user, o.password_complexity_enabled
		FROM users u
		LEFT JOIN organizations o ON u.organization_id = o.id
		WHERE u.id = $1`

	return r.scanUserWithOrg(r.db.QueryRow(ctx, query, id))
}

// List lists users with filters
func (r *PgxUserRepository) List(ctx context.Context, opts repository.ListUserOptions) ([]*domain.User, int, error) {
	filter := opts.Filter
	pagination := opts.Pagination
	sort := opts.Sort

	query := `
		SELECT u.id, u.email, u.name, u.organization_id, u.role, u.banned, u.email_verified, u.deleted_at, u.created_at, u.updated_at, u.last_login_at, u.mfa_enabled, u.mfa_secret, u.mfa_recovery_codes,
		       u.auth_source, u.external_id, u.requires_password_change, u.oidc_linked, u.oidc_issuer, u.activation_token_expires_at, u.activation_token_hash, u.verification_token_hash,
		       o.domain, o.name AS organization_name,
		       COUNT(*) OVER() AS total_count
		FROM users u
		LEFT JOIN organizations o ON u.organization_id = o.id`

	conditions := []string{}
	args := []any{}
	argIndex := 1

	if filter.Banned != nil {
		conditions = append(conditions, fmt.Sprintf("u.banned = $%d", argIndex))
		args = append(args, *filter.Banned)
		argIndex++
	}

	if filter.EmailVerified != nil {
		conditions = append(conditions, fmt.Sprintf("u.email_verified = $%d", argIndex))
		args = append(args, *filter.EmailVerified)
		argIndex++
	}

	if filter.Deleted != nil {
		if *filter.Deleted {
			conditions = append(conditions, "u.deleted_at IS NOT NULL")
		} else {
			conditions = append(conditions, "u.deleted_at IS NULL")
		}
	} else if !filter.IncludeDeleted {
		conditions = append(conditions, "u.deleted_at IS NULL")
	}

	if filter.Search != "" {
		conditions = append(conditions, fmt.Sprintf("(u.email ILIKE $%d OR u.name ILIKE $%d OR o.name ILIKE $%d)", argIndex, argIndex, argIndex))
		args = append(args, "%"+filter.Search+"%")
		argIndex++
	}

	if filter.Role != "" {
		conditions = append(conditions, fmt.Sprintf("u.role = $%d", argIndex))
		args = append(args, filter.Role)
		argIndex++
	}

	if filter.Email != "" {
		conditions = append(conditions, fmt.Sprintf("u.email ILIKE $%d", argIndex))
		args = append(args, "%"+filter.Email+"%")
		argIndex++
	}

	if filter.Name != "" {
		conditions = append(conditions, fmt.Sprintf("u.name ILIKE $%d", argIndex))
		args = append(args, "%"+filter.Name+"%")
		argIndex++
	}

	if filter.OrganizationName != "" {
		conditions = append(conditions, fmt.Sprintf("o.name ILIKE $%d", argIndex))
		args = append(args, "%"+filter.OrganizationName+"%")
		argIndex++
	}

	if len(conditions) > 0 {
		query += " WHERE " + strings.Join(conditions, " AND ")
	}

	sortField := "u.created_at"
	if sort.Field != "" {
		if repository.ValidSortFields[sort.Field] {
			sortField = "u." + sort.Field
		}
	}
	sortOrder := "ASC"
	if sort.Desc {
		sortOrder = "DESC"
	}
	query += fmt.Sprintf(" ORDER BY %s %s", sortField, sortOrder)

	if pagination.PageSize > 0 {
		query += fmt.Sprintf(" LIMIT $%d OFFSET $%d", argIndex, argIndex+1)
		args = append(args, pagination.PageSize, pagination.Offset)
	}

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list users: %w", err)
	}
	defer rows.Close()

	users := []*domain.User{}
	var totalCount int

	for rows.Next() {
		// Manual scan because of totalCount and extra fields
		var user domain.User
		var orgID *uuid.UUID
		var roleStr string
		var mfaRecoveryCodes []byte
		var orgDomain, orgName *string
		var externalID *string

		err := rows.Scan(
			&user.ID,
			&user.Email,
			&user.Name,
			&orgID,
			&roleStr,
			&user.Banned,
			&user.EmailVerified,
			&user.DeletedAt,
			&user.CreatedAt,
			&user.UpdatedAt,
			&user.LastLoginAt,
			&user.MFAEnabled,
			&user.MFASecret,
			&mfaRecoveryCodes,
			&user.AuthSource,
			&externalID,
			&user.RequiresPasswordChange,
			&user.OIDCLinked,
			&user.OIDCIssuer,
			&user.ActivationTokenExpiresAt,
			&user.ActivationTokenHash,
			&user.VerificationTokenHash,
			&orgDomain,
			&orgName,
			&totalCount,
		)

		if err != nil {
			return nil, 0, fmt.Errorf("failed to scan user: %w", err)
		}

		if len(mfaRecoveryCodes) > 0 {
			if err := json.Unmarshal(mfaRecoveryCodes, &user.MFARecoveryCodes); err != nil {
				logger.Warning.Printf("failed to parse MFA recovery codes for user %s: %v", user.ID.String(), err)
			}
		}

		if orgID != nil {
			user.OrganizationID = *orgID
		}
		user.Role = domain.UserRole(roleStr)
		if externalID != nil {
			user.ExternalID = externalID
		}
		if orgDomain != nil {
			user.Domain = orgDomain
		}
		if orgName != nil {
			user.OrganizationName = orgName
		}
		users = append(users, &user)
	}

	if err = rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error iterating users: %w", err)
	}

	return users, totalCount, nil
}

// ListByOrganization lists users by organization
func (r *PgxUserRepository) ListByOrganization(ctx context.Context, orgID uuid.UUID, opts repository.ListUserOptions) ([]*domain.User, int, error) {
	// Reusing List with OrganizationID filter would be cleaner, but existing logic separates them.
	// Implementing exact logic as legacy Repo for safety.
	filter := opts.Filter
	pagination := opts.Pagination
	sort := opts.Sort

	query := `
		SELECT u.id, u.email, u.name, u.organization_id, u.role, u.banned, u.email_verified, u.deleted_at, u.created_at, u.updated_at, u.last_login_at, u.mfa_enabled, u.mfa_secret, u.mfa_recovery_codes,
		       u.auth_source, u.external_id, u.requires_password_change, u.oidc_linked, u.oidc_issuer, u.activation_token_expires_at, u.activation_token_hash, u.verification_token_hash,
		       o.domain, o.name AS organization_name,
		       COUNT(*) OVER() AS total_count
		FROM users u
		INNER JOIN organizations o ON u.organization_id = o.id
		WHERE u.organization_id = $1`

	args := []any{orgID}
	argIndex := 2

	// filters... (Copy from legacy mostly)
	if filter.Banned != nil {
		query += fmt.Sprintf(" AND u.banned = $%d", argIndex)
		args = append(args, *filter.Banned)
		argIndex++
	}
	if filter.EmailVerified != nil {
		query += fmt.Sprintf(" AND u.email_verified = $%d", argIndex)
		args = append(args, *filter.EmailVerified)
		argIndex++
	}
	if filter.Deleted != nil {
		if *filter.Deleted {
			query += " AND u.deleted_at IS NOT NULL"
		} else {
			query += " AND u.deleted_at IS NULL"
		}
	} else if !filter.IncludeDeleted {
		query += " AND u.deleted_at IS NULL"
	}
	if filter.Search != "" {
		query += fmt.Sprintf(" AND (u.email ILIKE $%d OR u.name ILIKE $%d OR o.name ILIKE $%d)", argIndex, argIndex, argIndex)
		args = append(args, "%"+filter.Search+"%")
		argIndex++
	}
	if filter.Role != "" {
		query += fmt.Sprintf(" AND u.role = $%d", argIndex)
		args = append(args, filter.Role)
		argIndex++
	}
	// ... (Other filters skipped as per legacy reuse logic or brevity, assuming core filters covered)
	// Legacy has Name/Email/OrgName filters too.
	// I will include Name/Email. OrgName redundant if filtered by OrgID? But maybe for search.
	if filter.Email != "" {
		query += fmt.Sprintf(" AND u.email ILIKE $%d", argIndex)
		args = append(args, "%"+filter.Email+"%")
		argIndex++
	}
	if filter.Name != "" {
		query += fmt.Sprintf(" AND u.name ILIKE $%d", argIndex)
		args = append(args, "%"+filter.Name+"%")
		argIndex++
	}

	sortField := "u.created_at"
	if sort.Field != "" {
		if repository.ValidSortFields[sort.Field] {
			sortField = "u." + sort.Field
		}
	}
	sortOrder := "ASC"
	if sort.Desc {
		sortOrder = "DESC"
	}
	query += fmt.Sprintf(" ORDER BY %s %s", sortField, sortOrder)

	if pagination.PageSize > 0 {
		query += fmt.Sprintf(" LIMIT $%d OFFSET $%d", argIndex, argIndex+1)
		args = append(args, pagination.PageSize, pagination.Offset)
	}

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list users by organization: %w", err)
	}
	defer rows.Close()

	users := []*domain.User{}
	var totalCount int

	for rows.Next() {
		// Manual scan SAME AS List
		var user domain.User
		var orgIDScan *uuid.UUID
		var roleStr string
		var mfaRecoveryCodes []byte
		var orgDomain, orgName *string
		var externalID *string

		err := rows.Scan(
			&user.ID,
			&user.Email,
			&user.Name,
			&orgIDScan, // Use local var to avoid conflict
			&roleStr,
			&user.Banned,
			&user.EmailVerified,
			&user.DeletedAt,
			&user.CreatedAt,
			&user.UpdatedAt,
			&user.LastLoginAt,
			&user.MFAEnabled,
			&user.MFASecret,
			&mfaRecoveryCodes,
			&user.AuthSource,
			&externalID,
			&user.RequiresPasswordChange,
			&user.OIDCLinked,
			&user.OIDCIssuer,
			&user.ActivationTokenExpiresAt,
			&user.ActivationTokenHash,
			&user.VerificationTokenHash,
			&orgDomain,
			&orgName,
			&totalCount,
		)

		if err != nil {
			return nil, 0, fmt.Errorf("failed to scan user: %w", err)
		}

		if len(mfaRecoveryCodes) > 0 {
			if err := json.Unmarshal(mfaRecoveryCodes, &user.MFARecoveryCodes); err != nil {
				logger.Warning.Printf("failed to parse MFA recovery codes for user %s: %v", user.ID.String(), err)
			}
		}

		if orgIDScan != nil {
			user.OrganizationID = *orgIDScan
		}
		user.Role = domain.UserRole(roleStr)
		if externalID != nil {
			user.ExternalID = externalID
		}
		if orgDomain != nil {
			user.Domain = orgDomain
		}
		if orgName != nil {
			user.OrganizationName = orgName
		}
		users = append(users, &user)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("row iteration failed: %w", err)
	}

	return users, totalCount, nil
}

// UpdateLastLogin updates last login time
func (r *PgxUserRepository) UpdateLastLogin(ctx context.Context, id uuid.UUID) error {
	query := `UPDATE users SET last_login_at = NOW() WHERE id = $1`
	_, err := r.db.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to update last login: %w", err)
	}
	return nil
}

// VerifyPassword verifies a password
func (r *PgxUserRepository) VerifyPassword(ctx context.Context, password, hash string) error {
	logger.DebugContext(ctx, "VERIFY PASSWORD CALLED", zap.Int("password_len", len(password)))
	err := crypto.CompareHashAndPassword([]byte(hash), []byte(password))
	if err != nil {
		logger.DebugContext(ctx, "Password verification failed")
		return fmt.Errorf("password verification failed: %w", err)
	}
	return nil
}

// HashPassword hashes a password
func (r *PgxUserRepository) HashPassword(password string) (string, error) {
	hash, err := crypto.GenerateHash([]byte(password))
	if err != nil {
		return "", fmt.Errorf("failed to hash password: %w", err)
	}
	return hash, nil
}

// GetUserOrganization gets user organization
func (r *PgxUserRepository) GetUserOrganization(ctx context.Context, userID uuid.UUID) (*domain.Organization, error) {
	query := `
		SELECT o.id, o.name, o.domain, o.active, o.deleted_at, o.max_sessions_per_user, o.created_at
		FROM organizations o
		INNER JOIN users u ON o.id = u.organization_id
		WHERE u.id = $1 AND u.banned = false AND o.active = true`

	var org domain.Organization
	err := r.db.QueryRow(ctx, query, userID).Scan(
		&org.ID,
		&org.Name,
		&org.Domain,
		&org.Active,
		&org.DeletedAt,
		&org.MaxSessionsPerUser,
		&org.CreatedAt,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// AUTH-503: a typed verdict, so callers can tell it from a store error.
			return nil, domain.ErrUserOrganizationNotFound
		}
		return nil, fmt.Errorf("failed to get user organization: %w", err)
	}

	return &org, nil
}

// CountByOrganization counts users
func (r *PgxUserRepository) CountByOrganization(ctx context.Context, orgID uuid.UUID) (int, error) {
	query := `SELECT COUNT(*) FROM users WHERE organization_id = $1 AND deleted_at IS NULL`
	var count int
	err := r.db.QueryRow(ctx, query, orgID).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count users by organization: %w", err)
	}
	return count, nil
}

// CountOrgAdminsByOrganization counts active (non-deleted, non-banned) org_admin users in an organization.
func (r *PgxUserRepository) CountOrgAdminsByOrganization(ctx context.Context, orgID uuid.UUID) (int, error) {
	query := `SELECT COUNT(*) FROM users WHERE organization_id = $1 AND role = 'org_admin' AND deleted_at IS NULL AND banned = false`
	var count int
	err := r.db.QueryRow(ctx, query, orgID).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count org admins by organization: %w", err)
	}
	return count, nil
}

// CountVerifiedOrgAdminsByOrganization counts org_admin users with email_verified=true for one org.
// Zero means no verified (blocking) admin — when combined with CountOrgAdminsByOrganization > 0
// this signals the expired-pending-invitation state where can_assign_admin=true.
func (r *PgxUserRepository) CountVerifiedOrgAdminsByOrganization(ctx context.Context, orgID uuid.UUID) (int, error) {
	query := `SELECT COUNT(*) FROM users WHERE organization_id = $1 AND role = 'org_admin' AND email_verified = true AND deleted_at IS NULL AND banned = false`
	var count int
	if err := r.db.QueryRow(ctx, query, orgID).Scan(&count); err != nil {
		return 0, fmt.Errorf("failed to count verified org admins by organization: %w", err)
	}
	return count, nil
}

// CountVerifiedOrgAdminsByOrganizations is the batch version for list endpoints.
func (r *PgxUserRepository) CountVerifiedOrgAdminsByOrganizations(ctx context.Context, orgIDs []uuid.UUID) (map[uuid.UUID]int, error) {
	result := make(map[uuid.UUID]int, len(orgIDs))
	if len(orgIDs) == 0 {
		return result, nil
	}
	query := `
		SELECT organization_id, COUNT(*) AS cnt
		FROM users
		WHERE organization_id = ANY($1)
		  AND role = 'org_admin'
		  AND email_verified = true
		  AND deleted_at IS NULL
		  AND banned = false
		GROUP BY organization_id`
	rows, err := r.db.Query(ctx, query, orgIDs)
	if err != nil {
		return nil, fmt.Errorf("failed to count verified org admins by organizations: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id uuid.UUID
		var cnt int
		if err := rows.Scan(&id, &cnt); err != nil {
			return nil, fmt.Errorf("failed to scan verified org admin count: %w", err)
		}
		result[id] = cnt
	}
	return result, rows.Err()
}

// CountOrgAdminsByOrganizations returns a map of orgID -> active org_admin count for multiple orgs in one query.
func (r *PgxUserRepository) CountOrgAdminsByOrganizations(ctx context.Context, orgIDs []uuid.UUID) (map[uuid.UUID]int, error) {
	result := make(map[uuid.UUID]int, len(orgIDs))
	if len(orgIDs) == 0 {
		return result, nil
	}

	query := `
		SELECT organization_id, COUNT(*) AS cnt
		FROM users
		WHERE organization_id = ANY($1)
		  AND role = 'org_admin'
		  AND deleted_at IS NULL
		  AND banned = false
		GROUP BY organization_id`

	rows, err := r.db.Query(ctx, query, orgIDs)
	if err != nil {
		return nil, fmt.Errorf("failed to count org admins by organizations: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var orgID uuid.UUID
		var cnt int
		if err := rows.Scan(&orgID, &cnt); err != nil {
			return nil, fmt.Errorf("failed to scan org admin count: %w", err)
		}
		result[orgID] = cnt
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating org admin counts: %w", err)
	}
	return result, nil
}

// Admin implementations

func (r *PgxUserRepository) GetByIDAdmin(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	query := `
		SELECT id, email, name, organization_id, role, banned, email_verified, deleted_at, created_at, updated_at, last_login_at, mfa_enabled, mfa_secret, mfa_recovery_codes, auth_source, external_id, requires_password_change, oidc_linked, oidc_issuer, activation_token_expires_at, activation_token_hash, verification_token_hash
		FROM users
		WHERE id = $1`

	return r.scanUser(r.db.QueryRow(ctx, query, id))
}

func (r *PgxUserRepository) GetByEmailAdmin(ctx context.Context, email string) (*domain.User, error) {
	query := `
		SELECT id, email, name, organization_id, role, password_hash, banned, email_verified, deleted_at, created_at, updated_at, last_login_at, mfa_enabled, mfa_secret, mfa_recovery_codes, auth_source, external_id, requires_password_change, oidc_linked, oidc_issuer, activation_token_expires_at, activation_token_hash, verification_token_hash
		FROM users
		WHERE email = $1`

	return r.scanUserWithPassword(r.db.QueryRow(ctx, query, email))
}

func (r *PgxUserRepository) ListAll(ctx context.Context, opts repository.ListUserOptions) ([]*domain.User, int, error) {
	opts.Filter.IncludeDeleted = true
	return r.List(ctx, opts)
}

func (r *PgxUserRepository) ListDeleted(ctx context.Context, pagination repository.Pagination) ([]*domain.User, int, error) {
	query := `
		SELECT u.id, u.email, u.name, u.organization_id, u.role, u.banned, u.email_verified, u.deleted_at, u.created_at, u.updated_at, u.last_login_at, u.mfa_enabled, u.mfa_secret, u.mfa_recovery_codes,
		       u.auth_source, u.external_id, u.requires_password_change, u.oidc_linked, u.oidc_issuer, u.activation_token_expires_at, u.activation_token_hash, u.verification_token_hash,
		       o.domain, o.name AS organization_name,
		       COUNT(*) OVER() AS total_count
		FROM users u
		LEFT JOIN organizations o ON u.organization_id = o.id
		WHERE u.deleted_at IS NOT NULL
		ORDER BY u.created_at DESC`

	args := []any{}
	if pagination.PageSize > 0 {
		query += " LIMIT $1 OFFSET $2"
		args = append(args, pagination.PageSize, pagination.Offset)
	}

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list deleted users: %w", err)
	}
	defer rows.Close()

	users := []*domain.User{}
	var totalCount int

	for rows.Next() {
		// Manual scan because ListDeleted structure matches List?
		// Legacy used manual scan.
		// It returns total count too.

		var user domain.User
		var orgID *uuid.UUID
		var roleStr string
		var mfaRecoveryCodes []byte
		var orgDomain, orgName *string
		var externalID *string

		err := rows.Scan(
			&user.ID,
			&user.Email,
			&user.Name,
			&orgID,
			&roleStr,
			&user.Banned,
			&user.EmailVerified,
			&user.DeletedAt,
			&user.CreatedAt,
			&user.UpdatedAt,
			&user.LastLoginAt,
			&user.MFAEnabled,
			&user.MFASecret,
			&mfaRecoveryCodes,
			&user.AuthSource,
			&externalID,
			&user.RequiresPasswordChange,
			&user.OIDCLinked,
			&user.OIDCIssuer,
			&user.ActivationTokenExpiresAt,
			&user.ActivationTokenHash,
			&user.VerificationTokenHash,
			&orgDomain,
			&orgName,
			&totalCount,
		)

		if err != nil {
			return nil, 0, fmt.Errorf("failed to scan deleted user: %w", err)
		}

		if len(mfaRecoveryCodes) > 0 {
			if err := json.Unmarshal(mfaRecoveryCodes, &user.MFARecoveryCodes); err != nil {
				logger.Warning.Printf("failed to parse MFA recovery codes for user %s: %v", user.ID.String(), err)
			}
		}

		if orgID != nil {
			user.OrganizationID = *orgID
		}
		user.Role = domain.UserRole(roleStr)
		if externalID != nil {
			user.ExternalID = externalID
		}
		if orgDomain != nil {
			user.Domain = orgDomain
		}
		if orgName != nil {
			user.OrganizationName = orgName
		}
		users = append(users, &user)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("row iteration failed: %w", err)
	}

	return users, totalCount, nil
}

func (r *PgxUserRepository) HardDelete(_ context.Context, _ uuid.UUID) error {
	return fmt.Errorf("hard delete not supported, use soft delete instead")
}

func (r *PgxUserRepository) UpdateOrganizationID(ctx context.Context, id uuid.UUID, orgID uuid.UUID) error {
	query := `UPDATE users SET organization_id = $1 WHERE id = $2`

	var orgIDArg *uuid.UUID
	if orgID != uuid.Nil {
		orgIDArg = &orgID
	}

	result, err := r.db.Exec(ctx, query, orgIDArg, id)
	if err != nil {
		return fmt.Errorf("failed to update user organization: %w", err)
	}

	if result.RowsAffected() == 0 {
		return domain.ErrUserNotFound
	}

	return nil
}
