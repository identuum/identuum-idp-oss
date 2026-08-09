package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/metrics"
	"github.com/identuum/identuum-idp-oss/internal/repository"
	"github.com/identuum/identuum-idp-oss/logger"
	"github.com/jackc/pgx/v5"
	"github.com/prometheus/client_golang/prometheus"
)

// PgxSessionRepository implements repository.SessionRepository with pgx
type PgxSessionRepository struct {
	db DBTX
}

// NewPgxSessionRepository creates a new instance
func NewPgxSessionRepository(db DBTX) *PgxSessionRepository {
	return &PgxSessionRepository{
		db: db,
	}
}

// Compile-time interface checks
var _ repository.SessionRepository = (*PgxSessionRepository)(nil)
var _ repository.AdminSessionRepository = (*PgxSessionRepository)(nil)

// scanSession helper to scan session rows.
// Column order MUST match every SELECT in this file: id, user_id, token_selector,
// token_validator_hash, created_at, expires_at, last_used_at, revoked_at,
// revoked_reason, is_valid, acr, amr, remember_me, client_id,
// last_acr_uplift_at, last_acr_uplift_value, ip_address, user_agent,
// prev_validator_hash, prev_rotated_at.
func (r *PgxSessionRepository) scanSession(row pgx.Row) (*domain.Session, error) {
	var session domain.Session
	var tokenSelector *string // pgx can scan into *string for nullable text
	var tokenValidatorHash *string
	var lastUsedAt *time.Time
	var revokedAt *time.Time
	var revokedReason *string
	var amrStr *string
	var clientID *string
	var lastACRUpliftAt *time.Time
	var lastACRUpliftValue *string
	var ipAddress *string
	var userAgent *string
	var prevValidatorHash *string
	var prevRotatedAt *time.Time

	err := row.Scan(
		&session.ID,
		&session.UserID,
		&tokenSelector,
		&tokenValidatorHash,
		&session.CreatedAt,
		&session.ExpiresAt,
		&lastUsedAt,
		&revokedAt,
		&revokedReason,
		&session.IsValid,
		&session.Acr,
		&amrStr,
		&session.RememberMe,
		&clientID,
		&lastACRUpliftAt,
		&lastACRUpliftValue,
		&ipAddress,
		&userAgent,
		&prevValidatorHash,
		&prevRotatedAt,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrSessionNotFound
		}
		return nil, fmt.Errorf("failed to scan session: %w", err)
	}

	// Convert nullable fields
	if tokenSelector != nil {
		selector, err := uuid.Parse(*tokenSelector)
		if err == nil {
			session.TokenSelector = &selector
		}
	}
	session.TokenValidatorHash = tokenValidatorHash
	session.LastUsedAt = lastUsedAt
	session.RevokedAt = revokedAt
	session.RevokedReason = revokedReason
	session.ClientID = clientID
	session.LastACRUpliftAt = lastACRUpliftAt
	session.LastACRUpliftValue = lastACRUpliftValue
	session.IPAddress = ipAddress
	session.UserAgent = userAgent
	session.PrevValidatorHash = prevValidatorHash
	session.PrevRotatedAt = prevRotatedAt
	if amrStr != nil {
		session.Amr = strings.Split(*amrStr, ",")
	}

	return &session, nil
}

// Create creates a new session
func (r *PgxSessionRepository) Create(ctx context.Context, session *domain.Session) (*domain.Session, error) {
	// Use the validator hash as provided
	var validatorHash *string
	if session.TokenValidatorHash != nil {
		validatorHash = session.TokenValidatorHash
	}

	logger.Debug.Printf("Creating secure session for userID: %s", session.UserID)

	var sessionID uuid.UUID
	var createdAt time.Time

	err := r.db.QueryRow(
		ctx,
		// P2-21 principle A+B: created_at + expires_at must come from ONE clock
		// and ONE instant. created_at defaults to now(); expires_at is derived as
		// now() + the TTL, where the TTL is the caller's (ExpiresAt - CreatedAt) —
		// a DURATION, clock-independent. Postgres now()/CURRENT_TIMESTAMP return
		// transaction-start time (STABLE within a statement), so the default
		// created_at and this now() are the SAME instant. Result: expires_at =
		// created_at + TTL exactly, both on the DB clock, satisfying
		// chk_expires_after_created by construction and matching the DB clock a
		// later rotation writes last_used_at from (so chk_last_used_after_created
		// holds too). The old code inserted a HOST-clock absolute expires_at.
		`INSERT INTO sessions (user_id, token_selector, token_validator_hash, expires_at, is_valid, acr, amr, remember_me, client_id, ip_address, user_agent)
		 VALUES ($1, $2, $3, now() + ($4::timestamptz - $12::timestamptz), $5, $6, $7, $8, $9, $10, $11)
		 RETURNING id, created_at, is_valid`,
		session.UserID, session.TokenSelector, validatorHash, session.ExpiresAt, session.IsValid, session.Acr, strings.Join(session.Amr, ","), session.RememberMe, session.ClientID, session.IPAddress, session.UserAgent, session.CreatedAt,
	).Scan(&sessionID, &createdAt, &session.IsValid)

	if err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	logger.Debug.Printf("Secure session created successfully: %s (is_valid=%v)", sessionID, session.IsValid)
	created := *session
	created.ID = sessionID
	created.CreatedAt = createdAt
	return &created, nil
}

// GetByID retrieves a session by its ID
func (r *PgxSessionRepository) GetByID(ctx context.Context, id uuid.UUID) (*domain.Session, error) {

	query := `
		SELECT id, user_id, token_selector, token_validator_hash, created_at,
		       expires_at, last_used_at, revoked_at, revoked_reason, is_valid, acr, amr, remember_me, client_id, last_acr_uplift_at, last_acr_uplift_value,
		       ip_address, user_agent, prev_validator_hash, prev_rotated_at
		FROM sessions
		WHERE id = $1`

	timer := prometheus.NewTimer(metrics.DBQueryDuration.WithLabelValues("session_repo", "get_by_id", "all"))
	defer timer.ObserveDuration()

	session, err := r.scanSession(r.db.QueryRow(ctx, query, id))
	if err != nil {
		metrics.DBQueryDuration.WithLabelValues("session_repo", "get_by_id", "error").Observe(timer.ObserveDuration().Seconds())
		return nil, err
	}
	metrics.DBQueryDuration.WithLabelValues("session_repo", "get_by_id", "success").Observe(timer.ObserveDuration().Seconds())
	return session, nil
}

// GetSessionWithUserAndOrgStatus retrieves session with user and org status
func (r *PgxSessionRepository) GetSessionWithUserAndOrgStatus(ctx context.Context, sessionID uuid.UUID) (*domain.SessionValidationInfo, error) {
	var session domain.Session
	var tokenSelector *string
	var tokenValidatorHash *string
	var lastUsedAt *time.Time
	var revokedAt *time.Time
	var revokedReason *string
	var amrStr *string
	var userActive, userDeleted bool
	var orgActive, orgDeleted *bool
	var orgID *uuid.UUID

	var clientID *string
	query := `
		SELECT
			s.id, s.user_id, s.token_selector, s.token_validator_hash,
			s.created_at, s.expires_at, s.last_used_at, s.revoked_at,
			s.revoked_reason, s.is_valid, s.acr, s.amr, s.remember_me, s.client_id,
			NOT u.banned as user_active, (u.deleted_at IS NOT NULL) as user_deleted,
			o.id as organization_id, o.active as org_active, (o.deleted_at IS NOT NULL) as org_deleted
		FROM sessions s
		INNER JOIN users u ON s.user_id = u.id
		LEFT JOIN organizations o ON u.organization_id = o.id
		WHERE s.id = $1`

	err := r.db.QueryRow(ctx, query, sessionID).Scan(
		&session.ID,
		&session.UserID,
		&tokenSelector,
		&tokenValidatorHash,
		&session.CreatedAt,
		&session.ExpiresAt,
		&lastUsedAt,
		&revokedAt,
		&revokedReason,
		&session.IsValid,
		&session.Acr,
		&amrStr,
		&session.RememberMe,
		&clientID,
		&userActive,
		&userDeleted,
		&orgID,
		&orgActive,
		&orgDeleted,
	)

	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrSessionNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get session with user and org status: %w", err)
	}

	// Convert nullable fields
	if tokenSelector != nil {
		selector, err := uuid.Parse(*tokenSelector)
		if err == nil {
			session.TokenSelector = &selector
		}
	}
	session.TokenValidatorHash = tokenValidatorHash
	session.LastUsedAt = lastUsedAt
	session.RevokedAt = revokedAt
	session.RevokedReason = revokedReason
	session.ClientID = clientID
	if amrStr != nil {
		session.Amr = strings.Split(*amrStr, ",")
	}

	logger.Debug.Printf("GetSession details: OrgActivePtr=%v, OrgDeletedPtr=%v, OrgIDPtr=%v", orgActive, orgDeleted, orgID)
	if orgActive != nil {
		logger.Debug.Printf("OrgActive value: %v", *orgActive)
	}

	validationInfo := &domain.SessionValidationInfo{
		Session:     &session,
		UserActive:  userActive,
		UserDeleted: userDeleted,
	}

	if orgActive != nil {
		validationInfo.OrgActive = *orgActive
	}
	if orgDeleted != nil {
		validationInfo.OrgDeleted = *orgDeleted
	}
	if orgID != nil {
		validationInfo.OrganizationID = *orgID
	}

	if orgActive == nil {
		validationInfo.OrgActive = true
		validationInfo.OrgDeleted = false
	}

	return validationInfo, nil
}

// GetByTokenSelector retrieves a session by token selector
func (r *PgxSessionRepository) GetByTokenSelector(ctx context.Context, selector uuid.UUID) (*domain.Session, error) {

	query := `
		SELECT id, user_id, token_selector, token_validator_hash, created_at,
		       expires_at, last_used_at, revoked_at, revoked_reason, is_valid, acr, amr, remember_me, client_id, last_acr_uplift_at, last_acr_uplift_value,
		       ip_address, user_agent, prev_validator_hash, prev_rotated_at
		FROM sessions
		WHERE token_selector = $1`

	return r.scanSession(r.db.QueryRow(ctx, query, selector))
}

// ListByUserID retrieves all sessions for a specific user
func (r *PgxSessionRepository) ListByUserID(ctx context.Context, userID uuid.UUID, includeInvalid bool) ([]*domain.Session, error) {
	query := `
		SELECT id, user_id, token_selector, token_validator_hash, created_at, expires_at, last_used_at,
		       revoked_at, revoked_reason, is_valid, acr, amr, remember_me, client_id, last_acr_uplift_at, last_acr_uplift_value,
		       ip_address, user_agent, prev_validator_hash, prev_rotated_at
		FROM sessions
		WHERE user_id = $1`

	if !includeInvalid {
		query += " AND is_valid = true AND revoked_at IS NULL"
	}

	query += " ORDER BY created_at DESC"

	rows, err := r.db.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to list user sessions: %w", err)
	}
	defer rows.Close()

	sessions := []*domain.Session{}

	for rows.Next() {
		session, err := r.scanSession(rows)
		if err != nil {
			return nil, fmt.Errorf("failed to scan session row: %w", err)
		}
		sessions = append(sessions, session)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating user sessions: %w", err)
	}

	return sessions, nil
}

// RecordACRUplift atomically updates the step-up tracking columns
// (last_acr_uplift_at, last_acr_uplift_value) on a session in
// response to a successful ACR step-up event (e.g. WebAuthn
// ceremony completing on top of an existing password+TOTP session).
// The original sessions.acr column is intentionally NOT touched —
// preserving the original-login ACR is part of the audit signal.
//
// uplift.LastACRUpliftAt and uplift.LastACRUpliftValue MUST both be
// non-nil; the DB CHECK chk_sessions_acr_uplift_paired enforces that
// pair-or-neither invariant. This method does not implement the
// "clear uplift" path — there is no business case for it today.
func (r *PgxSessionRepository) RecordACRUplift(ctx context.Context, sessionID uuid.UUID, upliftAt time.Time, upliftValue string) error {
	if upliftValue == "" {
		return fmt.Errorf("RecordACRUplift: upliftValue cannot be empty")
	}
	result, err := r.db.Exec(
		ctx,
		`UPDATE sessions
		 SET last_acr_uplift_at = $1, last_acr_uplift_value = $2
		 WHERE id = $3`,
		upliftAt, upliftValue, sessionID,
	)
	if err != nil {
		return fmt.Errorf("failed to record acr uplift: %w", err)
	}
	if result.RowsAffected() == 0 {
		return domain.ErrSessionNotFound
	}
	return nil
}

// Update updates a session's mutable fields
func (r *PgxSessionRepository) Update(ctx context.Context, session *domain.Session, orgID uuid.UUID) error {
	// P2-21 principle A: last_used_at comes from the DB clock (now()), never
	// the host clock, matching Create/RotateToken — a skewed host can
	// otherwise violate chk_last_used_after_created (created_at is DB-clock).
	// No caller legitimately supplies an explicit LastUsedAt: the only
	// SessionRepository.Update caller is the (dormant) cached wrapper, and
	// the only host-clock setter Session.UpdateLastUsed has no live caller.
	query := `
		UPDATE sessions
		SET token_validator_hash = $1, last_used_at = now(), acr = $2, amr = $3, remember_me = $4
		WHERE id = $5`

	args := []any{session.TokenValidatorHash, session.Acr, strings.Join(session.Amr, ","), session.RememberMe, session.ID}

	if orgID != uuid.Nil {
		query += ` AND user_id IN (SELECT id FROM users WHERE organization_id = $6)`
		args = append(args, orgID)
	}

	result, err := r.db.Exec(ctx, query, args...)

	if err != nil {
		return fmt.Errorf("failed to update session: %w", err)
	}

	rowsAffected := result.RowsAffected()
	if rowsAffected == 0 {
		return domain.ErrSessionNotFound
	}

	return nil
}

// RotateToken is the P0-12 compare-and-set rotation: it advances the validator
// hash and persists the extended expiry in ONE statement, guarded on the
// validator the caller validated. Under READ COMMITTED two concurrent rotations
// serialize on the row lock — the first flips token_validator_hash (1 row); the
// second re-evaluates `token_validator_hash = $5` against the freshly committed
// row, matches nothing (0 rows), and loses. A zero-row result (lost CAS or the
// session became inactive) returns (nil, false, nil) so the caller rejects the
// loser as BENIGN — reuse/theft is caught earlier by the read-time validator
// mismatch, never here.
func (r *PgxSessionRepository) RotateToken(ctx context.Context, sessionID uuid.UUID, expectedValidatorHash, newValidatorHash string, newExpiresAt, lastUsedAt time.Time) (*domain.Session, bool, error) {
	// P2-21 principle A+B: last_used_at + the extended expires_at come from the
	// DB clock, captured ONCE. last_used_at = now(); expires_at = now() + the TTL,
	// where the TTL is the caller's (newExpiresAt - lastUsedAt) — a DURATION,
	// clock-independent. Both now() calls in this UPDATE return the identical
	// transaction-start instant (now() is STABLE within a statement), so the two
	// timestamps are internally consistent. Because created_at was ALSO written
	// from the DB clock at insert (see Create) and rotation happens later,
	// last_used_at = now() >= created_at holds by construction — the P2-21 fix
	// for chk_last_used_after_created (the host-clock last_used_at previously
	// written here could land BEFORE the DB-clock created_at under skew). The CAS
	// guard, the RETURNING projection, and the +TTL expiry EXTENSION are
	// unchanged — only the timestamp SOURCE moves from the host clock to now().
	// P0-12b: prev_validator_hash/prev_rotated_at capture the OUTGOING
	// validator and the DB-clock instant it stopped being current, in
	// the SAME statement as the CAS. The right-hand sides of a Postgres
	// UPDATE's SET list are all evaluated against the PRE-update row, so
	// `prev_validator_hash = token_validator_hash` reads the about-to-be-
	// superseded hash, not the new one being written by this same
	// statement — no subquery needed. now() is STABLE within the
	// statement (P2-21), so prev_rotated_at matches expires_at/last_used_at's
	// clock source exactly.
	const q = `
		UPDATE sessions
		SET token_validator_hash = $2,
		    prev_validator_hash = token_validator_hash,
		    prev_rotated_at = now(),
		    expires_at = now() + ($3::timestamptz - $4::timestamptz),
		    last_used_at = now()
		WHERE id = $1
		  AND token_validator_hash = $5
		  AND is_valid = true
		  AND revoked_at IS NULL
		  AND expires_at > now()
		RETURNING id, user_id, token_selector, token_validator_hash, created_at, expires_at, last_used_at, revoked_at, revoked_reason, is_valid, acr, amr, remember_me, client_id, last_acr_uplift_at, last_acr_uplift_value, ip_address, user_agent, prev_validator_hash, prev_rotated_at`
	session, err := r.scanSession(r.db.QueryRow(ctx, q, sessionID, newValidatorHash, newExpiresAt, lastUsedAt, expectedValidatorHash))
	if err != nil {
		if errors.Is(err, domain.ErrSessionNotFound) {
			return nil, false, nil // lost CAS / session inactive — benign, caller rejects
		}
		return nil, false, err
	}
	return session, true, nil
}

// Revoke revokes a specific session by ID
func (r *PgxSessionRepository) Revoke(ctx context.Context, id uuid.UUID, orgID uuid.UUID, reason string) error {
	timer := prometheus.NewTimer(metrics.DBQueryDuration.WithLabelValues("session_repo", "revoke", "all"))
	defer timer.ObserveDuration()

	query := `
		UPDATE sessions
		SET revoked_at = NOW(),
		    revoked_reason = $2,
		    is_valid = false
		WHERE id = $1 AND revoked_at IS NULL`
	args := []any{id, reason}

	if orgID != uuid.Nil {
		query += ` AND user_id IN (SELECT id FROM users WHERE organization_id = $3)`
		args = append(args, orgID)
	}

	result, err := r.db.Exec(ctx, query, args...)

	if err != nil {
		metrics.DBQueryDuration.WithLabelValues("session_repo", "revoke", "error").Observe(timer.ObserveDuration().Seconds())
		return fmt.Errorf("failed to revoke session: %w", err)
	}

	rowsAffected := result.RowsAffected()

	if rowsAffected == 0 {
		return domain.ErrSessionNotFound
	}

	metrics.DBQueryDuration.WithLabelValues("session_repo", "revoke", "success").Observe(timer.ObserveDuration().Seconds())

	logger.Info.WithFields(map[string]any{
		"session_id": id,
		"reason":     reason,
	}).Print("Session revoked successfully")

	return nil
}

// RevokeByUserID revokes all active sessions for a user
func (r *PgxSessionRepository) RevokeByUserID(ctx context.Context, userID uuid.UUID, reason string) error {
	timer := prometheus.NewTimer(metrics.DBQueryDuration.WithLabelValues("session_repo", "revoke_by_user", "all"))
	defer timer.ObserveDuration()

	if userID == uuid.Nil {
		return errors.New("user ID cannot be nil")
	}

	if reason == "" {
		reason = "admin_revocation"
	}

	query := `
		UPDATE sessions
		SET revoked_at = NOW(),
		    revoked_reason = $2,
		    is_valid = false
		WHERE user_id = $1
		AND revoked_at IS NULL`

	result, err := r.db.Exec(ctx, query, userID, reason)
	if err != nil {
		metrics.DBQueryDuration.WithLabelValues("session_repo", "revoke_by_user", "error").Observe(timer.ObserveDuration().Seconds())
		return fmt.Errorf("failed to revoke user sessions: %w", err)
	}

	rowsAffected := result.RowsAffected()

	metrics.DBQueryDuration.WithLabelValues("session_repo", "revoke_by_user", "success").Observe(timer.ObserveDuration().Seconds())

	logger.Info.WithFields(map[string]any{
		"user_id":        userID,
		"reason":         reason,
		"sessions_count": rowsAffected,
	}).Print("Successfully revoked all user sessions")

	return nil
}

// RevokeByOrganizationID revokes all sessions for users in an organization
func (r *PgxSessionRepository) RevokeByOrganizationID(ctx context.Context, orgID uuid.UUID, reason string) error {
	if orgID == uuid.Nil {
		return errors.New("organization ID cannot be nil")
	}

	if reason == "" {
		reason = "admin_revocation"
	}

	query := `
		UPDATE sessions
		SET revoked_at = NOW(),
		    revoked_reason = $2,
		    is_valid = false
		WHERE user_id IN (SELECT id FROM users WHERE organization_id = $1)
		AND revoked_at IS NULL`

	result, err := r.db.Exec(ctx, query, orgID, reason)
	if err != nil {
		return fmt.Errorf("failed to revoke organization sessions: %w", err)
	}

	rowsAffected := result.RowsAffected()

	logger.Info.WithFields(map[string]any{
		"org_id":         orgID,
		"reason":         reason,
		"sessions_count": rowsAffected,
	}).Print("Successfully revoked all organization sessions")

	return nil
}

// Delete soft deletes a session by revoking it
func (r *PgxSessionRepository) Delete(ctx context.Context, id uuid.UUID, orgID uuid.UUID) error {
	return r.Revoke(ctx, id, orgID, "deleted")
}

// ListActiveByUserID retrieves only active (non-expired, non-revoked) sessions for a user
func (r *PgxSessionRepository) ListActiveByUserID(ctx context.Context, userID uuid.UUID) ([]*domain.Session, error) {
	return r.ListByUserID(ctx, userID, false)
}

// CountActiveByUserID counts active sessions for a user
func (r *PgxSessionRepository) CountActiveByUserID(ctx context.Context, userID uuid.UUID) (int, error) {
	var count int
	err := r.db.QueryRow(ctx,
		`SELECT COUNT(*) FROM sessions
		 WHERE user_id = $1 AND is_valid = true AND expires_at > NOW() AND revoked_at IS NULL`,
		userID).Scan(&count)

	if err != nil {
		return 0, fmt.Errorf("failed to count active sessions: %w", err)
	}

	return count, nil
}

// DeleteExpiredReturning removes expired sessions and returns them for auditing
func (r *PgxSessionRepository) DeleteExpiredReturning(ctx context.Context, retentionPeriod time.Duration, batchSize int) ([]*domain.Session, error) {
	timer := prometheus.NewTimer(metrics.DBQueryDuration.WithLabelValues("session_repo", "delete_expired_returning", "all"))
	defer timer.ObserveDuration()

	cutoffTime := time.Now().Add(-retentionPeriod)
	deletedSessions := []*domain.Session{}

	// Target only *expired* sessions (inactivity: expires_at < cutoff), not
	// revoked ones — a revoked session already received an audit event at
	// revocation time, so only expirations need the "Session Expiration
	// Audit" emission by the caller. Expired sessions usually have
	// revoked_at = NULL, hence the single `WHERE expires_at < $1` filter.

	query := `
		DELETE FROM sessions
		WHERE id IN (
			SELECT id FROM sessions
			WHERE expires_at < $1
			ORDER BY expires_at ASC
			LIMIT $2
		)
		RETURNING id, user_id, token_selector, token_validator_hash, created_at,
		          expires_at, last_used_at, revoked_at, revoked_reason, is_valid, acr, amr, remember_me, client_id, last_acr_uplift_at, last_acr_uplift_value,
		          ip_address, user_agent, prev_validator_hash, prev_rotated_at`

	rows, err := r.db.Query(ctx, query, cutoffTime, batchSize)
	if err != nil {
		metrics.DBQueryDuration.WithLabelValues("session_repo", "delete_expired_returning", "error").Observe(timer.ObserveDuration().Seconds())
		return nil, fmt.Errorf("failed to delete expired sessions: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		session, err := r.scanSession(rows)
		if err != nil {
			return nil, fmt.Errorf("failed to scan deleted session: %w", err)
		}
		deletedSessions = append(deletedSessions, session)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating deleted rows: %w", err)
	}

	metrics.DBQueryDuration.WithLabelValues("session_repo", "delete_expired_returning", "success").Observe(timer.ObserveDuration().Seconds())
	return deletedSessions, nil
}

// === AdminSessionRepository interface implementation ===

// ListAll retrieves all sessions with filters and pagination
func (r *PgxSessionRepository) ListAll(ctx context.Context, filter repository.SessionFilter, pagination repository.Pagination) ([]*domain.Session, int, error) {
	query := `
		SELECT id, user_id, token_selector, token_validator_hash, created_at, expires_at, last_used_at,
		       revoked_at, revoked_reason, is_valid, acr, amr, remember_me, client_id, last_acr_uplift_at, last_acr_uplift_value,
		       ip_address, user_agent, prev_validator_hash, prev_rotated_at
		FROM sessions
		WHERE 1=1`

	countQuery := `SELECT COUNT(*) FROM sessions WHERE 1=1`
	args := []any{}
	argIndex := 1

	// Apply filters
	if filter.UserID != nil {
		query += fmt.Sprintf(" AND user_id = $%d", argIndex)
		countQuery += fmt.Sprintf(" AND user_id = $%d", argIndex)
		args = append(args, *filter.UserID)
		argIndex++
	}

	if filter.IsValid != nil {
		query += fmt.Sprintf(" AND is_valid = $%d", argIndex)
		countQuery += fmt.Sprintf(" AND is_valid = $%d", argIndex)
		args = append(args, *filter.IsValid)
		argIndex++
	}

	if filter.IsExpired != nil {
		if *filter.IsExpired {
			query += " AND expires_at < NOW()"
			countQuery += " AND expires_at < NOW()"
		} else {
			query += " AND expires_at > NOW()"
			countQuery += " AND expires_at > NOW()"
		}
	}

	// Get total count
	var totalCount int
	err := r.db.QueryRow(ctx, countQuery, args...).Scan(&totalCount)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count sessions: %w", err)
	}

	// Add pagination
	query += " ORDER BY created_at DESC"
	if pagination.PageSize > 0 {
		query += fmt.Sprintf(" LIMIT $%d OFFSET $%d", argIndex, argIndex+1)
		args = append(args, pagination.PageSize, pagination.Offset)
	}

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list sessions: %w", err)
	}
	defer rows.Close()

	sessions := []*domain.Session{}

	for rows.Next() {
		session, err := r.scanSession(rows)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to scan session row: %w", err)
		}
		sessions = append(sessions, session)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error iterating session rows: %w", err)
	}

	return sessions, totalCount, nil
}

// ListByOrganizationID retrieves sessions for all users in an organization
func (r *PgxSessionRepository) ListByOrganizationID(ctx context.Context, orgID uuid.UUID, pagination repository.Pagination) ([]*domain.Session, int, error) {
	countQuery := `
		SELECT COUNT(*) FROM sessions s
		JOIN users u ON s.user_id = u.id
		WHERE u.organization_id = $1`

	var totalCount int
	err := r.db.QueryRow(ctx, countQuery, orgID).Scan(&totalCount)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count organization sessions: %w", err)
	}

	query := `
		SELECT s.id, s.user_id, s.token_selector, s.token_validator_hash, s.created_at, s.expires_at, s.last_used_at,
		       s.revoked_at, s.revoked_reason, s.is_valid, s.acr, s.amr, s.remember_me, s.client_id, s.last_acr_uplift_at, s.last_acr_uplift_value,
		       s.ip_address, s.user_agent, s.prev_validator_hash, s.prev_rotated_at
		FROM sessions s
		JOIN users u ON s.user_id = u.id
		WHERE u.organization_id = $1
		ORDER BY s.created_at DESC`

	args := []any{orgID}
	if pagination.PageSize > 0 {
		query += " LIMIT $2 OFFSET $3"
		args = append(args, pagination.PageSize, pagination.Offset)
	}

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list organization sessions: %w", err)
	}
	defer rows.Close()

	sessions := []*domain.Session{}

	for rows.Next() {
		session, err := r.scanSession(rows)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to scan session row: %w", err)
		}
		sessions = append(sessions, session)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error iterating organization session rows: %w", err)
	}

	return sessions, totalCount, nil
}

// GetStats retrieves global session statistics
func (r *PgxSessionRepository) GetStats(ctx context.Context) (map[string]int, error) {
	var total, active, expired, revoked int

	query := `
		SELECT
			COUNT(*) as total,
			COUNT(*) FILTER (WHERE is_valid = true AND expires_at > NOW() AND revoked_at IS NULL) as active,
			COUNT(*) FILTER (WHERE expires_at < NOW()) as expired,
			COUNT(*) FILTER (WHERE revoked_at IS NOT NULL) as revoked
		FROM sessions`

	err := r.db.QueryRow(ctx, query).Scan(&total, &active, &expired, &revoked)
	if err != nil {
		return nil, fmt.Errorf("failed to get session stats: %w", err)
	}

	stats := map[string]int{
		"total":   total,
		"active":  active,
		"expired": expired,
		"revoked": revoked,
	}
	return stats, nil
}

// GetStatsByOrganization retrieves session statistics for a specific organization
func (r *PgxSessionRepository) GetStatsByOrganization(ctx context.Context, orgID uuid.UUID) (map[string]int, error) {
	var total, active, expired, revoked int

	query := `
		SELECT
			COUNT(*) as total,
			COUNT(*) FILTER (WHERE s.is_valid = true AND s.expires_at > NOW() AND s.revoked_at IS NULL) as active,
			COUNT(*) FILTER (WHERE s.expires_at < NOW()) as expired,
			COUNT(*) FILTER (WHERE s.revoked_at IS NOT NULL) as revoked
		FROM sessions s
		JOIN users u ON s.user_id = u.id
		WHERE u.organization_id = $1`

	err := r.db.QueryRow(ctx, query, orgID).Scan(&total, &active, &expired, &revoked)
	if err != nil {
		logger.Error.Printf("Failed to get organization session stats: %v", err)
		return nil, fmt.Errorf("failed to get organization session stats: %w", err)
	}

	stats := map[string]int{
		"total":   total,
		"active":  active,
		"expired": expired,
		"revoked": revoked,
	}
	return stats, nil
}
