package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/metrics"
	"github.com/identuum/identuum-idp-oss/internal/repository"
	"github.com/jackc/pgx/v5"
	"github.com/prometheus/client_golang/prometheus"
)

// PgxAuthCodeRepository implements AuthCodeRepository using pgx
type PgxAuthCodeRepository struct {
	db DBTX
}

// NewPgxAuthCodeRepository creates a new pgx auth code repository
func NewPgxAuthCodeRepository(db DBTX) *PgxAuthCodeRepository {
	return &PgxAuthCodeRepository{db: db}
}

// Compile-time check
var _ repository.AuthCodeRepository = (*PgxAuthCodeRepository)(nil)

func (r *PgxAuthCodeRepository) Store(ctx context.Context, code *domain.AuthCode) error {
	timer := prometheus.NewTimer(metrics.DBQueryDuration.WithLabelValues("auth_code_repo", "store", "all"))
	defer timer.ObserveDuration()

	query := `
		INSERT INTO auth_codes (code, user_id, client_id, redirect_uri, nonce, scope, expires_at, created_at, code_challenge, code_challenge_method, session_id, audience)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
	`
	_, err := r.db.Exec(ctx, query,
		code.Code,
		code.UserID,
		code.ClientID,
		code.RedirectURI,
		code.Nonce,
		code.Scope,
		code.ExpiresAt,
		code.CreatedAt,
		code.CodeChallenge,
		code.CodeChallengeMethod,
		code.SessionID,
		code.Audience,
	)
	if err != nil {
		metrics.DBQueryDuration.WithLabelValues("auth_code_repo", "store", "error").Observe(timer.ObserveDuration().Seconds())
		return fmt.Errorf("failed to store auth code: %w", err)
	}
	metrics.DBQueryDuration.WithLabelValues("auth_code_repo", "store", "success").Observe(timer.ObserveDuration().Seconds())
	return nil
}

func (r *PgxAuthCodeRepository) Get(ctx context.Context, codeStr string) (*domain.AuthCode, error) {
	timer := prometheus.NewTimer(metrics.DBQueryDuration.WithLabelValues("auth_code_repo", "get", "all"))
	defer timer.ObserveDuration()

	query := `
		SELECT code, user_id, client_id, redirect_uri, nonce, scope, expires_at, created_at, code_challenge, code_challenge_method, session_id, audience
		FROM auth_codes
		WHERE code = $1
	`
	var code domain.AuthCode
	// Use pointers for handling NULLs in pgx
	var nonce, scope, challenge, method, audience *string
	var created, expires time.Time
	var userID uuid.UUID
	var sessionID *uuid.UUID

	err := r.db.QueryRow(ctx, query, codeStr).Scan(
		&code.Code,
		&userID,
		&code.ClientID,
		&code.RedirectURI,
		&nonce,
		&scope,
		&expires,
		&created,
		&challenge,
		&method,
		&sessionID,
		&audience,
	)
	if err != nil {
		metrics.DBQueryDuration.WithLabelValues("auth_code_repo", "get", "error").Observe(timer.ObserveDuration().Seconds())
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrAuthCodeNotFound
		}
		return nil, fmt.Errorf("failed to get auth code: %w", err)
	}
	metrics.DBQueryDuration.WithLabelValues("auth_code_repo", "get", "success").Observe(timer.ObserveDuration().Seconds())

	code.UserID = userID
	code.ExpiresAt = expires
	code.CreatedAt = created

	// Assign values if not nil
	if nonce != nil {
		code.Nonce = *nonce
	}
	if scope != nil {
		code.Scope = *scope
	}
	if challenge != nil {
		code.CodeChallenge = *challenge
	}
	if method != nil {
		code.CodeChallengeMethod = *method
	}
	if sessionID != nil {
		code.SessionID = sessionID
	}
	if audience != nil {
		code.Audience = *audience
	}

	return &code, nil
}

func (r *PgxAuthCodeRepository) Delete(ctx context.Context, codeStr string) error {
	timer := prometheus.NewTimer(metrics.DBQueryDuration.WithLabelValues("auth_code_repo", "delete", "all"))
	defer timer.ObserveDuration()

	query := `DELETE FROM auth_codes WHERE code = $1`
	_, err := r.db.Exec(ctx, query, codeStr)
	if err != nil {
		metrics.DBQueryDuration.WithLabelValues("auth_code_repo", "delete", "error").Observe(timer.ObserveDuration().Seconds())
		return fmt.Errorf("failed to delete auth code: %w", err)
	}
	metrics.DBQueryDuration.WithLabelValues("auth_code_repo", "delete", "success").Observe(timer.ObserveDuration().Seconds())
	return nil
}
