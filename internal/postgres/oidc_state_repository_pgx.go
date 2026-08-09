package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/metrics"
	"github.com/identuum/identuum-idp-oss/internal/repository"
	"github.com/identuum/identuum-idp-oss/logger"
	"github.com/jackc/pgx/v5"
	"github.com/prometheus/client_golang/prometheus"
)

// PgxOIDCStateRepository implements repository.OIDCStateRepository using pgx
type PgxOIDCStateRepository struct {
	db DBTX
}

// NewPgxOIDCStateRepository creates a new instance
func NewPgxOIDCStateRepository(db DBTX) *PgxOIDCStateRepository {
	return &PgxOIDCStateRepository{
		db: db,
	}
}

// Compile-time interface check
var _ repository.OIDCStateRepository = (*PgxOIDCStateRepository)(nil)

func (r *PgxOIDCStateRepository) Create(ctx context.Context, state *domain.OIDCState) error {
	timer := prometheus.NewTimer(metrics.DBQueryDuration.WithLabelValues("oidc_state_repo", "create", "all"))
	defer timer.ObserveDuration()

	query := `
		INSERT INTO oidc_states (
			state, organization_id, provider_id, nonce, pkce_verifier_encrypted, 
			redirect_uri, return_url, code_challenge_method, expires_at, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW())`

	_, err := r.db.Exec(ctx, query,
		state.State,
		state.OrganizationID,
		state.ProviderID,
		state.Nonce,
		state.PKCEVerifierEncrypted,
		state.RedirectURI,
		state.ReturnURL,
		state.CodeChallengeMethod,
		state.ExpiresAt,
	)

	if err != nil {
		metrics.DBQueryDuration.WithLabelValues("oidc_state_repo", "create", "error").Observe(timer.ObserveDuration().Seconds())
		logger.Error.Printf("Failed to create OIDC state: %v", err)
		return fmt.Errorf("failed to persist OIDC state: %w", err)
	}

	metrics.DBQueryDuration.WithLabelValues("oidc_state_repo", "create", "success").Observe(timer.ObserveDuration().Seconds())
	return nil
}

func (r *PgxOIDCStateRepository) Get(ctx context.Context, stateKey string) (*domain.OIDCState, error) {
	timer := prometheus.NewTimer(metrics.DBQueryDuration.WithLabelValues("oidc_state_repo", "get", "all"))
	defer timer.ObserveDuration()

	const query = `
		SELECT state, organization_id, provider_id, nonce, pkce_verifier_encrypted,
		       redirect_uri, return_url, code_challenge_method, expires_at, created_at
		FROM oidc_states
		WHERE state = $1`

	s, err := scanOIDCState(r.db.QueryRow(ctx, query, stateKey))
	if err != nil {
		metrics.DBQueryDuration.WithLabelValues("oidc_state_repo", "get", "error").Observe(timer.ObserveDuration().Seconds())
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("OIDC state not found: %w", err)
		}
		logger.Error.Printf("Failed to get OIDC state: %v", err)
		return nil, fmt.Errorf("failed to get OIDC state: %w", err)
	}

	metrics.DBQueryDuration.WithLabelValues("oidc_state_repo", "get", "success").Observe(timer.ObserveDuration().Seconds())
	return s, nil
}

// ConsumeByState is the atomic single-use gate for upstream-login state.
// It deletes and returns the row in ONE statement — DELETE … WHERE
// state = $1 RETURNING …. Under READ COMMITTED two concurrent consumes
// serialize on the row lock: the first deletes and receives the RETURNING
// row; the second re-evaluates against the freshly committed (now-absent)
// row, matches zero rows, and receives pgx.ErrNoRows. A zero-row result
// (already consumed, never existed, or expired-and-swept) returns
// (nil, nil) so the caller rejects with no session and no token exchange.
// There is no separate lock/delete and no ignorable command tag — the
// RETURNED ROW IS THE PROOF the caller won.
func (r *PgxOIDCStateRepository) ConsumeByState(ctx context.Context, stateKey string) (*domain.OIDCState, error) {
	timer := prometheus.NewTimer(metrics.DBQueryDuration.WithLabelValues("oidc_state_repo", "consume", "all"))
	defer timer.ObserveDuration()

	const query = `
		DELETE FROM oidc_states
		WHERE state = $1
		RETURNING state, organization_id, provider_id, nonce, pkce_verifier_encrypted,
		          redirect_uri, return_url, code_challenge_method, expires_at, created_at`

	s, err := scanOIDCState(r.db.QueryRow(ctx, query, stateKey))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// Already consumed / never existed / swept — the atomic
			// single-use reject. Not an error: the caller treats a nil
			// row as an invalid state.
			metrics.DBQueryDuration.WithLabelValues("oidc_state_repo", "consume", "miss").Observe(timer.ObserveDuration().Seconds())
			return nil, nil
		}
		metrics.DBQueryDuration.WithLabelValues("oidc_state_repo", "consume", "error").Observe(timer.ObserveDuration().Seconds())
		logger.Error.Printf("Failed to consume OIDC state: %v", err)
		return nil, fmt.Errorf("failed to consume OIDC state: %w", err)
	}

	metrics.DBQueryDuration.WithLabelValues("oidc_state_repo", "consume", "success").Observe(timer.ObserveDuration().Seconds())
	return s, nil
}

// scanOIDCState scans a full oidc_states row — the shared column order of
// both the SELECT in Get and the DELETE … RETURNING in ConsumeByState —
// into a domain.OIDCState.
func scanOIDCState(row pgx.Row) (*domain.OIDCState, error) {
	var s domain.OIDCState
	if err := row.Scan(
		&s.State,
		&s.OrganizationID,
		&s.ProviderID,
		&s.Nonce,
		&s.PKCEVerifierEncrypted,
		&s.RedirectURI,
		&s.ReturnURL,
		&s.CodeChallengeMethod,
		&s.ExpiresAt,
		&s.CreatedAt,
	); err != nil {
		return nil, err
	}
	return &s, nil
}

func (r *PgxOIDCStateRepository) Delete(ctx context.Context, stateKey string) error {
	timer := prometheus.NewTimer(metrics.DBQueryDuration.WithLabelValues("oidc_state_repo", "delete", "all"))
	defer timer.ObserveDuration()

	query := `DELETE FROM oidc_states WHERE state = $1`
	_, err := r.db.Exec(ctx, query, stateKey)
	if err != nil {
		metrics.DBQueryDuration.WithLabelValues("oidc_state_repo", "delete", "error").Observe(timer.ObserveDuration().Seconds())
		logger.Error.Printf("Failed to delete OIDC state: %v", err)
		return fmt.Errorf("failed to delete OIDC state: %w", err)
	}
	metrics.DBQueryDuration.WithLabelValues("oidc_state_repo", "delete", "success").Observe(timer.ObserveDuration().Seconds())
	return nil
}

// DeleteExpired prunes every oidc_states row whose expires_at is in the past
// and returns the number of rows removed. A pure maintenance sweep — the
// callback path already single-use-deletes consumed rows, so this only reaps
// states abandoned before the callback (no live row is ever eligible).
func (r *PgxOIDCStateRepository) DeleteExpired(ctx context.Context) (int64, error) {
	timer := prometheus.NewTimer(metrics.DBQueryDuration.WithLabelValues("oidc_state_repo", "delete_expired", "all"))
	defer timer.ObserveDuration()

	query := `DELETE FROM oidc_states WHERE expires_at < NOW()`
	tag, err := r.db.Exec(ctx, query)
	if err != nil {
		metrics.DBQueryDuration.WithLabelValues("oidc_state_repo", "delete_expired", "error").Observe(timer.ObserveDuration().Seconds())
		logger.Error.Printf("Failed to delete expired OIDC states: %v", err)
		return 0, fmt.Errorf("failed to delete expired OIDC states: %w", err)
	}
	metrics.DBQueryDuration.WithLabelValues("oidc_state_repo", "delete_expired", "success").Observe(timer.ObserveDuration().Seconds())
	return tag.RowsAffected(), nil
}
