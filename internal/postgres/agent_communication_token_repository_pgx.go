package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/repository"
)

// PgxAgentCommunicationTokenRepository is the pgx implementation of
// repository.AgentCommunicationTokenRepository over agent_communication_tokens
// (migration 0039).
type PgxAgentCommunicationTokenRepository struct {
	db DBTX
}

var _ repository.AgentCommunicationTokenRepository = (*PgxAgentCommunicationTokenRepository)(nil)

// NewPgxAgentCommunicationTokenRepository constructs the repository.
func NewPgxAgentCommunicationTokenRepository(db DBTX) *PgxAgentCommunicationTokenRepository {
	return &PgxAgentCommunicationTokenRepository{db: db}
}

// Insert implements the repository contract.
func (r *PgxAgentCommunicationTokenRepository) Insert(ctx context.Context, t *domain.AgentCommunicationToken) error {
	if t == nil || t.JTI == "" {
		return errors.New("postgres: AgentCommunicationToken.Insert requires a jti")
	}
	if t.ExpiresAt.IsZero() {
		return errors.New("postgres: AgentCommunicationToken.Insert requires a non-zero expires_at")
	}
	_, err := r.db.Exec(ctx, `
		INSERT INTO agent_communication_tokens (jti, authorization_id, aci, expires_at, issued_at)
		VALUES ($1, $2, $3, $4, $5)`,
		t.JTI, t.AuthorizationID, t.ACI, t.ExpiresAt, t.IssuedAt)
	if err != nil {
		return fmt.Errorf("postgres: insert agent_communication_tokens: %w", err)
	}
	return nil
}

// ListActiveByAuthorization implements the repository contract.
func (r *PgxAgentCommunicationTokenRepository) ListActiveByAuthorization(ctx context.Context, authorizationID uuid.UUID, now time.Time) ([]domain.AgentCommunicationToken, error) {
	rows, err := r.db.Query(ctx, `
		SELECT jti, authorization_id, aci, expires_at, issued_at
		FROM agent_communication_tokens
		WHERE authorization_id = $1 AND expires_at > $2
		ORDER BY issued_at`, authorizationID, now)
	if err != nil {
		return nil, fmt.Errorf("postgres: list agent_communication_tokens: %w", err)
	}
	defer rows.Close()
	var out []domain.AgentCommunicationToken
	for rows.Next() {
		var t domain.AgentCommunicationToken
		if err := rows.Scan(&t.JTI, &t.AuthorizationID, &t.ACI, &t.ExpiresAt, &t.IssuedAt); err != nil {
			return nil, fmt.Errorf("postgres: scan agent_communication_tokens: %w", err)
		}
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate agent_communication_tokens: %w", err)
	}
	return out, nil
}

// DeleteExpiredBefore implements the repository contract.
func (r *PgxAgentCommunicationTokenRepository) DeleteExpiredBefore(ctx context.Context, cutoff time.Time) (int64, error) {
	tag, err := r.db.Exec(ctx, `DELETE FROM agent_communication_tokens WHERE expires_at < $1`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("postgres: delete expired agent_communication_tokens: %w", err)
	}
	return tag.RowsAffected(), nil
}
