package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/repository"
)

// PgxAgentCommunicationAuthorizationRepository is the pgx implementation
// of repository.AgentCommunicationAuthorizationRepository over the two
// tables of migration 0037.
type PgxAgentCommunicationAuthorizationRepository struct {
	db DBTX
}

var _ repository.AgentCommunicationAuthorizationRepository = (*PgxAgentCommunicationAuthorizationRepository)(nil)

// NewPgxAgentCommunicationAuthorizationRepository constructs the repository.
func NewPgxAgentCommunicationAuthorizationRepository(db DBTX) *PgxAgentCommunicationAuthorizationRepository {
	return &PgxAgentCommunicationAuthorizationRepository{db: db}
}

const agentCommunicationAuthorizationColumns = `
	id, organization_id, owner_user_id, session_id, relay_audience,
	max_messages, max_message_size_bytes, expires_at, created_at,
	revoked_at, revoked_by, revocation_reason, policy_version, policy_digest`

const agentCommunicationParticipantColumns = `
	id, authorization_id, aci, service_account_id, oauth_client_id, role,
	proof_key_thumbprint, capabilities, created_at`

// Create inserts the authorization and its two participants in one
// transaction. The deferred constraint trigger of migration 0037 counts the
// participant rows at COMMIT, so a partial write can never land.
func (r *PgxAgentCommunicationAuthorizationRepository) Create(ctx context.Context, a *domain.AgentCommunicationAuthorization) error {
	if a == nil {
		return fmt.Errorf("agent communication authorization: nil aggregate")
	}
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // rollback on any non-commit path

	_, err = tx.Exec(ctx, `
		INSERT INTO agent_communication_authorizations (`+agentCommunicationAuthorizationColumns+`)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`,
		a.ID, a.OrganizationID, a.OwnerID, a.SessionID, a.RelayAudience,
		a.MaxMessages, a.MaxMessageSizeBytes, a.ExpiresAt, a.CreatedAt,
		a.RevokedAt, a.RevokedBy, a.RevocationReason, a.PolicyVersion, a.PolicyDigest,
	)
	if err != nil {
		return fmt.Errorf("failed to insert agent communication authorization: %w", err)
	}
	for i := range a.Participants {
		p := &a.Participants[i]
		caps := make([]string, 0, len(p.Capabilities))
		for _, c := range p.Capabilities {
			caps = append(caps, string(c))
		}
		_, err = tx.Exec(ctx, `
			INSERT INTO agent_communication_participants (`+agentCommunicationParticipantColumns+`)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
			p.ID, p.AuthorizationID, p.ACI, p.ServiceAccountID, p.OAuthClientID, string(p.Role),
			p.ProofKeyThumbprint, caps, p.CreatedAt,
		)
		if err != nil {
			return fmt.Errorf("failed to insert agent communication participant: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("failed to commit agent communication authorization: %w", err)
	}
	return nil
}

func scanAgentCommunicationAuthorization(row pgx.Row) (*domain.AgentCommunicationAuthorization, error) {
	var a domain.AgentCommunicationAuthorization
	err := row.Scan(
		&a.ID, &a.OrganizationID, &a.OwnerID, &a.SessionID, &a.RelayAudience,
		&a.MaxMessages, &a.MaxMessageSizeBytes, &a.ExpiresAt, &a.CreatedAt,
		&a.RevokedAt, &a.RevokedBy, &a.RevocationReason, &a.PolicyVersion, &a.PolicyDigest,
	)
	if err != nil {
		return nil, err
	}
	return &a, nil
}

func (r *PgxAgentCommunicationAuthorizationRepository) loadParticipants(ctx context.Context, ids []uuid.UUID) (map[uuid.UUID][]domain.AgentCommunicationParticipant, error) {
	out := make(map[uuid.UUID][]domain.AgentCommunicationParticipant, len(ids))
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := r.db.Query(ctx, `
		SELECT `+agentCommunicationParticipantColumns+`
		FROM agent_communication_participants
		WHERE authorization_id = ANY($1)
		ORDER BY authorization_id, role`, ids)
	if err != nil {
		return nil, fmt.Errorf("failed to query agent communication participants: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var p domain.AgentCommunicationParticipant
		var role string
		var caps []string
		if err := rows.Scan(&p.ID, &p.AuthorizationID, &p.ACI, &p.ServiceAccountID, &p.OAuthClientID, &role,
			&p.ProofKeyThumbprint, &caps, &p.CreatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan agent communication participant: %w", err)
		}
		p.Role = domain.AgentCommunicationParticipantRole(role)
		p.Capabilities = make([]domain.AgentCommunicationCapability, 0, len(caps))
		for _, c := range caps {
			p.Capabilities = append(p.Capabilities, domain.AgentCommunicationCapability(c))
		}
		out[p.AuthorizationID] = append(out[p.AuthorizationID], p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate agent communication participants: %w", err)
	}
	return out, nil
}

// GetByID implements the repository contract.
func (r *PgxAgentCommunicationAuthorizationRepository) GetByID(ctx context.Context, organizationID, id uuid.UUID) (*domain.AgentCommunicationAuthorization, error) {
	a, err := scanAgentCommunicationAuthorization(r.db.QueryRow(ctx, `
		SELECT `+agentCommunicationAuthorizationColumns+`
		FROM agent_communication_authorizations
		WHERE id = $1 AND organization_id = $2`, id, organizationID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrAgentCommunicationAuthorizationNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get agent communication authorization: %w", err)
	}
	parts, err := r.loadParticipants(ctx, []uuid.UUID{a.ID})
	if err != nil {
		return nil, err
	}
	a.Participants = parts[a.ID]
	return a, nil
}

// ListByOrganization implements the repository contract.
func (r *PgxAgentCommunicationAuthorizationRepository) ListByOrganization(ctx context.Context, organizationID uuid.UUID) ([]*domain.AgentCommunicationAuthorization, error) {
	rows, err := r.db.Query(ctx, `
		SELECT `+agentCommunicationAuthorizationColumns+`
		FROM agent_communication_authorizations
		WHERE organization_id = $1
		ORDER BY created_at DESC, id DESC`, organizationID)
	if err != nil {
		return nil, fmt.Errorf("failed to list agent communication authorizations: %w", err)
	}
	defer rows.Close()
	var out []*domain.AgentCommunicationAuthorization
	var ids []uuid.UUID
	for rows.Next() {
		a, err := scanAgentCommunicationAuthorization(rows)
		if err != nil {
			return nil, fmt.Errorf("failed to scan agent communication authorization: %w", err)
		}
		out = append(out, a)
		ids = append(ids, a.ID)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate agent communication authorizations: %w", err)
	}
	parts, err := r.loadParticipants(ctx, ids)
	if err != nil {
		return nil, err
	}
	for _, a := range out {
		a.Participants = parts[a.ID]
	}
	return out, nil
}

// Revoke implements the repository contract: the first stamp wins, a
// later call is a no-op reported as false.
func (r *PgxAgentCommunicationAuthorizationRepository) Revoke(ctx context.Context, organizationID, id, revokedBy uuid.UUID, reason *string, at time.Time) (bool, error) {
	tag, err := r.db.Exec(ctx, `
		UPDATE agent_communication_authorizations
		SET revoked_at = $3, revoked_by = $4, revocation_reason = $5
		WHERE id = $1 AND organization_id = $2 AND revoked_at IS NULL`,
		id, organizationID, at, revokedBy, reason)
	if err != nil {
		return false, fmt.Errorf("failed to revoke agent communication authorization: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}
