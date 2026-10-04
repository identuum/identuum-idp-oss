package postgres

import (
	"context"
	"fmt"

	"github.com/google/uuid"
)

// PgxSessionRelyingPartyRepository stores session_relying_parties (migration 0047).
type PgxSessionRelyingPartyRepository struct {
	db DBTX
}

// NewPgxSessionRelyingPartyRepository wires the store to a connection or pool.
func NewPgxSessionRelyingPartyRepository(db DBTX) *PgxSessionRelyingPartyRepository {
	return &PgxSessionRelyingPartyRepository{db: db}
}

// Record notes the pair once; a pair already there is left alone.
func (r *PgxSessionRelyingPartyRepository) Record(ctx context.Context, sessionID uuid.UUID, clientID string) error {
	const q = `
		INSERT INTO session_relying_parties (session_id, client_id)
		VALUES ($1, $2)
		ON CONFLICT (session_id, client_id) DO NOTHING`
	if _, err := r.db.Exec(ctx, q, sessionID, clientID); err != nil {
		return fmt.Errorf("failed to record session relying party: %w", err)
	}
	return nil
}

// ClientIDs returns the client_ids recorded for the session.
func (r *PgxSessionRelyingPartyRepository) ClientIDs(ctx context.Context, sessionID uuid.UUID) ([]string, error) {
	const q = `SELECT client_id FROM session_relying_parties WHERE session_id = $1 ORDER BY first_issued_at, client_id`
	rows, err := r.db.Query(ctx, q, sessionID)
	if err != nil {
		return nil, fmt.Errorf("failed to list session relying parties: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("failed to scan session relying party: %w", err)
		}
		out = append(out, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("row iteration failed: %w", err)
	}
	return out, nil
}
