package repository

import (
	"context"

	"github.com/google/uuid"
)

// SessionRelyingPartyRepository records which relying parties hold an ID token
// for a session (migration 0047), so that ending the session can notify every
// one of them that registered a back-channel logout endpoint.
type SessionRelyingPartyRepository interface {
	// Record notes that clientID was issued an ID token for the session. It is
	// idempotent: a pair already recorded is left as it is.
	Record(ctx context.Context, sessionID uuid.UUID, clientID string) error
	// ClientIDs returns the public client_ids recorded for the session, in a
	// stable order. An unknown or empty session yields none.
	ClientIDs(ctx context.Context, sessionID uuid.UUID) ([]string, error)
}
