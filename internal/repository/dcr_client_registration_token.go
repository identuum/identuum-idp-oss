package repository

import (
	"context"
	"errors"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// ErrDCRClientRegistrationTokenNotFound is the sentinel returned
// when a lookup hits no row. The handler maps it to an opaque
// 401 invalid_token envelope so a probing caller cannot
// distinguish "no such client" from "wrong RAT".
var ErrDCRClientRegistrationTokenNotFound = errors.New("repository: dcr client registration token not found")

// DCRClientRegistrationTokenRepository persists per-client
// RFC 7592 registration access token rows. One row per client.
//
// Upsert is the load-bearing operation: DCR /register inserts a
// fresh row at issuance time, and rotation is implemented as
// Upsert with a new hash (replaces UpdatedAt). DELETE is
// idempotent and handled via the ON DELETE CASCADE on the
// underlying oauth_clients.id, but an explicit DeleteByClientID
// is also provided for the RFC 7592 DELETE management call.
//
// LookupByClientIDAndHash is the read-side authentication
// primitive: it returns the row when (client_id, hash) matches,
// and ErrDCRClientRegistrationTokenNotFound otherwise. The
// returned row's TokenHash is scrubbed on read.
type DCRClientRegistrationTokenRepository interface {
	// Upsert inserts (or replaces) the RAT row for clientID.
	// tokenHash is required. Returns the persisted row.
	Upsert(ctx context.Context, clientID uuid.UUID, tokenHash string) (*domain.DCRClientRegistrationToken, error)

	// GetByClientID returns the row identified by clientID with
	// TokenHash scrubbed. Used by the management surface to
	// confirm a client is RFC 7592-manageable.
	GetByClientID(ctx context.Context, clientID uuid.UUID) (*domain.DCRClientRegistrationToken, error)

	// LookupByClientIDAndHash is the constant-time authentication
	// primitive. Returns the row when (clientID, tokenHash) both
	// match, ErrDCRClientRegistrationTokenNotFound otherwise.
	// TokenHash is scrubbed on return.
	LookupByClientIDAndHash(ctx context.Context, clientID uuid.UUID, tokenHash string) (*domain.DCRClientRegistrationToken, error)

	// DeleteByClientID removes the RAT row for clientID.
	// Idempotent: a no-op when the row is absent.
	DeleteByClientID(ctx context.Context, clientID uuid.UUID) error
}
