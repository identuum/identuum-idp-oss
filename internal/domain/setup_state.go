package domain

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

// Setup status values persisted in system_setup_state.status. Wire-format
// constants: do not rename without updating the migration's CHECK constraint
// and every reader (HTTP handlers, UI, tests).
const (
	// SetupStatusRequired means the IDP is freshly migrated and the
	// operator must complete first-run setup via the /api/setup/* surface
	// before normal product APIs become useful. The setup token file at
	// $DATA_DIR/setup-token.txt is the wizard's proof of authority.
	SetupStatusRequired = "setup_required"

	// SetupStatusComplete means first-run setup has succeeded: the first
	// organization, site_admin user, and EdDSA signing key exist; the
	// setup token file has been deleted; the DB hash has been cleared;
	// and /api/setup/verify-token + /api/setup/complete now fail-closed
	// with 410 Gone. GET /api/setup/status keeps returning the state so
	// operators and the UI can detect completion idempotently.
	SetupStatusComplete = "setup_complete"
)

// SetupStateSingletonID is the reserved UUIDv7-zero sentinel for the single
// row of system_setup_state. It sits alongside SystemOrgID (0x00) and
// SiteAdminID (0x01) in the bootstrap sentinel family: a UUIDv7 whose
// timestamp bits are all zero, picked so the value cannot collide with any
// genuinely generated UUIDv7 and is identifiably synthetic in logs and SQL.
//
// The migration's CHECK constraint pins every row to this exact value;
// the pre-seed INSERT makes it present on every installation from boot.
var SetupStateSingletonID = uuid.MustParse("00000000-0000-7000-0000-000000000010")

// ErrSetupStateNotFound is returned when the singleton row is absent —
// defensive only, since migration 0019 always seeds it.
var ErrSetupStateNotFound = errors.New("setup state row not found")

// SetupState is the in-memory shape of the singleton system_setup_state row.
//
// SetupTokenHash is the SHA-256 hex digest of the plaintext setup token;
// the plaintext itself lives only in the data-volume file and in startup
// logs while status == SetupStatusRequired. Hash is empty after completion.
type SetupState struct {
	ID                  uuid.UUID
	Status              string
	SetupTokenHash      string
	SetupTokenCreatedAt *time.Time
	CompletedAt         *time.Time
	UpdatedAt           time.Time
}

// IsComplete reports whether setup has finished. Convenience helper so
// handlers and the UI proxy don't have to compare status strings inline.
func (s *SetupState) IsComplete() bool {
	return s != nil && s.Status == SetupStatusComplete
}
