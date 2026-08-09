package repository

// webauthn_session_repository.go — narrow seam for the ephemeral
// WebAuthn ceremony session storage consumed by the OSS WebAuthn
// service. The interface mirrors the monolith's so the OSS service
// implementation stays a structural port — we never import monolith
// code. The default in-memory implementation lives in
// inmemory_webauthn_session_repository.go. CE wiring may later
// supply a Redis-backed implementation behind the same seam without
// touching the OSS handler or service surfaces.
//
// Ceremony sessions are short-lived (5 minutes per the upstream
// go-webauthn library's design) and single-use. Consume is the ATOMIC
// single-use read the finish paths use: a Get-then-Delete pair on the
// caller side is NOT atomic — two concurrent finishes for the same
// sessionID can both read the live entry before either deletes,
// enabling assertion replay (P2-11). Consume reads and removes the
// entry in ONE lock acquisition so exactly one concurrent finisher
// wins.

import (
	"context"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

// WebAuthnSessionRepository defines storage for ephemeral WebAuthn
// ceremony sessions. Implementations must enforce the supplied TTL
// (Save dropping the row on expiry is acceptable; Get returning an
// error for an expired row is required so the service treats
// expired challenges as invalid).
type WebAuthnSessionRepository interface {
	// Save stores the session data with a TTL. Overwriting an
	// existing key is allowed — the upstream go-webauthn API may
	// re-issue a session under the same id on retry.
	Save(ctx context.Context, key string, data *webauthn.SessionData, ttl time.Duration) error

	// Get retrieves the session data. Returns a non-nil error on
	// missing / expired entries so the caller can collapse both
	// failure modes onto the same opaque wire response.
	Get(ctx context.Context, key string) (*webauthn.SessionData, error)

	// Consume ATOMICALLY reads and removes the session data in a
	// SINGLE lock acquisition — the single-use primitive the finish
	// paths use. It returns the same missing / expired sentinels as
	// Get (so callers collapse both onto one opaque response), and on
	// a live entry it returns the data AND removes it, so two
	// concurrent finishes for the same key yield exactly one winner
	// (the loser gets the not-found sentinel). Idempotent for the
	// caller: a second Consume of a consumed key returns not-found.
	Consume(ctx context.Context, key string) (*webauthn.SessionData, error)

	// Delete removes the session data. Idempotent — deleting a
	// missing key MUST NOT return an error so handlers can fire
	// it from a defer without checking the prior Get outcome.
	Delete(ctx context.Context, key string) error
}
