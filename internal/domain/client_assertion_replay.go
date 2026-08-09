package domain

import "time"

// ClientAssertionReplay is the persistent record of a single
// (client_id, jti_hash) pair seen on the private_key_jwt path.
// Storage NEVER carries the raw jti value — only its SHA-256
// hex digest. The repository's primary-key collision IS the
// replay signal: a no-op insert means the same client has
// already minted an assertion carrying the same jti within the
// row's expires_at window.
type ClientAssertionReplay struct {
	ClientID  string
	JTIHash   string
	ExpiresAt time.Time
	CreatedAt time.Time
}
