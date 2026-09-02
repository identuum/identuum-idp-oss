package domain

// auth_store_error.go — THE-SESSION-REJECTION-ROOT-CAUSE (2026-09-02), AUTH-503.
//
// On the authentication path a STORE / INFRASTRUCTURE failure (the
// database, the signing-key store, the revocation store, the session
// cache) is NOT an authentication verdict. Before this slice every
// consumer collapsed `err != nil` into the same unlogged 401 a bad token
// gets, so a transient database stall under load presented as "your
// session is dead" — measured twice in the harness (a seconds-old
// site_admin session bounced to /login while the SAME cookie jar
// validated 200 on the next call).
//
// The repositories already separate the two: a missing row arrives as
// ErrSessionNotFound / ErrUserNotFound / ErrClientNotFound (a VERDICT),
// anything else is infrastructure. This sentinel names the second class
// so every consumer can answer 503 + an ERROR log with a correlation id
// (see internal/mw.RespondAuthStoreUnavailable) and keep 401 for genuine
// verdicts: absent, invalid, expired, revoked, mismatched, not live.

import (
	"errors"
	"fmt"
)

// ErrAuthStoreUnavailable marks an auth-path store / infrastructure error.
// Wrap with AuthStoreUnavailable; test with errors.Is.
var ErrAuthStoreUnavailable = errors.New("auth store unavailable")

// ErrUserOrganizationNotFound is the VERDICT of the user→organization
// join lookup (no row: the user is banned / unknown or the organization is
// inactive) — distinct from a store error on the same query.
var ErrUserOrganizationNotFound = errors.New("organization not found for user")

// AuthStoreUnavailable wraps a store error for the auth path. `where`
// names the lookup (secret-free: "signing-keys", "session", "user",
// "revocation", "client"); err keeps the driver detail for the log line,
// which is the only place it is ever written.
func AuthStoreUnavailable(where string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%w: %s: %w", ErrAuthStoreUnavailable, where, err)
}

// IsAuthStoreUnavailable reports whether err is (or wraps) the store
// class — the branch that must answer 503, never 401.
func IsAuthStoreUnavailable(err error) bool {
	return err != nil && errors.Is(err, ErrAuthStoreUnavailable)
}
