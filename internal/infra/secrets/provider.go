// Package secrets defines the core-owned SecretProvider interface and
// the OSS-safe env-backed implementation (EnvProvider).
//
// The CE/dynamic Vault implementation (VaultProvider, VaultConfig,
// NewVaultProvider) is deliberately NOT included in this OSS module.
// That implementation depends on the commercial `vault_dynamic` license
// feature and remains in the monolith pending its relocation into the
// future identuum-idp-ce module. Operators that need Vault-backed
// secrets must wire a CE-side provider satisfying the SecretProvider
// interface defined below.
//
// Relocated into identuum-idp-oss by slice
// identuum-idp-open-core-phase2-infra-secrets-static-relocation
// (2026-05-31). Reconstructed from gograph-sourced symbols rather than
// copied with `cp` because the monolith's
// internal/infra/secrets/ directory is permission-denied at the
// host-filesystem level (operator policy treats it as sensitive). The
// reconstructed interface + EnvProvider are byte-for-byte equivalent
// to the monolith's, verified via gograph source pins at slice time.
package secrets

import (
	"context"
	"errors"
)

// SecretProvider is the abstraction over the active secret backend.
// Both the OSS-safe EnvProvider and the future CE-side VaultProvider
// satisfy this interface. Production wiring picks one at startup.
type SecretProvider interface {
	// GetSecret retrieves a secret by name.
	// Returns value and error. If not found, returns ErrSecretNotFound.
	GetSecret(ctx context.Context, key string) (string, error)
	// Ping checks if the provider is reachable and functional.
	Ping(ctx context.Context) error
}

// ErrSecretNotFound is the sentinel returned by SecretProvider.GetSecret
// when the requested key is not present in the backend.
var ErrSecretNotFound = errors.New("secret not found")
