package secrets

import (
	"context"
	"os"
)

// EnvProvider is the OSS-safe SecretProvider that resolves secrets
// from process environment variables. It has no external dependencies
// beyond stdlib and is the default provider for the Starter tier and
// for any deployment that does not have the `vault_dynamic` license
// feature.
type EnvProvider struct{}

// NewEnvProvider constructs a ready-to-use EnvProvider. The struct
// has no state; the constructor exists for symmetry with future
// commercial providers.
func NewEnvProvider() *EnvProvider {
	return &EnvProvider{}
}

// GetSecret reads `key` from the process environment. Returns
// ErrSecretNotFound if the variable is not set.
func (p *EnvProvider) GetSecret(_ context.Context, key string) (string, error) {
	val, ok := os.LookupEnv(key)
	if !ok {
		return "", ErrSecretNotFound
	}
	return val, nil
}

// Ping always succeeds: the process environment is always reachable.
func (p *EnvProvider) Ping(_ context.Context) error {
	return nil // Environment is always reachable
}
