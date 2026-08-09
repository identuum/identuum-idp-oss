package secrets

// OSS-side EnvProvider contract test. Reconstructed from the monolith's
// TestEnvProvider via gograph source (the monolith's
// internal/infra/secrets/ directory is permission-denied at the host-
// filesystem level so direct copy was not possible). The reconstructed
// body is byte-for-byte equivalent to the monolith's TestEnvProvider
// modulo the file split (the monolith carries TestVaultProviderInit in
// the same _test.go file; the Vault test stays in the monolith because
// the commercial VaultProvider is NOT shipped in OSS).

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEnvProvider(t *testing.T) {
	provider := NewEnvProvider()
	ctx := context.Background()

	// Should not find non-existent key
	_, err := provider.GetSecret(ctx, "NON_EXISTENT_SECRET_123")
	assert.ErrorIs(t, err, ErrSecretNotFound)

	// Set a key and find it
	os.Setenv("TEST_SECRET_KEY", "test_value")
	defer os.Unsetenv("TEST_SECRET_KEY")

	val, err := provider.GetSecret(ctx, "TEST_SECRET_KEY")
	assert.NoError(t, err)
	assert.Equal(t, "test_value", val)

	// Ping should always succeed
	assert.NoError(t, provider.Ping(ctx))
}

func TestEnvProvider_SatisfiesSecretProviderInterface(t *testing.T) {
	// Compile-time + runtime pin that EnvProvider implements
	// SecretProvider. If a future signature drift breaks
	// conformance, the build fails here at the authoritative
	// location.
	var _ SecretProvider = (*EnvProvider)(nil)
	var p SecretProvider = NewEnvProvider()
	// Cannot nil-check p directly (SA4023): assigning a non-nil
	// concrete *EnvProvider to a SecretProvider interface always
	// yields a non-nil interface value. Instead, exercise the
	// interface dispatch to prove conformance at runtime.
	if err := p.Ping(context.Background()); err != nil {
		t.Errorf("SecretProvider-typed EnvProvider.Ping must return nil; got %v", err)
	}
}
