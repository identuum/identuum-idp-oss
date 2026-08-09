package secrets

import (
	"context"
	"errors"
)

// VaultProvider in OSS is a compile-time placeholder for the commercial
// Vault-backed SecretProvider. The real implementation lives in the
// monolith's `internal/infra/secrets/vault_provider.go` and will move
// to identuum-idp-ce in a future slice.
//
// This stub exists so that callers that reference the type name (e.g.
// `internal/startup/provider_resolution.go::ResolveSecretProvider`) can
// compile against the OSS module. The stub satisfies the SecretProvider
// interface but every method returns ErrVaultProviderNotAvailable so a
// caller that accidentally reaches the stub at runtime fails closed
// with a clear, actionable error.
//
// Runtime reachability: in OSS-only builds, ResolveSecretProvider's
// featureChecker callback always denies the `vault_static` feature
// (no commercial license is loaded), so the early-return at line 38
// of provider_resolution.go fires BEFORE NewVaultProvider is ever
// called. The stub is therefore dead code at runtime in pure OSS
// deployments; it exists only to satisfy the Go compiler.
//
// Reconstructed in OSS by slice
// identuum-idp-open-core-phase2-startup-mw-relocation (2026-05-31).
// SECURITY: this stub holds no Vault address, token, or other
// credential. It is safe to ship in any artefact.
//
// Drift discipline: if the monolith's commercial VaultProvider gains
// a new method on the SecretProvider interface, this stub MUST be
// updated to add a matching method (returning the sentinel error) so
// compile-time conformance holds.
type VaultProvider struct{}

// ErrVaultProviderNotAvailable is returned by every VaultProvider
// method in the OSS module. It signals that the caller has reached a
// commercial-only code path that is not wired in this build.
var ErrVaultProviderNotAvailable = errors.New(
	"identuum-idp-oss/internal/infra/secrets: VaultProvider is a commercial-only " +
		"implementation; this OSS build does not ship it — wire a CE binary or " +
		"supply a custom SecretProvider implementation")

// NewVaultProvider always returns ErrVaultProviderNotAvailable in OSS.
// The signature matches the monolith's commercial constructor exactly
// so callers compile unchanged; the runtime behavior differs (fails
// closed instead of returning a working Vault client).
func NewVaultProvider(cfg VaultConfig) (*VaultProvider, error) {
	// Silence the unused parameter; the OSS stub deliberately ignores cfg.
	_ = cfg
	return nil, ErrVaultProviderNotAvailable
}

// GetSecret on the OSS VaultProvider stub always fails closed.
func (p *VaultProvider) GetSecret(_ context.Context, _ string) (string, error) {
	return "", ErrVaultProviderNotAvailable
}

// Ping on the OSS VaultProvider stub always fails closed.
func (p *VaultProvider) Ping(_ context.Context) error {
	return ErrVaultProviderNotAvailable
}

// Compile-time assertion that the OSS VaultProvider stub satisfies
// the SecretProvider interface, mirroring the monolith's commercial
// implementation. If the interface shape drifts, the build fails
// here.
var _ SecretProvider = (*VaultProvider)(nil)
