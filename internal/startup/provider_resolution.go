package startup

import (
	"github.com/identuum/identuum-idp-oss/internal/features"
	"github.com/identuum/identuum-idp-oss/internal/infra/secrets"
)

// ResolveSecretProvider determines and instantiates the correct SecretProvider
// based on the configured secret source and the license file's feature entitlements.
//
// When secretSource is "vault" and the StaticVault feature is licensed,
// a VaultProvider is returned. In all other cases (non-vault source, feature
// not licensed, or license check error) an EnvProvider is returned and the
// warn callback is invoked with a human-readable explanation.
//
// Vault connectivity (Ping) is intentionally NOT performed here — that concern
// belongs in the caller's resilient startup loop where a context.Context is
// available. ResolveSecretProvider is a pure resolution step.
//
// Parameters:
//   - secretSource:     value of AUTH_SERVICE_SECRET_SOURCE ("vault" | "env" | ...)
//   - licenseFile:      path to the license file, forwarded to featureChecker
//   - vaultCfg:         Vault connection parameters, used only when source is "vault"
//   - featureChecker:   injectable function — production callers pass license.CheckFeatureEnabled
//   - warn:             receives advisory messages that would otherwise go to the logger
func ResolveSecretProvider(
	secretSource string,
	licenseFile string,
	vaultCfg secrets.VaultConfig,
	featureChecker func(path, feature string) (bool, error),
	warn func(msg string),
) (secrets.SecretProvider, error) {
	if secretSource != "vault" {
		return secrets.NewEnvProvider(), nil
	}

	hasFeature, err := featureChecker(licenseFile, features.StaticVault)
	if err != nil || !hasFeature {
		warn("Vault integration requires the '" + features.StaticVault +
			"' license feature. Falling back to ENV.")
		return secrets.NewEnvProvider(), nil
	}

	vaultProvider, err := secrets.NewVaultProvider(vaultCfg)
	if err != nil {
		return nil, err
	}

	return vaultProvider, nil
}
