package startup

import (
	"context"
	"errors"
	"fmt"

	"github.com/identuum/identuum-idp-oss/internal/infra/secrets"
)

// criticalSecretKey is the load-bearing secret that §7.3's "No Autogenerate"
// policy refuses to synthesize. If the resolved provider returns
// ErrSecretNotFound for this key, the service refuses to start — callers
// MUST NOT fall through to a locally-generated default.
// #nosec G101 - False positive: this is the NAME of an env var / Vault key, not a credential value.
const criticalSecretKey = "AUTH_SERVICE_ENCRYPTION_KEY"

// optionalSecretKeys is the best-effort override set. Each key is read in turn
// and folded into the returned map on success. A not-found response is silent
// (expected when the secret is supplied via env var or left unconfigured); a
// transport-level error is routed to the warn callback but does not abort
// startup.
//
// IDENTUUM_IDP_* is the preferred prefix. InjectSecrets accepts both
// IDENTUUM_IDP_* and the legacy AUTH_SERVICE_* forms for backward
// compatibility with Vault deployments that store secrets under the old names.
var optionalSecretKeys = []string{
	"IDENTUUM_IDP_DATABASE_USER",
	"IDENTUUM_IDP_DATABASE_PASSWORD",
	"IDENTUUM_IDP_REDIS_PASSWORD",
	"IDENTUUM_IDP_SMTP_USERNAME",
	"IDENTUUM_IDP_SMTP_PASSWORD",
}

// ResolveSecretsOrFail reads the load-bearing secret set from the provider
// and returns the collected values. Contract:
//
//   - criticalSecretKey (AUTH_SERVICE_ENCRYPTION_KEY) is MANDATORY: a
//     `secrets.ErrSecretNotFound` response aborts startup with a CRITICAL
//     error whose message names the key and the configured secret source.
//     Any other error on the critical-key read aborts startup with a
//     wrapped transport error. For the ENV provider, the compat layer
//     ensures AUTH_SERVICE_ENCRYPTION_KEY is set from IDENTUUM_IDP_ENCRYPTION_KEY.
//   - optionalSecretKeys are BEST-EFFORT: a not-found response is silent;
//     a transport error is logged via the `warn` callback but does not
//     abort startup.
//
// Load-bearing invariant of §7.3: there is NO code path in which a missing
// critical key causes startup to proceed with a synthesized default. Tests
// against this helper pin the refusal contract.
//
// secretSource is surfaced only in the refusal-error message so operators
// see which provider was consulted when the critical key was missing.
//
// The info / warn callbacks mirror the `ResolveSecretProvider` injection
// pattern so this helper is unit-testable without reaching the package-level
// logger.
func ResolveSecretsOrFail(
	ctx context.Context,
	provider secrets.SecretProvider,
	secretSource string,
	info func(msg string),
	warn func(msg string),
) (map[string]string, error) {
	resolved := make(map[string]string, 1+len(optionalSecretKeys))

	val, err := provider.GetSecret(ctx, criticalSecretKey)
	if err != nil {
		if errors.Is(err, secrets.ErrSecretNotFound) {
			return nil, fmt.Errorf("CRITICAL: Encryption key (%s) not found in %s", criticalSecretKey, secretSource)
		}
		return nil, fmt.Errorf("secret retrieval error for %s: %w", criticalSecretKey, err)
	}
	resolved[criticalSecretKey] = val

	for _, key := range optionalSecretKeys {
		v, err := provider.GetSecret(ctx, key)
		if err == nil {
			resolved[key] = v
			if info != nil {
				info(fmt.Sprintf("Loaded secret override: %s", key))
			}
			continue
		}
		if errors.Is(err, secrets.ErrSecretNotFound) {
			continue
		}
		if warn != nil {
			warn(fmt.Sprintf("Failed to fetch optional secret %s: %v", key, err))
		}
	}

	return resolved, nil
}
