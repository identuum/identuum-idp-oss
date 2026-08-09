package startup

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/identuum/identuum-idp-oss/internal/infra/secrets"
)

// fakeSecretProvider is a per-key result map. Ping() is always OK — only
// GetSecret behaviour is exercised by the ResolveSecretsOrFail tests.
type fakeSecretProvider struct {
	responses map[string]fakeSecretResponse
}

type fakeSecretResponse struct {
	value string
	err   error
}

func (f *fakeSecretProvider) GetSecret(_ context.Context, key string) (string, error) {
	r, ok := f.responses[key]
	if !ok {
		// Unconfigured key → treat as not-found so tests that pin only the
		// critical-key response don't have to enumerate every optional key.
		return "", secrets.ErrSecretNotFound
	}
	return r.value, r.err
}

func (f *fakeSecretProvider) Ping(_ context.Context) error { return nil }

// §7.3 F3 — the No-Autogenerate gate MUST refuse startup when the critical
// key (AUTH_SERVICE_ENCRYPTION_KEY) is absent from the configured provider.
// The error message MUST name the key and the secret source so operators
// can diagnose provider-side misconfiguration.
func TestResolveSecretsOrFail_MissingCriticalKey_Refuses(t *testing.T) {
	provider := &fakeSecretProvider{
		responses: map[string]fakeSecretResponse{
			criticalSecretKey: {err: secrets.ErrSecretNotFound},
		},
	}
	warnCalls := 0
	_, err := ResolveSecretsOrFail(context.Background(), provider, "vault",
		func(string) {},
		func(string) { warnCalls++ },
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "CRITICAL")
	assert.Contains(t, err.Error(), criticalSecretKey)
	assert.Contains(t, err.Error(), "vault",
		"error MUST name the configured secret source so operators can diagnose provider misconfiguration")
	assert.Equal(t, 0, warnCalls, "warn must not fire when the critical-key read fails — the error is surfaced via the return value")
}

// §7.3 F3 — a transport error on the critical-key read is DISTINCT from not-
// found and must propagate as a wrapped error (not a CRITICAL message).
// This lets operators distinguish "provider online but key absent" from
// "provider offline / network failure".
func TestResolveSecretsOrFail_CriticalKeyTransportError_Propagates(t *testing.T) {
	transportErr := errors.New("dial tcp: connection refused")
	provider := &fakeSecretProvider{
		responses: map[string]fakeSecretResponse{
			criticalSecretKey: {err: transportErr},
		},
	}
	_, err := ResolveSecretsOrFail(context.Background(), provider, "vault", nil, nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, transportErr),
		"transport error must be wrapped, not swallowed or translated to a not-found message")
	assert.NotContains(t, err.Error(), "CRITICAL",
		"transport failures must NOT reuse the not-found CRITICAL phrasing")
}

// §7.3 F3 — optional keys are best-effort: a not-found response on every
// optional key must not abort startup, and the returned map contains ONLY
// the critical key.
func TestResolveSecretsOrFail_OptionalKeysMissing_Tolerated(t *testing.T) {
	provider := &fakeSecretProvider{
		responses: map[string]fakeSecretResponse{
			criticalSecretKey: {value: "hex64-key-value"},
			// every optional key absent (fakeSecretProvider returns
			// ErrSecretNotFound for unconfigured keys)
		},
	}
	infoCalls := 0
	warnCalls := 0
	resolved, err := ResolveSecretsOrFail(context.Background(), provider, "env",
		func(string) { infoCalls++ },
		func(string) { warnCalls++ },
	)
	require.NoError(t, err)
	assert.Len(t, resolved, 1, "only the critical key should be present when every optional is not-found")
	assert.Equal(t, "hex64-key-value", resolved[criticalSecretKey])
	assert.Equal(t, 0, infoCalls, "info must only fire for successful optional overrides")
	assert.Equal(t, 0, warnCalls, "warn must not fire on ErrSecretNotFound for optional keys — that is the expected case")
}

// §7.3 F3 — a transport error on an optional key must be surfaced via the
// warn callback but must NOT abort startup or contaminate the resolved map.
func TestResolveSecretsOrFail_OptionalKeyTransportError_Warns(t *testing.T) {
	provider := &fakeSecretProvider{
		responses: map[string]fakeSecretResponse{
			criticalSecretKey: {value: "hex64-key-value"},
			// Inject a transport error on one optional key (IDENTUUM_IDP_* prefix);
			// leave the others unset so they fall through to ErrSecretNotFound.
			"IDENTUUM_IDP_DATABASE_PASSWORD": {err: errors.New("vault lease expired")},
		},
	}
	warnMsgs := []string{}
	resolved, err := ResolveSecretsOrFail(context.Background(), provider, "vault",
		func(string) {},
		func(msg string) { warnMsgs = append(warnMsgs, msg) },
	)
	require.NoError(t, err, "a transport error on an optional key must not abort startup")
	assert.Len(t, resolved, 1, "only the critical key should be present; the failing optional must be omitted")
	assert.Equal(t, "hex64-key-value", resolved[criticalSecretKey])
	require.Len(t, warnMsgs, 1, "warn must fire exactly once — for the single transport error")
	assert.True(t,
		strings.Contains(warnMsgs[0], "IDENTUUM_IDP_DATABASE_PASSWORD") &&
			strings.Contains(warnMsgs[0], "vault lease expired"),
		"warn message must name the optional key and the underlying error so operators can debug; got %q", warnMsgs[0])
}

// §7.3 F3 — successful optional overrides must be folded into the resolved
// map and announced via the info callback. Multiple successes accumulate.
func TestResolveSecretsOrFail_OptionalKeysSuccess_FoldedIntoMap(t *testing.T) {
	provider := &fakeSecretProvider{
		responses: map[string]fakeSecretResponse{
			criticalSecretKey:            {value: "hex64"},
			"IDENTUUM_IDP_DATABASE_USER": {value: "dbuser"},
			"IDENTUUM_IDP_SMTP_PASSWORD": {value: "smtppass"},
		},
	}
	infoMsgs := []string{}
	resolved, err := ResolveSecretsOrFail(context.Background(), provider, "vault",
		func(msg string) { infoMsgs = append(infoMsgs, msg) },
		func(string) {},
	)
	require.NoError(t, err)
	assert.Equal(t, "hex64", resolved[criticalSecretKey])
	assert.Equal(t, "dbuser", resolved["IDENTUUM_IDP_DATABASE_USER"])
	assert.Equal(t, "smtppass", resolved["IDENTUUM_IDP_SMTP_PASSWORD"])
	assert.Len(t, resolved, 3, "only the critical key + two successful optional overrides must appear")
	assert.Len(t, infoMsgs, 2, "info must fire once per successful optional override")
}
