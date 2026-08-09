package startup_test

import (
	"errors"
	"testing"

	"github.com/identuum/identuum-idp-oss/internal/infra/secrets"
	"github.com/identuum/identuum-idp-oss/internal/startup"
)

func TestResolveSecretProvider(t *testing.T) {
	t.Parallel()

	errChecker := errors.New("license check failed")

	tests := []struct {
		name           string
		secretSource   string
		featureChecker func(path, feature string) (bool, error)
		wantVault      bool // true → expect *secrets.VaultProvider, false → expect *secrets.EnvProvider
		wantWarning    bool
		wantErr        bool
	}{
		{
			name:         "env source always returns EnvProvider without calling checker",
			secretSource: "env",
			featureChecker: func(path, feature string) (bool, error) {
				t.Error("featureChecker must not be called for non-vault source")
				return false, nil
			},
			wantVault:   false,
			wantWarning: false,
		},
		{
			// OSS-side variant: when the featureChecker reports the
			// `vault_static` feature is licensed, ResolveSecretProvider
			// would normally construct a *secrets.VaultProvider. In OSS,
			// the VaultProvider type is a fail-closed stub (the
			// commercial implementation lives in the monolith / future
			// identuum-idp-ce). The OSS resolver therefore returns
			// ErrVaultProviderNotAvailable for this case. The monolith's
			// version of this test expects wantVault=true; the OSS
			// version expects wantErr=true. Documented divergence.
			name:         "vault source, feature licensed → OSS stub returns error",
			secretSource: "vault",
			featureChecker: func(path, feature string) (bool, error) {
				return true, nil
			},
			wantVault:   false,
			wantWarning: false,
			wantErr:     true,
		},
		{
			name:         "vault source, feature not licensed → EnvProvider with warning",
			secretSource: "vault",
			featureChecker: func(path, feature string) (bool, error) {
				return false, nil
			},
			wantVault:   false,
			wantWarning: true,
		},
		{
			name:         "vault source, checker returns error → EnvProvider with warning",
			secretSource: "vault",
			featureChecker: func(path, feature string) (bool, error) {
				return false, errChecker
			},
			wantVault:   false,
			wantWarning: true,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var warned bool
			warn := func(msg string) { warned = true }

			// Use a syntactically valid but unreachable Vault address.
			// NewVaultProvider only opens a network connection on Ping, not here.
			vaultCfg := secrets.VaultConfig{
				Address:    "http://127.0.0.1:18200",
				Token:      "test-token",
				MountPath:  "secret",
				SecretPath: "auth-service/config",
			}

			provider, err := startup.ResolveSecretProvider(
				tc.secretSource,
				"test-license.lic",
				vaultCfg,
				tc.featureChecker,
				warn,
			)

			if tc.wantErr {
				if err == nil {
					t.Fatal("expected an error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if provider == nil {
				t.Fatal("expected a non-nil SecretProvider")
			}

			_, isVault := provider.(*secrets.VaultProvider)
			if tc.wantVault && !isVault {
				t.Errorf("expected *secrets.VaultProvider, got %T", provider)
			}
			if !tc.wantVault && isVault {
				t.Errorf("expected *secrets.EnvProvider, got *secrets.VaultProvider")
			}

			if tc.wantWarning && !warned {
				t.Error("expected warn callback to be invoked, but it was not")
			}
			if !tc.wantWarning && warned {
				t.Error("expected no warning, but warn callback was invoked")
			}
		})
	}
}
