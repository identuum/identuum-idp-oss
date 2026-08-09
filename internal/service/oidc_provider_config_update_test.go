package service

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// (a) SECRET-PRESERVE / (b) SECRET-ROTATE — Update without a new client_secret
// preserves the stored ciphertext (still decrypts to the original); Update with
// a new client_secret re-encrypts it (ciphertext changes, decrypts to the new
// value, plaintext never persisted).
func TestOIDCProviderConfig_UpdatePreservesSecretUnlessRotated(t *testing.T) {
	svc, _ := newOIDCConfigTestService(t)
	org := uuid.New()

	in := validOIDCProviderInput(org)
	origSecret := in.ClientSecret
	require.NotEmpty(t, origSecret)

	created, err := svc.CreateOIDCProvider(context.Background(), in)
	require.NoError(t, err)
	ct1 := created.Config.ClientSecretEncrypted
	require.NotEmpty(t, ct1)
	require.NotEqual(t, origSecret, ct1, "stored value must be ciphertext, not plaintext")

	// (a) PRESERVE — update other fields WITHOUT supplying a new secret.
	preserveIn := validOIDCProviderInput(org)
	preserveIn.ClientSecret = "" // no new secret
	preserveIn.Name = "Renamed Provider"
	updated, err := svc.UpdateOIDCProvider(context.Background(), org, preserveIn)
	require.NoError(t, err)
	require.Equal(t, ct1, updated.Config.ClientSecretEncrypted,
		"secret ciphertext must be preserved unchanged when no new secret is supplied")
	require.NotEmpty(t, updated.Config.ClientSecretEncrypted, "secret must not be blanked on update")
	plain, err := svc.DecryptClientSecret(updated)
	require.NoError(t, err)
	require.Equal(t, origSecret, plain, "preserved secret must still decrypt to the original value")
	require.Equal(t, "Renamed Provider", updated.Name, "non-secret fields must be updated")

	// (b) ROTATE — update WITH a new secret.
	rotateIn := validOIDCProviderInput(org)
	rotateIn.ClientSecret = "rotated-new-secret-value"
	rotated, err := svc.UpdateOIDCProvider(context.Background(), org, rotateIn)
	require.NoError(t, err)
	require.NotEqual(t, ct1, rotated.Config.ClientSecretEncrypted,
		"secret ciphertext must change when a new secret is supplied")
	require.NotContains(t, rotated.Config.ClientSecretEncrypted, "rotated-new-secret-value",
		"the new plaintext secret must never be persisted")
	plain2, err := svc.DecryptClientSecret(rotated)
	require.NoError(t, err)
	require.Equal(t, "rotated-new-secret-value", plain2, "rotated secret must decrypt to the new value")
}

// (c) INVARIANTS-ON-UPDATE — type=oidc stays enforced, the one-per-org
// invariant is not violated by update, and updating an org with no provider is
// a clean not-found.
func TestOIDCProviderConfig_UpdateInvariants(t *testing.T) {
	svc, repo := newOIDCConfigTestService(t)
	org := uuid.New()

	_, err := svc.CreateOIDCProvider(context.Background(), validOIDCProviderInput(org))
	require.NoError(t, err)

	// type=oidc enforced on update: ldap/ad are refused (CE).
	for _, typ := range []domain.IdentityProviderType{domain.IDPTypeLDAP, domain.IDPTypeAD} {
		bad := validOIDCProviderInput(org)
		bad.Type = typ
		_, err := svc.UpdateOIDCProvider(context.Background(), org, bad)
		require.ErrorIsf(t, err, ErrUnsupportedProviderType(), "update with type %q must be refused", typ)
	}

	// A successful update must NOT create a second provider (one-per-org).
	good := validOIDCProviderInput(org)
	good.Name = "Updated Name"
	_, err = svc.UpdateOIDCProvider(context.Background(), org, good)
	require.NoError(t, err)
	oidcCount := 0
	for _, p := range repo.byID {
		if p.OrganizationID == org && p.Type == domain.IDPTypeOIDC {
			oidcCount++
		}
	}
	require.Equal(t, 1, oidcCount, "update must leave exactly one oidc provider for the org (one-per-org)")

	// Updating an org that has no configured provider is a clean not-found.
	_, err = svc.UpdateOIDCProvider(context.Background(), uuid.New(), validOIDCProviderInput(org))
	require.ErrorIs(t, err, ErrOIDCProviderNotFound())
}
