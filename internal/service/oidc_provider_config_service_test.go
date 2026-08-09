package service

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/lifecycle"
	"github.com/identuum/identuum-idp-oss/internal/repository"
	"github.com/identuum/identuum-idp-oss/internal/utils/uuidgen"
)

// fakeIDPConfigRepo is an in-memory IdentityProviderRepository standing in
// for the pgx repo. Its Create mints a UUIDv7 to mirror the production
// identity_providers DEFAULT uuidv7() column. Delete is hard, matching the
// real repo.
type fakeIDPConfigRepo struct {
	byID map[uuid.UUID]*domain.IdentityProvider
}

var _ repository.IdentityProviderRepository = (*fakeIDPConfigRepo)(nil)

func newFakeIDPConfigRepo() *fakeIDPConfigRepo {
	return &fakeIDPConfigRepo{byID: map[uuid.UUID]*domain.IdentityProvider{}}
}

func (f *fakeIDPConfigRepo) Create(_ context.Context, p *domain.IdentityProvider) (*domain.IdentityProvider, error) {
	id, err := uuidgen.NewV7()
	if err != nil {
		return nil, err
	}
	cp := *p
	cp.ID = id
	f.byID[id] = &cp
	out := cp
	return &out, nil
}

func (f *fakeIDPConfigRepo) GetByID(_ context.Context, id uuid.UUID) (*domain.IdentityProvider, error) {
	p, ok := f.byID[id]
	if !ok {
		return nil, fmt.Errorf("identity provider not found")
	}
	cp := *p
	return &cp, nil
}

func (f *fakeIDPConfigRepo) GetByOrgAndType(_ context.Context, orgID uuid.UUID, t domain.IdentityProviderType) (*domain.IdentityProvider, error) {
	for _, p := range f.byID {
		if p.OrganizationID == orgID && p.Type == t {
			cp := *p
			return &cp, nil
		}
	}
	return nil, fmt.Errorf("identity provider not found for type %s", t)
}

func (f *fakeIDPConfigRepo) ListByOrganization(_ context.Context, orgID uuid.UUID) ([]*domain.IdentityProvider, error) {
	out := []*domain.IdentityProvider{}
	for _, p := range f.byID {
		if p.OrganizationID == orgID {
			cp := *p
			out = append(out, &cp)
		}
	}
	return out, nil
}

func (f *fakeIDPConfigRepo) Update(_ context.Context, p *domain.IdentityProvider) (*domain.IdentityProvider, error) {
	if _, ok := f.byID[p.ID]; !ok {
		return nil, fmt.Errorf("identity provider not found")
	}
	cp := *p
	f.byID[p.ID] = &cp
	out := cp
	return &out, nil
}

func (f *fakeIDPConfigRepo) Delete(_ context.Context, id uuid.UUID, orgID uuid.UUID) error {
	p, ok := f.byID[id]
	if !ok || p.OrganizationID != orgID {
		return fmt.Errorf("identity provider not found")
	}
	delete(f.byID, id)
	return nil
}

// fakeSecretCipher is a reversible, non-plaintext stand-in for
// crypto.CryptoService: the ciphertext base64-encodes the plaintext behind
// a marker prefix, so it never equals nor contains the plaintext.
type fakeSecretCipher struct{}

func (fakeSecretCipher) Encrypt(plaintext string) (string, error) {
	return "fakeenc:" + base64.StdEncoding.EncodeToString([]byte(plaintext)), nil
}

func (fakeSecretCipher) Decrypt(ciphertext string) (string, error) {
	raw := strings.TrimPrefix(ciphertext, "fakeenc:")
	b, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func newOIDCConfigTestService(t *testing.T) (*OIDCProviderConfigService, *fakeIDPConfigRepo) {
	t.Helper()
	repo := newFakeIDPConfigRepo()
	svc := NewOIDCProviderConfigService(lifecycle.NewStartupReport(), repo, fakeSecretCipher{})
	return svc, repo
}

func validOIDCProviderInput(org uuid.UUID) OIDCProviderInput {
	return OIDCProviderInput{
		OrganizationID: org,
		Type:           domain.IDPTypeOIDC,
		Name:           "Google Workspace",
		IssuerURL:      "https://accounts.google.com",
		ClientID:       "client-abc.apps.googleusercontent.com",
		ClientSecret:   "super-secret-client-value",
		Scopes:         []string{"openid", "email", "profile"},
		EmailDomains:   []string{"example.com"},
	}
}

// (1) ONE-PER-ORG: the second oidc provider for an org is refused; a
// different org is unaffected. This is the load-bearing OSS/CE tripwire.
func TestOIDCProviderConfig_OnePerOrgRejectsSecond(t *testing.T) {
	svc, _ := newOIDCConfigTestService(t)
	org := uuid.New()

	_, err := svc.CreateOIDCProvider(context.Background(), validOIDCProviderInput(org))
	require.NoError(t, err, "first oidc provider must succeed")

	_, err = svc.CreateOIDCProvider(context.Background(), validOIDCProviderInput(org))
	require.ErrorIs(t, err, ErrOIDCProviderExists(), "a second oidc provider for the same org must be refused")

	_, err = svc.CreateOIDCProvider(context.Background(), validOIDCProviderInput(uuid.New()))
	require.NoError(t, err, "a different org must be able to configure its own oidc provider")
}

// (2) CLIENT-SECRET ENCRYPTION ROUND-TRIP: the plaintext is encrypted on
// store (never persisted or returned in the clear) and DecryptClientSecret
// recovers it in memory.
func TestOIDCProviderConfig_ClientSecretEncryptedRoundTrip(t *testing.T) {
	svc, repo := newOIDCConfigTestService(t)
	in := validOIDCProviderInput(uuid.New())

	created, err := svc.CreateOIDCProvider(context.Background(), in)
	require.NoError(t, err)

	// Returned object carries ciphertext, not the plaintext.
	require.NotEqual(t, in.ClientSecret, created.Config.ClientSecretEncrypted)
	require.NotContains(t, created.Config.ClientSecretEncrypted, in.ClientSecret)

	// The persisted row also holds ciphertext, never the plaintext.
	stored := repo.byID[created.ID]
	require.NotNil(t, stored)
	require.NotEqual(t, in.ClientSecret, stored.Config.ClientSecretEncrypted)
	require.NotContains(t, stored.Config.ClientSecretEncrypted, in.ClientSecret)

	// Only DecryptClientSecret reveals the original plaintext, in memory.
	plain, err := svc.DecryptClientSecret(created)
	require.NoError(t, err)
	require.Equal(t, in.ClientSecret, plain)
}

// (3) TYPE=oidc ONLY: ldap/ad are CE transports and are refused.
func TestOIDCProviderConfig_RejectsNonOIDCType(t *testing.T) {
	svc, _ := newOIDCConfigTestService(t)
	for _, typ := range []domain.IdentityProviderType{domain.IDPTypeLDAP, domain.IDPTypeAD} {
		in := validOIDCProviderInput(uuid.New())
		in.Type = typ
		_, err := svc.CreateOIDCProvider(context.Background(), in)
		require.ErrorIsf(t, err, ErrUnsupportedProviderType(), "type %q must be refused (CE)", typ)
	}
}

// (4) DISCOVERY-URL VALIDATION (structural, no network): non-https and
// malformed issuer URLs are refused; a valid https issuer is accepted.
func TestOIDCProviderConfig_RejectsInvalidIssuerURL(t *testing.T) {
	svc, _ := newOIDCConfigTestService(t)
	for _, bad := range []string{"", "http://insecure.example", "not-a-url", "://missing-scheme", "ftp://x.example", "https://"} {
		in := validOIDCProviderInput(uuid.New())
		in.IssuerURL = bad
		_, err := svc.CreateOIDCProvider(context.Background(), in)
		require.ErrorIsf(t, err, ErrInvalidIssuerURL(), "issuer %q must be refused", bad)
	}

	// A valid https issuer (Entra tenant-in-authority form) is accepted.
	in := validOIDCProviderInput(uuid.New())
	in.IssuerURL = "https://login.microsoftonline.com/tenant-id/v2.0"
	_, err := svc.CreateOIDCProvider(context.Background(), in)
	require.NoError(t, err)
}
