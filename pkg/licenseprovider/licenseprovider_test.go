package licenseprovider_test

// Tests for the public OSS pkg/licenseprovider seam.
//
// These tests pin two properties future identuum-idp-ce work will
// rely on:
//
//   1. The Provider interface and StarterProvider type exposed
//      publicly are aliases of the internal authority — a value of
//      one IS a value of the other at the Go type level.
//   2. StarterProvider returned through the public factory
//      functions exhibits the documented Starter-tier semantics
//      (IsFeatureEnabled, GetLimit, GetLicenseInfo).

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	internalfeatures "github.com/identuum/identuum-idp-oss/internal/features"
	internallp "github.com/identuum/identuum-idp-oss/internal/licenseprovider"
	pkgfeatures "github.com/identuum/identuum-idp-oss/pkg/features"
	pkglp "github.com/identuum/identuum-idp-oss/pkg/licenseprovider"
)

func TestNew_ReturnsStarterProvider(t *testing.T) {
	p := pkglp.New()
	require.NotNil(t, p)
	assert.Equal(t, "VALID", p.GetLicenseInfo()["status"])
}

// TestNewStarterProvider_SatisfiesProviderInterface confirms the
// public factory returns a value satisfying the Provider interface,
// which is the contract CE will rely on.
func TestNewStarterProvider_SatisfiesProviderInterface(t *testing.T) {
	var p pkglp.Provider = pkglp.NewStarterProvider()
	require.NotNil(t, p)
	assert.True(t, p.IsFeatureEnabled(pkgfeatures.Core))
	assert.False(t, p.IsFeatureEnabled(pkgfeatures.PAR))
}

// TestPublicProvider_IsAliasOfInternal proves the public Provider
// type alias is real: a value constructed via the public factory
// satisfies the internal Provider interface (and vice versa)
// without conversion. If aliases ever degrade to distinct
// definitions this test breaks at compile time.
func TestPublicProvider_IsAliasOfInternal(t *testing.T) {
	acceptInternal := func(p internallp.Provider) bool {
		return p.IsFeatureEnabled(pkgfeatures.Core)
	}
	acceptPublic := func(p pkglp.Provider) bool {
		return p.IsFeatureEnabled(pkgfeatures.Core)
	}

	pub := pkglp.NewStarterProvider()
	intp := internallp.NewStarterProvider()

	assert.True(t, acceptInternal(pub))
	assert.True(t, acceptPublic(intp))
}

// TestStarterProvider_IsFeatureEnabledParity confirms the public
// path's IsFeatureEnabled agrees with the internal authority for
// the full Starter / commercial / unknown matrix.
func TestStarterProvider_IsFeatureEnabledParity(t *testing.T) {
	pub := pkglp.NewStarterProvider()
	intp := internallp.NewStarterProvider()

	keys := []string{
		pkgfeatures.Core,
		pkgfeatures.PublicRegistration,
		pkgfeatures.MFA,
		pkgfeatures.SSO,
		pkgfeatures.StaticVault,
		pkgfeatures.WebAuthn,
		pkgfeatures.PAR,
		pkgfeatures.OIDCFederation,
		pkgfeatures.SCIM,
		pkgfeatures.LDAP,
		pkgfeatures.AnomalyDetection,
		pkgfeatures.SPIFFEFederation,
		"unknown_feature_key",
	}
	for _, k := range keys {
		assert.Equal(t, intp.IsFeatureEnabled(k), pub.IsFeatureEnabled(k),
			"public StarterProvider must agree with internal for feature %q", k)
	}

	assert.True(t, pub.IsFeatureEnabled(pkgfeatures.MFA, "site_admin"),
		"site_admin MFA invariant must hold via the public Provider")
}

// TestStarterProvider_GetLimitParity pins the public path's GetLimit
// against the internal authority.
func TestStarterProvider_GetLimitParity(t *testing.T) {
	pub := pkglp.NewStarterProvider()
	intp := internallp.NewStarterProvider()

	metrics := []string{
		pkgfeatures.LimitTenants,
		pkgfeatures.LimitM2MSessions,
		pkgfeatures.LimitUsers,
		pkgfeatures.LimitSPIFFEPeers,
		pkgfeatures.LimitUserSessions,
		"unknown_metric",
	}
	for _, m := range metrics {
		assert.Equal(t, intp.GetLimit(m), pub.GetLimit(m),
			"public StarterProvider must agree with internal for metric %q", m)
	}

	assert.Equal(t, int64(1), pub.GetLimit(pkgfeatures.LimitTenants))
	assert.Equal(t, int64(50), pub.GetLimit(pkgfeatures.LimitM2MSessions))
	assert.Equal(t, int64(-1), pub.GetLimit(pkgfeatures.LimitUsers))
}

// TestStarterProvider_GetLicenseInfo_StableContract pins the
// runtime-safe scalar keys returned by GetLicenseInfo and confirms
// that no license-envelope, signature, or commercial-only keys
// appear in the public surface.
func TestStarterProvider_GetLicenseInfo_StableContract(t *testing.T) {
	info := pkglp.NewStarterProvider().GetLicenseInfo()

	assert.Equal(t, "VALID", info["status"])
	assert.Equal(t, "starter", info["tier"])
	assert.Equal(t, "starter", info["license_type"])
	assert.Equal(t, "self-hosted", info["deployment_mode"])

	forbidden := []string{
		"signature",
		"envelope",
		"signed_payload",
		"verifier",
		"hardware_id",
		"machine_id",
		"licensee",
		"revocation_bundle",
	}
	for _, k := range forbidden {
		_, present := info[k]
		assert.False(t, present, "GetLicenseInfo must not leak %q", k)
	}
}

// TestPublicSeam_LicenseInfoProviderAlias proves the seam type
// alias from pkg/features.LicenseInfoProvider holds: a value
// returned through pkg/licenseprovider satisfies the public
// LicenseInfoProvider interface, and that interface is identical
// to the internal one.
func TestPublicSeam_LicenseInfoProviderAlias(t *testing.T) {
	var lip pkgfeatures.LicenseInfoProvider = pkglp.NewStarterProvider()
	require.NotNil(t, lip)
	assert.Equal(t, "VALID", lip.GetLicenseInfo()["status"])

	var intLip internalfeatures.LicenseInfoProvider = pkglp.NewStarterProvider()
	require.NotNil(t, intLip)
}
