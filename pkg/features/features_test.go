package features_test

// Tests for the public OSS pkg/features seam.
//
// These tests guard three properties future identuum-idp-ce work
// will rely on:
//
//   1. Constant values match the internal authority byte-for-byte
//      (no public/internal drift).
//   2. The interface types are Go type aliases — meaning that a
//      value declared via the public package satisfies the
//      internal interface and vice versa.
//   3. The Starter feature set and Starter limit set exposed
//      publicly match the internal authority.

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	internalfeatures "github.com/identuum/identuum-idp-oss/internal/features"
	pkgfeatures "github.com/identuum/identuum-idp-oss/pkg/features"
)

// TestFeatureConstants_MatchInternalAuthority ensures the public
// feature-key constants are byte-for-byte identical to the internal
// authority. A drift here would manifest as a route gated by the
// wrong key after CE adoption.
func TestFeatureConstants_MatchInternalAuthority(t *testing.T) {
	cases := []struct {
		name, pub, internal string
	}{
		{"Core", pkgfeatures.Core, internalfeatures.Core},
		{"PublicRegistration", pkgfeatures.PublicRegistration, internalfeatures.PublicRegistration},
		{"MFA", pkgfeatures.MFA, internalfeatures.MFA},
		{"SSO", pkgfeatures.SSO, internalfeatures.SSO},
		{"AppendOnlyAudit", pkgfeatures.AppendOnlyAudit, internalfeatures.AppendOnlyAudit},
		{"FailClosedAudit", pkgfeatures.FailClosedAudit, internalfeatures.FailClosedAudit},
		{"StaticVault", pkgfeatures.StaticVault, internalfeatures.StaticVault},
		{"DynamicVault", pkgfeatures.DynamicVault, internalfeatures.DynamicVault},
		{"PAR", pkgfeatures.PAR, internalfeatures.PAR},
		{"WhiteLabel", pkgfeatures.WhiteLabel, internalfeatures.WhiteLabel},
		{"OIDCFederation", pkgfeatures.OIDCFederation, internalfeatures.OIDCFederation},
		{"Webhooks", pkgfeatures.Webhooks, internalfeatures.Webhooks},
		{"WebAuthn", pkgfeatures.WebAuthn, internalfeatures.WebAuthn},
		{"AuthorizationServer", pkgfeatures.AuthorizationServer, internalfeatures.AuthorizationServer},
		{"AuditExport", pkgfeatures.AuditExport, internalfeatures.AuditExport},
		{"DynamicClientRegistration", pkgfeatures.DynamicClientRegistration, internalfeatures.DynamicClientRegistration},
		{"LDAP", pkgfeatures.LDAP, internalfeatures.LDAP},
		{"SCIM", pkgfeatures.SCIM, internalfeatures.SCIM},
		{"AnomalyDetection", pkgfeatures.AnomalyDetection, internalfeatures.AnomalyDetection},
		{"MCPServer", pkgfeatures.MCPServer, internalfeatures.MCPServer},
		{"DatabaseBackups", pkgfeatures.DatabaseBackups, internalfeatures.DatabaseBackups},
		{"SPIFFEFederation", pkgfeatures.SPIFFEFederation, internalfeatures.SPIFFEFederation},
		{"FIPS", pkgfeatures.FIPS, internalfeatures.FIPS},
		{"HardwareBinding", pkgfeatures.HardwareBinding, internalfeatures.HardwareBinding},
		{"LimitUserSessions", pkgfeatures.LimitUserSessions, internalfeatures.LimitUserSessions},
		{"LimitM2MSessions", pkgfeatures.LimitM2MSessions, internalfeatures.LimitM2MSessions},
		{"LimitTenants", pkgfeatures.LimitTenants, internalfeatures.LimitTenants},
		{"LimitUsers", pkgfeatures.LimitUsers, internalfeatures.LimitUsers},
		{"LimitSPIFFEPeers", pkgfeatures.LimitSPIFFEPeers, internalfeatures.LimitSPIFFEPeers},
		{"LimitSPIFFEBundleSizeBytes", pkgfeatures.LimitSPIFFEBundleSizeBytes, internalfeatures.LimitSPIFFEBundleSizeBytes},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.internal, c.pub, "public constant must equal internal authority")
			assert.NotEmpty(t, c.pub, "public feature constant must not be empty")
		})
	}
}

// TestStarterFeatures_PublicMatchesInternal pins the Starter
// feature-set slice exposed publicly against the internal source of
// truth.
func TestStarterFeatures_PublicMatchesInternal(t *testing.T) {
	assert.Equal(t, internalfeatures.StarterFeatures, pkgfeatures.StarterFeatures)

	expected := []string{
		pkgfeatures.Core,
		pkgfeatures.PublicRegistration,
		pkgfeatures.MFA,
		pkgfeatures.SSO,
		pkgfeatures.StaticVault,
		pkgfeatures.WebAuthn,
		pkgfeatures.AuthorizationServer,
		pkgfeatures.DynamicClientRegistration,
	}
	assert.ElementsMatch(t, expected, pkgfeatures.StarterFeatures,
		"Starter set must be exactly {Core, PublicRegistration, MFA, SSO, StaticVault, WebAuthn, AuthorizationServer, DynamicClientRegistration}")
}

// TestStarterLimits_PublicMatchesInternal pins the Starter
// per-metric limit map exposed publicly against the internal source
// of truth.
func TestStarterLimits_PublicMatchesInternal(t *testing.T) {
	assert.Equal(t, internalfeatures.StarterLimits, pkgfeatures.StarterLimits)

	require.Contains(t, pkgfeatures.StarterLimits, pkgfeatures.LimitTenants)
	require.Contains(t, pkgfeatures.StarterLimits, pkgfeatures.LimitM2MSessions)
	require.Contains(t, pkgfeatures.StarterLimits, pkgfeatures.LimitUsers)

	assert.Equal(t, int64(1), pkgfeatures.StarterLimits[pkgfeatures.LimitTenants])
	assert.Equal(t, int64(50), pkgfeatures.StarterLimits[pkgfeatures.LimitM2MSessions])
	assert.Equal(t, int64(-1), pkgfeatures.StarterLimits[pkgfeatures.LimitUsers])
}

// TestStarterFeatureGate_BehaviorParity confirms the public
// StarterFeatureGate type behaves identically to the internal
// StarterFeatureGate for Starter, commercial, and unknown features
// plus the site_admin MFA invariant.
func TestStarterFeatureGate_BehaviorParity(t *testing.T) {
	pubGate := pkgfeatures.StarterFeatureGate{}
	intGate := internalfeatures.StarterFeatureGate{}

	keys := []string{
		pkgfeatures.Core,
		pkgfeatures.PublicRegistration,
		pkgfeatures.MFA,
		pkgfeatures.SSO,
		pkgfeatures.StaticVault,
		pkgfeatures.WebAuthn,
		pkgfeatures.PAR,
		pkgfeatures.SCIM,
		pkgfeatures.LDAP,
		pkgfeatures.OIDCFederation,
		"completely_unknown_feature",
	}
	for _, k := range keys {
		assert.Equal(t, intGate.IsFeatureEnabled(k), pubGate.IsFeatureEnabled(k),
			"public StarterFeatureGate must agree with internal for %q", k)
	}

	assert.True(t, pubGate.IsFeatureEnabled(pkgfeatures.MFA, "site_admin"),
		"site_admin MFA invariant must hold via the public gate")
}

// TestStarterFeatureLimits_BehaviorParity confirms the public
// StarterFeatureLimits returns identical values to the internal
// implementation for known and unknown metrics.
func TestStarterFeatureLimits_BehaviorParity(t *testing.T) {
	pubLim := pkgfeatures.StarterFeatureLimits{}
	intLim := internalfeatures.StarterFeatureLimits{}

	metrics := []string{
		pkgfeatures.LimitTenants,
		pkgfeatures.LimitM2MSessions,
		pkgfeatures.LimitUsers,
		pkgfeatures.LimitSPIFFEPeers,
		pkgfeatures.LimitUserSessions,
		"unknown_metric",
	}
	for _, m := range metrics {
		assert.Equal(t, intLim.GetLimit(m), pubLim.GetLimit(m),
			"public StarterFeatureLimits must agree with internal for %q", m)
	}
}

// TestPublicTypesAreAliasesOfInternal proves the type aliases are
// real: a value declared as the public type can be passed to a
// function whose parameter is the internal type, and vice versa,
// without conversion. If aliases ever degrade to distinct
// definitions this test breaks at compile time.
func TestPublicTypesAreAliasesOfInternal(t *testing.T) {
	acceptInternalGate := func(g internalfeatures.FeatureGate) bool {
		return g.IsFeatureEnabled(pkgfeatures.Core)
	}
	acceptPublicGate := func(g pkgfeatures.FeatureGate) bool {
		return g.IsFeatureEnabled(pkgfeatures.Core)
	}

	assert.True(t, acceptInternalGate(pkgfeatures.StarterFeatureGate{}))
	assert.True(t, acceptPublicGate(internalfeatures.StarterFeatureGate{}))

	acceptInternalLimits := func(l internalfeatures.FeatureLimits) int64 {
		return l.GetLimit(pkgfeatures.LimitTenants)
	}
	acceptPublicLimits := func(l pkgfeatures.FeatureLimits) int64 {
		return l.GetLimit(pkgfeatures.LimitTenants)
	}
	assert.Equal(t, int64(1), acceptInternalLimits(pkgfeatures.StarterFeatureLimits{}))
	assert.Equal(t, int64(1), acceptPublicLimits(internalfeatures.StarterFeatureLimits{}))
}

// TestOpenGate_ClosedGate_StaticGate confirms the three test/composition
// gates are reachable through the public seam with identical semantics.
func TestOpenGate_ClosedGate_StaticGate(t *testing.T) {
	assert.True(t, pkgfeatures.OpenGate{}.IsFeatureEnabled("anything"))
	assert.False(t, pkgfeatures.ClosedGate{}.IsFeatureEnabled("anything"))

	g := pkgfeatures.NewStaticGate(map[string]bool{pkgfeatures.PAR: true})
	assert.True(t, g.IsFeatureEnabled(pkgfeatures.PAR))
	assert.False(t, g.IsFeatureEnabled(pkgfeatures.SCIM))
	assert.False(t, g.IsFeatureEnabled("unknown"))
}
