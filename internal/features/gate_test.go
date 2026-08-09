package features_test

// OSS-side FeatureGate / StarterFeatureGate contract pins. The
// monolith's gate_test.go imports internal/license to drift-mirror
// against license.TierFeatures[TierStarter]; that drift mirror
// remains in the monolith. Here in OSS we pin Starter behaviour
// directly without importing internal/license — the OSS module
// MUST NOT depend on the commercial verifier.

import (
	"testing"

	"github.com/identuum/identuum-idp-oss/internal/features"
)

func TestStarterFeatureGate_EnablesEveryStarterFeature(t *testing.T) {
	gate := features.StarterFeatureGate{}
	for _, f := range features.StarterFeatures {
		if !gate.IsFeatureEnabled(f) {
			t.Errorf("StarterFeatureGate must enable Starter feature %q, got false", f)
		}
	}
}

func TestStarterFeatureGate_StarterFeaturesContentPin(t *testing.T) {
	// Pin the exact Starter feature set so OSS contributors cannot
	// silently add or remove a Starter feature without touching this
	// test. This is the set OSS actually SERVES — it intentionally
	// diverges from CE license.TierFeatures[TierStarter] for the
	// OSS-baseline-ungated capabilities authorization_server and
	// dynamic_client_registration (audit C2/F2). See StarterFeatures.
	want := map[string]bool{
		features.Core:                      true,
		features.PublicRegistration:        true,
		features.MFA:                       true,
		features.SSO:                       true,
		features.StaticVault:               true,
		features.WebAuthn:                  true,
		features.AuthorizationServer:       true,
		features.DynamicClientRegistration: true,
	}
	if got := len(features.StarterFeatures); got != len(want) {
		t.Fatalf("features.StarterFeatures length = %d, want %d", got, len(want))
	}
	for _, f := range features.StarterFeatures {
		if !want[f] {
			t.Errorf("features.StarterFeatures contains unexpected entry %q", f)
		}
		delete(want, f)
	}
	for f := range want {
		t.Errorf("features.StarterFeatures missing expected entry %q", f)
	}
}

func TestStarterFeatureGate_DisablesCommercialFeatures(t *testing.T) {
	gate := features.StarterFeatureGate{}
	commercial := []string{
		// Optional modules (commercial-only at Starter).
		features.AppendOnlyAudit,
		features.FailClosedAudit,
		features.DynamicVault,
		// Professional features. (authorization_server is NOT here — it
		// is an OSS-baseline-ungated capability OSS serves; see
		// StarterFeatures / audit C2/F2.)
		features.PAR,
		features.WhiteLabel,
		features.OIDCFederation,
		features.Webhooks,
		features.AuditExport,
		// Enterprise features. (dynamic_client_registration is NOT here —
		// the DCR Foundation ships in OSS; see StarterFeatures.)
		features.LDAP,
		features.SCIM,
		features.AnomalyDetection,
		features.MCPServer,
		features.DatabaseBackups,
		features.SPIFFEFederation,
		// Declarative tier markers (never checked at runtime).
		features.FIPS,
		features.HardwareBinding,
	}
	for _, f := range commercial {
		if gate.IsFeatureEnabled(f) {
			t.Errorf("StarterFeatureGate must DENY commercial feature %q, got true", f)
		}
	}
}

func TestStarterFeatureGate_UnknownFeatureReturnsFalse(t *testing.T) {
	gate := features.StarterFeatureGate{}
	cases := []string{
		"",
		"this_feature_does_not_exist",
		"definitely_not_a_feature",
	}
	for _, f := range cases {
		if gate.IsFeatureEnabled(f) {
			t.Errorf("StarterFeatureGate.IsFeatureEnabled(%q) = true, want false (unknown feature)", f)
		}
	}
}

func TestStarterFeatureGate_SiteAdminMFAInvariant(t *testing.T) {
	gate := features.StarterFeatureGate{}
	if !gate.IsFeatureEnabled(features.MFA, "site_admin") {
		t.Errorf("StarterFeatureGate MUST honour site_admin MFA invariant; got false")
	}
}

func TestStarterFeatureGate_MFAEnabledWithoutRoles(t *testing.T) {
	// MFA is in the Starter set, so it should be true even without a
	// site_admin role argument.
	gate := features.StarterFeatureGate{}
	if !gate.IsFeatureEnabled(features.MFA) {
		t.Errorf("StarterFeatureGate.IsFeatureEnabled(MFA) without roles must be true (Starter feature)")
	}
}

func TestStarterFeatureGate_OrdinaryRoleDoesNotElevate(t *testing.T) {
	gate := features.StarterFeatureGate{}
	if gate.IsFeatureEnabled(features.LDAP, "org_admin") {
		t.Errorf("StarterFeatureGate.IsFeatureEnabled(LDAP, org_admin) = true, want false (no role-based elevation for commercial features)")
	}
}

func TestStarterFeatureGate_SatisfiesFeatureGateInterface(t *testing.T) {
	// Compile-time + runtime pin.
	var _ features.FeatureGate = features.StarterFeatureGate{}
	var gate features.FeatureGate = features.StarterFeatureGate{}
	if !gate.IsFeatureEnabled(features.Core) {
		t.Errorf("features.FeatureGate-typed StarterFeatureGate must enable Core")
	}
}
