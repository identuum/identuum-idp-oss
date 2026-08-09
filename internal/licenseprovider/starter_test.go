package licenseprovider_test

// OSS-side StarterProvider contract pins. Copied verbatim from the
// monolith's internal/licenseprovider/starter_test.go (import paths
// updated to identuum-idp-oss). This file has NO internal/license
// import; it exercises only Starter behaviour and is safe to ship
// in the OSS module.

import (
	"sort"
	"testing"

	"github.com/identuum/identuum-idp-oss/internal/features"
	"github.com/identuum/identuum-idp-oss/internal/licenseprovider"
)

func TestStarterProvider_SatisfiesFeatureGate(t *testing.T) {
	// Compile-time + runtime double pin.
	var _ features.FeatureGate = licenseprovider.StarterProvider{}
	gate := features.FeatureGate(licenseprovider.New())
	if !gate.IsFeatureEnabled(features.Core) {
		t.Errorf("StarterProvider must enable features.Core via FeatureGate interface")
	}
}

func TestStarterProvider_SatisfiesFeatureLimits(t *testing.T) {
	var _ features.FeatureLimits = licenseprovider.StarterProvider{}
	limits := features.FeatureLimits(licenseprovider.New())
	if got := limits.GetLimit(features.LimitUsers); got != -1 {
		t.Errorf("StarterProvider.GetLimit(LimitUsers) via FeatureLimits = %d, want -1 (unlimited)", got)
	}
}

func TestStarterProvider_SatisfiesLicenseInfoProvider(t *testing.T) {
	var _ features.LicenseInfoProvider = licenseprovider.StarterProvider{}
	provider := features.LicenseInfoProvider(licenseprovider.New())
	info := provider.GetLicenseInfo()
	if info == nil {
		t.Fatalf("LicenseInfoProvider.GetLicenseInfo() must not return nil")
	}
}

func TestStarterProvider_IsFeatureEnabled_AllowsStarterFeatures(t *testing.T) {
	p := licenseprovider.New()
	for _, f := range features.StarterFeatures {
		if !p.IsFeatureEnabled(f) {
			t.Errorf("StarterProvider.IsFeatureEnabled(%q) = false, want true (Starter feature)", f)
		}
	}
}

func TestStarterProvider_IsFeatureEnabled_DeniesCommercialFeatures(t *testing.T) {
	p := licenseprovider.New()
	commercial := []string{
		features.PAR,
		features.WhiteLabel,
		features.OIDCFederation,
		features.Webhooks,
		features.AppendOnlyAudit,
		// authorization_server + dynamic_client_registration were moved to
		// StarterFeatures (audit C2/F2) — OSS serves them; they are no
		// longer commercial-denied at the OSS gate.
		features.MCPServer,
		features.SCIM,
		features.AuditExport,
		features.LDAP,
		features.DynamicVault,
		features.FailClosedAudit,
		features.AnomalyDetection,
		features.DatabaseBackups,
		features.SPIFFEFederation,
		features.FIPS,
		features.HardwareBinding,
	}
	for _, f := range commercial {
		if p.IsFeatureEnabled(f) {
			t.Errorf("StarterProvider.IsFeatureEnabled(%q) = true, want false (commercial feature)", f)
		}
	}
}

func TestStarterProvider_IsFeatureEnabled_SiteAdminMFAInvariant(t *testing.T) {
	p := licenseprovider.New()
	if !p.IsFeatureEnabled(features.MFA, "site_admin") {
		t.Errorf("StarterProvider must honour the site_admin MFA invariant inherited from StarterFeatureGate")
	}
}

func TestStarterProvider_GetLimit_StarterValues(t *testing.T) {
	p := licenseprovider.New()
	cases := map[string]int64{
		features.LimitTenants:     1,
		features.LimitM2MSessions: 50,
		features.LimitUsers:       -1,
	}
	for metric, want := range cases {
		if got := p.GetLimit(metric); got != want {
			t.Errorf("StarterProvider.GetLimit(%q) = %d, want %d", metric, got, want)
		}
	}
}

func TestStarterProvider_GetLimit_UnknownMetricReturnsZero(t *testing.T) {
	p := licenseprovider.New()
	cases := []string{
		"",
		"this_metric_does_not_exist",
		features.LimitSPIFFEPeers,           // Enterprise-only → 0 at Starter
		features.LimitSPIFFEBundleSizeBytes, // Enterprise-only → 0 at Starter
		features.LimitUserSessions,          // Reserved/unused → 0
	}
	for _, metric := range cases {
		if got := p.GetLimit(metric); got != 0 {
			t.Errorf("StarterProvider.GetLimit(%q) = %d, want 0 (unknown / Enterprise-only metric)", metric, got)
		}
	}
}

func TestStarterProvider_GetLicenseInfo_RuntimeSafeMap(t *testing.T) {
	p := licenseprovider.New()
	info := p.GetLicenseInfo()

	if got, _ := info["status"].(string); got != "VALID" {
		t.Errorf(`GetLicenseInfo()["status"] = %v, want "VALID"`, info["status"])
	}
	if got, _ := info["tier"].(string); got != "starter" {
		t.Errorf(`GetLicenseInfo()["tier"] = %v, want "starter"`, info["tier"])
	}
	if got, _ := info["license_type"].(string); got != "starter" {
		t.Errorf(`GetLicenseInfo()["license_type"] = %v, want "starter"`, info["license_type"])
	}
	if got, _ := info["deployment_mode"].(string); got != "self-hosted" {
		t.Errorf(`GetLicenseInfo()["deployment_mode"] = %v, want "self-hosted"`, info["deployment_mode"])
	}
}

func TestStarterProvider_GetLicenseInfo_OmitsCommercialFields(t *testing.T) {
	// Defence-in-depth: the Starter map MUST NOT contain
	// customer-bearing or commercial-only keys.
	p := licenseprovider.New()
	info := p.GetLicenseInfo()
	forbidden := []string{
		"licensee",
		"issued_at",
		"features",
		"signature",
		"envelope",
		"private_key",
		"public_key",
		"machine_id",
		"entitlements",
		"valid",
	}
	for _, k := range forbidden {
		if _, ok := info[k]; ok {
			t.Errorf("GetLicenseInfo() must NOT contain forbidden key %q (got %v)", k, info[k])
		}
	}
}

func TestStarterProvider_GetLicenseInfo_ExpiresAtIsNilOrMissing(t *testing.T) {
	// The component-discovery projection in
	// handler_component.go::buildIDPComponentLicenseInfo treats a
	// missing OR nil "expires" key as "perpetual" and emits
	// expires_at = null + days_remaining = null. Starter is
	// perpetual so the key must be missing or nil.
	p := licenseprovider.New()
	info := p.GetLicenseInfo()
	v, present := info["expires"]
	if present && v != nil {
		t.Errorf(`GetLicenseInfo()["expires"] must be missing or nil (Starter is perpetual); got %v (%T)`, v, v)
	}
}

func TestStarterProvider_GetLicenseInfo_StableKeySet(t *testing.T) {
	// Pin the exact key set so a future contributor cannot
	// silently add a new key without updating the contract.
	p := licenseprovider.New()
	info := p.GetLicenseInfo()
	want := []string{"deployment_mode", "license_type", "status", "tier"}
	got := make([]string, 0, len(info))
	for k := range info {
		got = append(got, k)
	}
	sort.Strings(got)
	if len(got) != len(want) {
		t.Fatalf("StarterProvider.GetLicenseInfo() key set drift: got %v, want %v", got, want)
	}
	for i, k := range want {
		if got[i] != k {
			t.Errorf("StarterProvider.GetLicenseInfo() key drift at index %d: got %q, want %q", i, got[i], k)
		}
	}
}

func TestStarterProvider_GetLimit_Variadic_ZeroRoles(t *testing.T) {
	// StarterProvider embeds StarterFeatureGate which accepts the
	// variadic roles ... parameter. Documenting that callers can
	// invoke without roles (the common case).
	p := licenseprovider.New()
	_ = p.IsFeatureEnabled(features.Core)
}

func TestStarterProvider_SatisfiesProviderUnion(t *testing.T) {
	// Compile-time + runtime pin that StarterProvider satisfies
	// the Phase 2 Provider union. If a future change to any of the
	// three Phase 1 seams breaks composition, this fails to build.
	var _ licenseprovider.Provider = licenseprovider.StarterProvider{}
	var _ licenseprovider.Provider = (*licenseprovider.StarterProvider)(nil)
	p := licenseprovider.NewStarterProvider()
	if p == nil {
		t.Fatalf("NewStarterProvider() must not return a nil Provider")
	}
	if !p.IsFeatureEnabled(features.Core) {
		t.Errorf("NewStarterProvider().IsFeatureEnabled(Core) must be true")
	}
	if got := p.GetLimit(features.LimitUsers); got != -1 {
		t.Errorf("NewStarterProvider().GetLimit(LimitUsers) = %d, want -1", got)
	}
	if info := p.GetLicenseInfo(); info == nil {
		t.Errorf("NewStarterProvider().GetLicenseInfo() returned nil")
	}
}
