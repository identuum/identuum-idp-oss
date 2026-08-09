package features_test

// OSS-side FeatureLimits / StarterFeatureLimits contract pins. The
// monolith's limits_test.go imports internal/license to drift-mirror
// against license.TierLimits[TierStarter]; that drift mirror
// remains in the monolith. Here in OSS we pin Starter behaviour
// directly without importing internal/license.

import (
	"testing"

	"github.com/identuum/identuum-idp-oss/internal/features"
)

func TestStarterFeatureLimits_KnownMetricsReturnStarterValues(t *testing.T) {
	limits := features.StarterFeatureLimits{}
	cases := map[string]int64{
		features.LimitTenants:     1,
		features.LimitM2MSessions: 50,
		features.LimitUsers:       -1,
	}
	for metric, want := range cases {
		if got := limits.GetLimit(metric); got != want {
			t.Errorf("StarterFeatureLimits.GetLimit(%q) = %d, want %d", metric, got, want)
		}
	}
}

func TestStarterFeatureLimits_StarterLimitsContentPin(t *testing.T) {
	// Pin the exact Starter limits map so OSS contributors cannot
	// silently change a Starter value without touching this test.
	if got := len(features.StarterLimits); got != 3 {
		t.Fatalf("features.StarterLimits length = %d, want 3", got)
	}
	want := map[string]int64{
		features.LimitTenants:     1,
		features.LimitM2MSessions: 50,
		features.LimitUsers:       -1,
	}
	for metric, wantVal := range want {
		gotVal, ok := features.StarterLimits[metric]
		if !ok {
			t.Errorf("features.StarterLimits missing expected metric %q", metric)
			continue
		}
		if gotVal != wantVal {
			t.Errorf("features.StarterLimits[%q] = %d, want %d", metric, gotVal, wantVal)
		}
	}
}

func TestStarterFeatureLimits_UnknownMetricReturnsZero(t *testing.T) {
	limits := features.StarterFeatureLimits{}
	cases := []string{
		"",
		"this_metric_does_not_exist",
		features.LimitSPIFFEPeers,
		features.LimitSPIFFEBundleSizeBytes,
		features.LimitUserSessions,
	}
	for _, metric := range cases {
		if got := limits.GetLimit(metric); got != 0 {
			t.Errorf("StarterFeatureLimits.GetLimit(%q) = %d, want 0", metric, got)
		}
	}
}

func TestStarterFeatureLimits_SatisfiesFeatureLimitsInterface(t *testing.T) {
	var _ features.FeatureLimits = features.StarterFeatureLimits{}
	var limits features.FeatureLimits = features.StarterFeatureLimits{}
	if got := limits.GetLimit(features.LimitUsers); got != -1 {
		t.Errorf("features.FeatureLimits-typed StarterFeatureLimits.GetLimit(LimitUsers) = %d, want -1", got)
	}
}

func TestStarterFeatureLimits_UnlimitedSemanticPin(t *testing.T) {
	// Pin the -1 = unlimited convention. The monolith's
	// (*license.Service).GetLimit returns the same sentinel; the
	// OSS StarterFeatureLimits MUST preserve it because every
	// limit-checking call site reads -1 as "no cap".
	limits := features.StarterFeatureLimits{}
	if got := limits.GetLimit(features.LimitUsers); got != -1 {
		t.Errorf("LimitUsers at Starter must be -1 (unlimited); got %d", got)
	}
}
