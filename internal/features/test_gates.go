package features

// Composition gates for OSS scaffolding and tests. These do not
// import internal/license and are safe in any code path that can
// reference internal/features.
//
// The existing FeatureGate interface already covers the seam; this
// file adds three drop-in implementations:
//
//   - OpenGate   — every IsFeatureEnabled call returns true.
//                  Used as the default in the OSS Gin scaffold so
//                  Phase 2 wiring does not regress route reachability
//                  before CE composition installs a tier-aware gate.
//                  Document deliberately: OSS defaults to OPEN.
//   - ClosedGate — every IsFeatureEnabled call returns false.
//                  Useful in tests that need to confirm a gated
//                  route fails closed.
//   - StaticGate — map-of-allowed-features, with a deliberate
//                  fail-closed default for everything else. The
//                  zero value is equivalent to ClosedGate.

// OpenGate is the always-allow FeatureGate. Suitable for the OSS
// default wiring during Phase 2 and for tests that exercise
// unrelated behavior.
type OpenGate struct{}

// IsFeatureEnabled always returns true.
func (OpenGate) IsFeatureEnabled(_ string, _ ...string) bool { return true }

// ClosedGate is the always-deny FeatureGate. Suitable for tests
// that confirm a gated route returns 403 when its feature is
// withheld.
type ClosedGate struct{}

// IsFeatureEnabled always returns false.
func (ClosedGate) IsFeatureEnabled(_ string, _ ...string) bool { return false }

// StaticGate is a map-backed FeatureGate. Features whose key is
// present and true return true; everything else is denied.
//
// The zero value is a valid ClosedGate equivalent. Use
// NewStaticGate for a constructor with documented copy semantics.
type StaticGate struct {
	enabled map[string]bool
}

// NewStaticGate returns a StaticGate whose enabled set is a
// defensive copy of enabled. The caller may mutate the supplied
// map after construction without affecting the gate's behavior.
func NewStaticGate(enabled map[string]bool) StaticGate {
	copy := make(map[string]bool, len(enabled))
	for k, v := range enabled {
		copy[k] = v
	}
	return StaticGate{enabled: copy}
}

// IsFeatureEnabled returns true iff feature is keyed-and-true in
// the underlying map. The roles argument is ignored — StaticGate
// is role-agnostic on purpose. Callers that need role-aware
// behavior should compose StaticGate with a wrapping FeatureGate
// implementation.
func (g StaticGate) IsFeatureEnabled(feature string, _ ...string) bool {
	if g.enabled == nil {
		return false
	}
	return g.enabled[feature]
}

// Compile-time assertions.
var _ FeatureGate = OpenGate{}
var _ FeatureGate = ClosedGate{}
var _ FeatureGate = StaticGate{}
