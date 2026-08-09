package startup

import (
	"errors"
	"runtime/debug"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildInfoWith constructs a debug.BuildInfo populated with the given
// settings — the minimum surface VerifyFIPSBuildOrFail reads.
func buildInfoWith(settings map[string]string) *debug.BuildInfo {
	bi := &debug.BuildInfo{}
	for k, v := range settings {
		bi.Settings = append(bi.Settings, debug.BuildSetting{Key: k, Value: v})
	}
	return bi
}

// TestVerifyFIPSBuildOrFail_NotRequired_IsAlwaysNoop pins the opt-in
// contract: when AUTH_SERVICE_REQUIRE_FIPS is false, the assertion
// MUST return nil without inspecting the binary. Operators on the
// standard (non-FIPS) artifact should see zero effect from this code
// path — anything else would break every existing deployment.
func TestVerifyFIPSBuildOrFail_NotRequired_IsAlwaysNoop(t *testing.T) {
	err := VerifyFIPSBuildOrFail(
		false,
		func() (*debug.BuildInfo, bool) {
			t.Fatal("readBuildInfo must not be called when requireFIPS is false")
			return nil, false
		},
		nil,
	)
	require.NoError(t, err)
}

// TestVerifyFIPSBuildOrFail_RequiredAndMatching passes when the build
// info records GOFIPS140=v1.0.0-<hash>. The hash suffix varies per Go
// toolchain release; the matcher is prefix-based so patch releases of
// the same validated module (v1.0.0) continue to pass.
func TestVerifyFIPSBuildOrFail_RequiredAndMatching(t *testing.T) {
	var logged string
	err := VerifyFIPSBuildOrFail(
		true,
		func() (*debug.BuildInfo, bool) {
			return buildInfoWith(map[string]string{
				"GOFIPS140":      "v1.0.0-c2097c7c",
				"CGO_ENABLED":    "0",
				"DefaultGODEBUG": "fips140=on",
			}), true
		},
		func(msg string) { logged = msg },
	)
	require.NoError(t, err)
	assert.Contains(t, logged, "FIPS gate satisfied")
	assert.Contains(t, logged, "v1.0.0-c2097c7c")
}

// TestVerifyFIPSBuildOrFail_RequiredButMissing — the headline fail-
// closed case: operator set AUTH_SERVICE_REQUIRE_FIPS=true but the
// running binary is the standard non-FIPS artifact. Must refuse to
// boot with ErrFIPSBuildRequired so the mis-deployment surfaces
// loudly at startup rather than as a silent compliance gap.
func TestVerifyFIPSBuildOrFail_RequiredButMissing(t *testing.T) {
	err := VerifyFIPSBuildOrFail(
		true,
		func() (*debug.BuildInfo, bool) {
			return buildInfoWith(map[string]string{
				"CGO_ENABLED": "0",
				// GOFIPS140 deliberately absent
			}), true
		},
		nil,
	)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrFIPSBuildRequired)
}

// TestVerifyFIPSBuildOrFail_WrongMajorVersion — a binary built against
// a future v2.x module must NOT satisfy a "v1.0.0 required" check.
// v2.x would be a different validated module with a different CMVP
// certificate; operators must re-assert the gate at upgrade time.
func TestVerifyFIPSBuildOrFail_WrongMajorVersion(t *testing.T) {
	err := VerifyFIPSBuildOrFail(
		true,
		func() (*debug.BuildInfo, bool) {
			return buildInfoWith(map[string]string{
				"GOFIPS140": "v2.0.0-abcdef12",
			}), true
		},
		nil,
	)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrFIPSBuildRequired)
}

// TestVerifyFIPSBuildOrFail_BuildInfoUnavailable is the defensive path:
// debug.ReadBuildInfo returns (nil, false) when invoked on a binary
// built without -buildmode=exe (rare in practice) or in certain
// testing contexts. Must still fail closed when the operator requested
// FIPS — "couldn't verify" is not "verified."
func TestVerifyFIPSBuildOrFail_BuildInfoUnavailable(t *testing.T) {
	err := VerifyFIPSBuildOrFail(
		true,
		func() (*debug.BuildInfo, bool) { return nil, false },
		nil,
	)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrFIPSBuildRequired))
}
