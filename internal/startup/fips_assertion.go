package startup

import (
	"errors"
	"fmt"
	"runtime/debug"
	"strings"
)

// fipsModulePrefix is the expected GOFIPS140 value prefix. The Go
// toolchain records the active module version as
// "<semver>-<commit-hash>" (e.g. "v1.0.0-c2097c7c"), so we prefix-match
// on the semver portion. A future v1.0.1 release would satisfy the
// check; a v2.x would NOT — that's a deliberate boundary because v2
// would be a different validated module.
const fipsModulePrefix = "v1.0.0"

// ErrFIPSBuildRequired is returned by VerifyFIPSBuildOrFail when the
// operator has set AUTH_SERVICE_REQUIRE_FIPS=true but the running
// binary was not built with the native Go Cryptographic Module. Fail
// closed — refuse to boot rather than silently downgrade to the
// non-FIPS path.
var ErrFIPSBuildRequired = errors.New(
	"CRITICAL: AUTH_SERVICE_REQUIRE_FIPS=true but the running binary " +
		"was not built with GOFIPS140=" + fipsModulePrefix +
		" — rebuild with 'make build-fips' or unset AUTH_SERVICE_REQUIRE_FIPS")

// buildInfoReader is the testable shape of runtime/debug.ReadBuildInfo.
// Production callers pass debug.ReadBuildInfo; unit tests inject a
// stub that returns a fabricated BuildInfo.
type buildInfoReader func() (*debug.BuildInfo, bool)

// VerifyFIPSBuildOrFail checks whether the running binary was built
// with the native Go Cryptographic Module. Behaviour:
//
//   - requireFIPS == false → always returns nil (opt-in gate).
//   - requireFIPS == true  → inspects debug.BuildInfo for a GOFIPS140
//     setting whose value begins with fipsModulePrefix. On match,
//     returns nil. On miss, returns ErrFIPSBuildRequired.
//
// The check is intentionally a build-time attestation, not a runtime
// crypto-module probe: the Go toolchain guarantees that a binary built
// with GOFIPS140=<ver> has the corresponding module baked in and
// DefaultGODEBUG=fips140=on wired into startup. Reading BuildInfo is
// sufficient; no symbol probing required.
//
// Why opt-in rather than default-on:
// (1) operators receive the FIPS-locked artifact as a separate release
// build, not via a license flip; an Enterprise customer on the non-FIPS
// artifact must not be forced to fail-closed at boot when the operator
// intentionally deployed the non-FIPS binary. (2) argon2id password
// hashing is not on the FIPS 140-3 approved list but is retained as an
// OWASP-recommended security-stronger choice than PBKDF2; FIPS builds
// therefore run under GODEBUG=fips140=on (approved operations routed
// through the validated module, non-approved algorithms still
// available), NOT the strict fips140=only mode which would panic on
// argon2 calls. AUTH_SERVICE_REQUIRE_FIPS is the operator's
// declaration of "I chose the FIPS artifact; refuse to boot if somehow
// the wrong binary ended up here."
func VerifyFIPSBuildOrFail(
	requireFIPS bool,
	readBuildInfo buildInfoReader,
	info func(msg string),
) error {
	if !requireFIPS {
		return nil
	}

	bi, ok := readBuildInfo()
	if !ok || bi == nil {
		return fmt.Errorf("%w (build info unavailable)", ErrFIPSBuildRequired)
	}

	for _, s := range bi.Settings {
		if s.Key == "GOFIPS140" && strings.HasPrefix(s.Value, fipsModulePrefix) {
			if info != nil {
				info(fmt.Sprintf(
					"FIPS gate satisfied: native Go Cryptographic Module %s (GOFIPS140=%s)",
					fipsModulePrefix, s.Value))
			}
			return nil
		}
	}
	return ErrFIPSBuildRequired
}
