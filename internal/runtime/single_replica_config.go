package runtime

import (
	"os"
	"strconv"
	"strings"
)

// single_replica_config.go — the OSS single-replica override toggle
// (A-2a). Same getenv-hook convention as public_hardening_config.go /
// ratelimit_config.go so the resolution is unit-testable without a live
// process (tests inject a stub getenv).

// resolveAllowMultiReplica reports whether the operator has KNOWINGLY
// opted into running multiple replicas, disabling the single-replica
// instance lease, via
//
//	IDENTUUM_IDP_ALLOW_MULTI_REPLICA
//
// The value is parsed with strconv.ParseBool (accepts 1/t/T/TRUE/true/…
// and 0/f/F/FALSE/false/…). Unset, empty, or MALFORMED ⇒ false: the safe
// default ENFORCES the single-replica boundary, so a typo never silently
// disables the lease and drops the process into broken multi-replica
// behaviour. When true, the caller emits a LOUD startup WARNING naming
// exactly what degrades — the override is never silent.
func resolveAllowMultiReplica(getenv func(string) string) bool {
	if getenv == nil {
		getenv = os.Getenv
	}
	v, err := strconv.ParseBool(strings.TrimSpace(getenv("IDENTUUM_IDP_ALLOW_MULTI_REPLICA")))
	if err != nil {
		return false // unset / empty / malformed → lease enforced (safe default)
	}
	return v
}

// resolveEnvBool parses a boolean env var through getenv with the same
// unset/empty/malformed-means-false rule as resolveAllowMultiReplica.
// Used by the L-3 FIPS attestation for AUTH_SERVICE_REQUIRE_FIPS and its
// IDENTUUM_IDP_REQUIRE_FIPS alias.
func resolveEnvBool(getenv func(string) string, key string) bool {
	if getenv == nil {
		getenv = os.Getenv
	}
	v, err := strconv.ParseBool(strings.TrimSpace(getenv(key)))
	if err != nil {
		return false
	}
	return v
}
