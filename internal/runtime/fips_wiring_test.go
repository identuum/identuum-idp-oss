package runtime

import (
	"context"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// L-3: VerifyFIPSBuildOrFail existed with five callers, all in its own test
// file — the refusal it implements never executed in any process. It is now
// wired into (*Runtime).Start under P-018: on a non-FIPS binary with
// AUTH_SERVICE_REQUIRE_FIPS=true, Start records a FATAL and the process enters
// NOT-SERVING (503) instead of serving with the wrong crypto module — and
// instead of os.Exit, which P-018 forbids on serving paths.
//
// DB-backed; runs in gates via P2-24's require mode. The test binary is NOT
// built with GOFIPS140, which is exactly the wrong-binary case the operator
// flag exists to refuse — so no fake is needed: this test IS the wrong binary.
func TestStart_RequireFIPSOnNonFIPSBuild_TripsNotServing(t *testing.T) {
	dbURL := testDBURL(t)
	migrateTestSchema(t, dbURL)
	t.Setenv("IDENTUUM_IDP_ENCRYPTION_KEY", "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
	// A-2a: not asserting the single-replica boundary; opt out of the lease so
	// this never contends with the other DB-backed runtime tests (and so the
	// only fatal below can be the FIPS one).
	t.Setenv("IDENTUUM_IDP_ALLOW_MULTI_REPLICA", "true")
	t.Setenv("AUTH_SERVICE_REQUIRE_FIPS", "true")

	rt, err := New(Config{
		Addr:      "127.0.0.1:0",
		Issuer:    "http://127.0.0.1:7113",
		JWKSDBURL: dbURL,
		DataDir:   t.TempDir(),
		Stdout:    io.Discard,
		Stderr:    io.Discard,
	})
	require.NoError(t, err)

	// P-018: Start must SUCCEED — the process stays alive and refuses traffic;
	// it does not fail to boot and it does not exit.
	require.NoError(t, rt.Start(context.Background()),
		"P-018 demands NOT-SERVING, not a refusal to start")
	t.Cleanup(func() { _ = rt.Shutdown(context.Background()) })

	if rt.startupReport.Serving() {
		t.Fatal("AUTH_SERVICE_REQUIRE_FIPS=true on a non-FIPS test binary, yet the startup " +
			"report says SERVING — the FIPS attestation still never runs, or its failure is " +
			"not recorded as a P-018 fatal")
	}
	found := false
	for _, f := range rt.startupReport.Faults() {
		if strings.Contains(f.Component, "fips") {
			found = true
		}
	}
	if !found {
		t.Fatalf("a fatal is recorded but none names the fips component: %+v", rt.startupReport.Faults())
	}
}
