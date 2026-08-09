package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"strconv"
	"time"

	"github.com/identuum/identuum-idp-oss/internal/appliance"
)

// The `appliance` subcommand: what deployment/entrypoint.sh used to be.
//
// It is NOT the default action. Serving with `identuum-idp` (no subcommand)
// stays exactly as it was, so nothing about running the binary directly
// changes. This subcommand exists for the container, where the sequence
// prepare → migrate → drop privileges → serve has to happen in one process
// because there is no shell to sequence it.
//
// P-018 APPLIES HERE IN FULL. This path leads into serving, so it never calls
// panic, log.Fatal or os.Exit — it returns a status code to run(), the same as
// every other subcommand. A failure before serving returns non-zero and the
// container exits; a failure DURING serving is the runtime's own
// NOT-SERVING-JUST-ALERTING path, untouched by this file.

// applianceRunUID / GID must match the user the image creates. They are
// constants rather than env-configurable on purpose: an operator who could
// choose the drop target could choose 0, and "drop privileges to root" is the
// bug this replaces gosu to avoid.
const (
	applianceRunUID = 10001
	applianceRunGID = 10001
)

func runAppliance(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 {
		fmt.Fprintf(stderr, "identuum-idp: appliance takes no arguments, got %v\n", args)
		return 2
	}

	env := appliance.OSEnv{}
	isRoot := appliance.IsRoot()

	cfg, err := appliance.Prepare(ctx, env, stdout, applianceRunUID, applianceRunGID, isRoot, appliance.Chown)
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return 2
	}

	// Migrations run BEFORE the privilege drop only because they must run
	// before serving; they need no elevated permission, and running them here
	// keeps the old ordering (a failed migration aborts the container rather
	// than serving against a half-migrated schema).
	fmt.Fprintln(stdout, "identuum-idp-oss: applying migrations (URL redacted)...")
	if code := runMigrate(ctx, cfg.DatabaseURL, stdout, stderr); code != 0 {
		return code
	}

	if isRoot {
		if err := appliance.DropPrivileges(applianceRunUID, applianceRunGID); err != nil {
			fmt.Fprintf(stderr, "%v\n", err)
			return 2
		}
		fmt.Fprintf(stdout, "identuum-idp-oss: dropped privileges to uid=%d gid=%d\n",
			applianceRunUID, applianceRunGID)
	} else {
		fmt.Fprintf(stdout, "identuum-idp-oss: already unprivileged (uid=%d), no drop needed\n", os.Getuid())
	}

	fmt.Fprintf(stdout, "identuum-idp-oss: starting OSS IdP on %s (issuer=%s)...\n", cfg.Listen, cfg.Issuer)
	// Hand off to the SAME serve path the default action uses. Any divergence
	// here would mean the container runs a different server from the one a
	// developer runs locally.
	return runServe(cfg.Listen, cfg.Issuer, cfg.DatabaseURL,
		time.Hour, // same default as the serve flag
		resolveMetricsAddr("", os.Getenv("IDENTUUM_IDP_METRICS_ADDR")),
		stdout, stderr)
}

// applianceUIDGIDForTest exposes the drop target so a test can assert it is not
// root without duplicating the literals.
func applianceUIDGIDForTest() (string, string) {
	return strconv.Itoa(applianceRunUID), strconv.Itoa(applianceRunGID)
}
