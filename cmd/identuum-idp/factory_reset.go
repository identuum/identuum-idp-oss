package main

// The factory-reset subcommand (OPERATOR-UX-1) — a one-shot that returns the
// DATABASE to factory state:
//
//	identuum-idp factory-reset --i-understand-this-destroys-all-data [database-url]
//
// It drops the public schema (every table, row, trigger, and signing key —
// ALL tenant and identity data), recreates it, and re-applies the embedded
// migrations, leaving exactly what a first `identuum-idp migrate` leaves:
// an empty, migrated database at setup_required. The operator then restarts
// the appliance (or runs bootstrap) to begin setup again.
//
// GUARD (FACTORY-RESET-GUARD-1): without the EXPLICIT
// --i-understand-this-destroys-all-data flag the subcommand REFUSES before
// resolving a DSN or contacting any database — the refusal path is provably
// side-effect-free. There is no environment variable that substitutes for
// the flag: destruction must be typed.
//
// Scope: the DATABASE only. The data-dir (at-rest key file, stale setup-token
// file) is NOT touched — the at-rest key remains valid for the next setup,
// and the appliance regenerates the setup token on boot.
//
// The database URL follows the shared one-shot precedence (explicit
// positional wins, else IDENTUUM_IDP_DATABASE_URL, else IDENTUUM_IDP_OSS_DB —
// DSN-DEFAULT-1) and is never printed, even on failure.

import (
	"context"
	"flag"
	"fmt"
	"io"

	"github.com/identuum/identuum-idp-oss/internal/postgres"
)

// factoryResetConfirmFlag is the exact confirmation flag name. Documented in
// the operator guide; changing it is a breaking change for operator scripts.
const factoryResetConfirmFlag = "i-understand-this-destroys-all-data"

// dispatchFactoryReset parses the factory-reset subcommand. The confirmation
// guard runs BEFORE DSN resolution, so a refusal can never have contacted a
// database.
func dispatchFactoryReset(ctx context.Context, rest []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("identuum-idp factory-reset", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var confirmed bool
	fs.BoolVar(&confirmed, factoryResetConfirmFlag, false,
		"REQUIRED to proceed. Factory reset destroys ALL data in the database: every organization, user, client, session, audit row, and signing key.")
	if err := fs.Parse(rest); err != nil {
		return 2
	}
	if !confirmed {
		fmt.Fprintf(stderr, "identuum-idp: factory-reset: REFUSED — this destroys ALL data in the database "+
			"(every organization, user, client, session, audit row, and signing key). "+
			"Pass --%s to proceed. No database was contacted.\n", factoryResetConfirmFlag)
		return 2
	}
	if fs.NArg() > 1 {
		fmt.Fprintf(stderr, "identuum-idp: factory-reset: unexpected arguments after the database URL: %v\n", fs.Args()[1:])
		return 2
	}
	url, ok := requirePositionalURL("factory-reset", fs.Args(), stderr)
	if !ok {
		return 2
	}
	return runFactoryReset(ctx, url, stdout, stderr)
}

// runFactoryReset wipes the public schema and re-applies the embedded
// migrations. Errors are redacted so the URL never appears in output.
func runFactoryReset(ctx context.Context, databaseURL string, stdout, stderr io.Writer) int {
	db, err := postgres.OpenStdlibDB(databaseURL)
	if err != nil {
		fmt.Fprintln(stderr, "identuum-idp: factory-reset: open db failed:", redactURL(err, databaseURL))
		return 1
	}
	defer func() { _ = db.Close() }()

	// DROP SCHEMA ... CASCADE removes every table, trigger, and extension
	// object in one statement — including the model-guard triggers that
	// (correctly) refuse row-level deletion of the site_admin sentinel, which
	// is why a row-by-row wipe cannot reach factory state and this can.
	if _, err := db.ExecContext(ctx, "DROP SCHEMA public CASCADE"); err != nil {
		fmt.Fprintln(stderr, "identuum-idp: factory-reset: drop schema failed:", redactURL(err, databaseURL))
		return 1
	}
	if _, err := db.ExecContext(ctx, "CREATE SCHEMA public"); err != nil {
		fmt.Fprintln(stderr, "identuum-idp: factory-reset: recreate schema failed:", redactURL(err, databaseURL))
		return 1
	}
	fmt.Fprintln(stdout, "identuum-idp: factory-reset: all data destroyed (schema wiped)")

	// Re-apply the embedded migrations so the database is immediately usable
	// at factory state (migrated, empty, setup_required) — identical to a
	// fresh `identuum-idp migrate`.
	results, err := postgres.RunMigrations(ctx, db)
	if err != nil {
		fmt.Fprintln(stderr, "identuum-idp: factory-reset: re-migration failed:", redactURL(err, databaseURL))
		return 1
	}
	applied := 0
	for _, r := range results {
		if r.Applied {
			applied++
		}
	}
	fmt.Fprintf(stdout, "identuum-idp: factory-reset: re-applied %d migration(s) of %d embedded\n", applied, len(results))
	fmt.Fprintln(stdout, "identuum-idp: factory-reset: factory state reached — setup_required. Restart the appliance (or run bootstrap) to begin setup.")
	return 0
}
