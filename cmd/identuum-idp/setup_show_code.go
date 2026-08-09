package main

// show-setup-code subcommand for the appliance install UX,
// hardened on 2026-06-13 to make the database the authority for "is
// setup complete?".
//
// What this is:
//   - A customer-facing local support command that reveals the
//     first-run setup code so the operator can finish the browser
//     wizard. It consults the database first; the on-disk
//     $DATA_DIR/setup-token.txt is read ONLY while
//     system_setup_state.status='setup_required'. A stale token file
//     left behind by a failed delete-after-completion sweep does NOT
//     cause the plaintext to be revealed.
//   - Zero-credential beyond the database URL: the command does not
//     consult any other secret. The DB URL is supplied via the env var
//     IDENTUUM_IDP_DATABASE_URL or --database-url
//     flag and is never echoed to stdout or stderr (redactURL).
//
// What this is NOT:
//   - A way to read the setup token after setup completes. Once the
//     wizard succeeds the DB flips to 'setup_complete' and we refuse
//     (exit 2) regardless of whether the file is still on disk.
//   - A way to mutate state. No DB writes, no file writes, no
//     re-issuance of the token. A future --regenerate-setup-code
//     command is out of scope for this slice.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/postgres"
	"github.com/identuum/identuum-idp-oss/internal/setup"
)

// envShowSetupCodeDatabaseURL is the canonical env-var name the
// support command reads when the operator did not pass an explicit
// --database-url flag (under the show-setup-code subcommand). Same key the integration test
// harness already uses (postgres/setup_state_repository_pgx_test.go,
// e2e/oss_e2e_test.go) so operators don't learn a new env-var name.
const envShowSetupCodeDatabaseURL = "IDENTUUM_IDP_DATABASE_URL"

// setupStateLoader is the narrow surface runShowSetupCode needs. The
// production wrapper opens a pgxpool and binds it to
// PgxSetupStateRepository.Get; tests pass an in-memory closure so the
// behaviour matrix can be exercised without Postgres.
type setupStateLoader func(ctx context.Context) (*domain.SetupState, error)

// showSetupCodeCommand resolves the database URL, opens a pgxpool, and
// hands a setupStateLoader to runShowSetupCode. It is the surface
// invoked from main.go and is the only place this command is wired to
// real os.Getenv / *pgxpool.Pool.
func showSetupCodeCommand(ctx context.Context, dataDir, databaseURLFlag string, getenv func(string) string, stdout, stderr io.Writer) int {
	databaseURL := strings.TrimSpace(databaseURLFlag)
	if databaseURL == "" && getenv != nil {
		databaseURL = strings.TrimSpace(getenv(envShowSetupCodeDatabaseURL))
	}
	if databaseURL == "" {
		fmt.Fprintln(stderr, "identuum-idp: show-setup-code: database URL required — set the IDENTUUM_IDP_DATABASE_URL env var or pass --database-url <url>")
		return 2
	}

	pool, err := postgres.NewPool(ctx, databaseURL, nil)
	if err != nil {
		fmt.Fprintln(stderr, "identuum-idp: show-setup-code: open pool failed:", redactURL(err, databaseURL))
		return 1
	}
	defer pool.Close()

	repo := postgres.NewPgxSetupStateRepository(pool)
	loader := func(ctx context.Context) (*domain.SetupState, error) {
		state, err := repo.Get(ctx)
		if err != nil {
			return nil, redactURL(err, databaseURL)
		}
		return state, nil
	}

	return runShowSetupCode(ctx, dataDir, loader, stdout, stderr)
}

// runShowSetupCode is the testable core of the show-setup-code subcommand. The
// loader is the only collaborator that touches the database, so unit
// tests can substitute an in-memory closure that returns canned
// SetupState values without spinning up Postgres.
//
// Exit codes:
//
//   - 0 on success — DB reports setup_required AND the on-disk file is
//     present. The plaintext is printed to stdout with a single
//     trailing newline.
//   - 2 on every "refuse" case: empty data dir, missing/file-shaped
//     data dir, nil loader (database not configured), DB reports
//     setup_complete (stale file ignored), DB reports setup_required
//     but the file is missing (operator must restart the IDP service
//     so Initialize regenerates the token).
//   - 1 on unexpected I/O errors: loader failure (DB unreachable, row
//     missing, scan error) or filesystem read failure on the token
//     file other than fs.ErrNotExist.
func runShowSetupCode(ctx context.Context, dataDir string, loader setupStateLoader, stdout, stderr io.Writer) int {
	if dataDir == "" {
		fmt.Fprintln(stderr, "identuum-idp: show-setup-code: data dir is required")
		return 2
	}

	info, err := os.Stat(dataDir)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		fmt.Fprintf(stderr, "identuum-idp: show-setup-code: data dir does not exist: %s\n", dataDir)
		return 2
	case err != nil:
		fmt.Fprintf(stderr, "identuum-idp: show-setup-code: stat data dir: %v\n", err)
		return 1
	case !info.IsDir():
		fmt.Fprintf(stderr, "identuum-idp: show-setup-code: %s is not a directory\n", dataDir)
		return 2
	}

	if loader == nil {
		fmt.Fprintln(stderr, "identuum-idp: show-setup-code: database URL required — set the IDENTUUM_IDP_DATABASE_URL env var or pass --database-url <url>")
		return 2
	}

	state, err := loader(ctx)
	if err != nil {
		fmt.Fprintln(stderr, "identuum-idp: show-setup-code: read setup state failed:", err)
		return 1
	}
	if state == nil {
		fmt.Fprintln(stderr, "identuum-idp: show-setup-code: setup state row is missing — has the database been migrated?")
		return 1
	}

	if state.IsComplete() {
		fmt.Fprintln(stderr, "identuum-idp: show-setup-code: setup is already complete — the setup code is no longer valid; sign in through the UI with the site-administrator credentials created during setup")
		return 2
	}

	plaintext, err := setup.ReadTokenFile(dataDir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			fmt.Fprintf(stderr,
				"identuum-idp: show-setup-code: setup is required but the setup token file is missing at %s — restart the identuum-idp service so it regenerates the token and prints it on the next boot banner\n",
				setup.TokenFilePath(dataDir))
			return 2
		}
		fmt.Fprintf(stderr, "identuum-idp: show-setup-code: read setup token file: %v\n", err)
		return 1
	}

	// Print the plaintext exactly, with a trailing newline so a shell
	// pipe (`identuum-idp show-setup-code ./data | pbcopy`) does not
	// pick up extra padding. No banner, no log prefix.
	fmt.Fprintln(stdout, plaintext)
	return 0
}
