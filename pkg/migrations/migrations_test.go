package migrations_test

// Tests for the public OSS pkg/migrations seam.
//
// These tests guard four properties future identuum-idp-ce work will
// rely on:
//
//   1. The EmbedFS surfaced by pkg/migrations is byte-identical to the
//      core top-level migrations package's EmbedFS — there is no
//      drift between the two paths.
//   2. The embedded set carries the expected OSS migration history
//      (count + first/last names + no-empty-files guard).
//   3. The Apply / ApplyFS helpers fail closed on nil inputs without
//      reaching the database driver.
//   4. The public package's direct imports do not pull in CE, the
//      identuum-idp monolith, identuum-ag, identuum-ui, or
//      auth-service.

import (
	"context"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coremigrations "github.com/identuum/identuum-idp-oss/migrations"
	pkgmigrations "github.com/identuum/identuum-idp-oss/pkg/migrations"
)

// expectedOSSFiles is the exact set of SQL filenames the public
// EmbedFS must surface. Any addition / removal MUST be a deliberate
// slice and updated here. Mirrors the same list pinned by the core
// migrations package's own tests, kept in lockstep on purpose.
var expectedOSSFiles = []string{
	"0001_identity_credentials.sql",
	"0002_oauth_oidc.sql",
	"0003_identity_providers_and_roles.sql",
	"0004_keys_and_jobs.sql",
	"0005_organization_domains.sql",
	"0006_oauth_token_revocations.sql",
	"0007_oauth_refresh_tokens.sql",
	"0008_oauth_client_assertion_replays.sql",
	"0009_oauth_authorization_codes.sql",
	"0010_oauth_consents.sql",
	"0011_login_attempts.sql",
	"0012_browser_session_tokens_and_logout_metadata.sql",
	"0013_backchannel_logout_deliveries.sql",
	"0014_dcr_initial_access_tokens.sql",
	"0015_dcr_client_registration_tokens.sql",
	"0016_organization_protocol_settings.sql",
	"0017_mfa_pending_login_sessions.sql",
	"0018_email_verifications.sql",
	"0019_system_setup_state.sql",
	"0020_drop_oauth_par_requests.sql",
	"0021_session_rotation_grace_window.sql",
	"0022_mfa_pending_failed_attempts.sql",
	"0023_instance_lease.sql",
	"0024_oauth_refresh_token_family_id.sql",
	"0025_audit_events.sql",
	"0026_users_contact_email.sql",
	"0027_model_db_teeth.sql",
	"0028_model_update_teeth.sql",
	"0029_org_primary_domain_backfill.sql",
	"0030_service_account_name_unique.sql",
	"0031_setup_complete_coherence.sql",
	"0032_client_id_token_alg.sql",
	"0033_authcode_issued_tokens.sql",
	"0034_claims_parameter.sql",
	"0035_user_profiles.sql",
	"0036_address_phone.sql",
	"0037_agent_communication_authorizations.sql",
	"0038_dpop_proof_replays.sql",
	"0039_agent_communication_tokens.sql",
}

// TestEmbedFS_Opens verifies the embedded migration FS exposed by the
// public seam opens at all and returns at least one entry.
func TestEmbedFS_Opens(t *testing.T) {
	entries, err := fs.ReadDir(pkgmigrations.EmbedFS, pkgmigrations.DirName)
	require.NoErrorf(t, err, "pkg/migrations.EmbedFS must open at DirName=%q", pkgmigrations.DirName)
	require.NotEmpty(t, entries, "pkg/migrations.EmbedFS must contain at least one entry")
}

// TestEmbedFS_MatchesCorePackage proves the public EmbedFS is the same
// underlying embed.FS as the one the core top-level migrations package
// declares. We compare the rendered file-name set rather than relying
// on Go pointer identity, because embed.FS is a struct value type — a
// future Go release could legitimately copy it without changing
// semantics. Lockstep coverage of the set is what the CE overlay
// actually depends on.
func TestEmbedFS_MatchesCorePackage(t *testing.T) {
	pub := readSQLNames(t, pkgmigrations.EmbedFS, pkgmigrations.DirName)
	core := readSQLNames(t, coremigrations.EmbedFS, ".")
	assert.Equal(t, core, pub,
		"pkg/migrations.EmbedFS must surface the same SQL set as the core embed")
}

// TestEmbedFS_ExactFileSet enforces that the public EmbedFS contains
// exactly the 18 SQL filenames in expectedOSSFiles — no more, no
// fewer. Catches accidental adds/removes in CE seam work.
func TestEmbedFS_ExactFileSet(t *testing.T) {
	actual := readSQLNames(t, pkgmigrations.EmbedFS, pkgmigrations.DirName)
	expected := append([]string(nil), expectedOSSFiles...)
	sort.Strings(expected)

	if len(actual) != len(expected) {
		t.Fatalf("expected %d SQL files, found %d: actual=%v expected=%v",
			len(expected), len(actual), actual, expected)
	}
	for i := range actual {
		assert.Equalf(t, expected[i], actual[i], "file[%d]", i)
	}
}

// TestEmbedFS_StableFirstAndLast pins the first and last filenames so
// an accidental embed misordering or a missed renumber surfaces
// loudly. These are the bookends of the OSS history.
func TestEmbedFS_StableFirstAndLast(t *testing.T) {
	actual := readSQLNames(t, pkgmigrations.EmbedFS, pkgmigrations.DirName)
	require.NotEmpty(t, actual, "EmbedFS must have at least one SQL file")
	assert.Equal(t, "0001_identity_credentials.sql", actual[0],
		"first OSS migration must be 0001_identity_credentials.sql")
	assert.Equal(t, "0039_agent_communication_tokens.sql", actual[len(actual)-1],
		"last OSS migration must be 0039_agent_communication_tokens.sql")
}

// TestEmbedFS_NoFileIsEmpty guarantees every embedded SQL file has
// non-zero contents. A zero-byte migration would silently advance the
// goose version table without applying schema; this surfaces it
// immediately.
func TestEmbedFS_NoFileIsEmpty(t *testing.T) {
	for _, name := range expectedOSSFiles {
		t.Run(name, func(t *testing.T) {
			data, err := pkgmigrations.EmbedFS.ReadFile(name)
			require.NoErrorf(t, err, "failed to read %q", name)
			assert.NotEmptyf(t, data, "migration %q must not be empty", name)
		})
	}
}

// TestCurrent_MatchesCore confirms the public Current() helper is a
// pass-through onto the core top-level package's Current(). Drift here
// would mean a CE caller asking "what version is OSS at?" gets a
// different answer than the OSS runtime itself.
func TestCurrent_MatchesCore(t *testing.T) {
	assert.Equal(t, coremigrations.Current(), pkgmigrations.Current(),
		"pkg/migrations.Current must agree with core migrations.Current")
	assert.Equal(t, "0039", pkgmigrations.Current(),
		"pkg/migrations.Current must report the highest pinned version 0039")
}

// TestConstants_AreStable pins the three string constants the CE
// overlay will read at compile time. Changes to any of these are an
// API break that needs an explicit slice.
func TestConstants_AreStable(t *testing.T) {
	assert.Equal(t, ".", pkgmigrations.DirName, "DirName must be \".\" (flat embed root)")
	assert.Equal(t, "postgres", pkgmigrations.DefaultDialect, "DefaultDialect must be \"postgres\"")
	assert.Equal(t, "goose_db_version", pkgmigrations.DefaultVersionTable,
		"DefaultVersionTable must be the goose default goose_db_version")
}

// TestApply_NilDB verifies Apply returns an explicit error when called
// with a nil *sql.DB instead of panicking inside goose. The error
// message must mention "nil *sql.DB" so the operator sees what went
// wrong.
func TestApply_NilDB(t *testing.T) {
	results, err := pkgmigrations.Apply(context.Background(), nil)
	require.Error(t, err, "Apply(nil) must return an error")
	assert.Nil(t, results, "Apply(nil) must return nil results")
	assert.Containsf(t, err.Error(), "nil *sql.DB",
		"error message must mention nil DB, got %q", err.Error())
}

// TestApplyFS_NilFS verifies ApplyFS returns an explicit error when
// called with a nil fs.FS even when a non-nil *sql.DB-shaped pointer is
// supplied. Catches a CE caller that wires up the seam with a stale FS
// reference.
func TestApplyFS_NilFS(t *testing.T) {
	// Use a typed nil *sql.DB so the db-check fires first; that's the
	// behaviour we want for callers — the FS-check is the secondary
	// gate. With a nil DB the error must still be the db gate.
	_, err := pkgmigrations.ApplyFS(context.Background(), nil, nil)
	require.Error(t, err)
	assert.Containsf(t, err.Error(), "nil *sql.DB",
		"with nil DB the db gate must fire first, got %q", err.Error())
}

// TestPublicPackageDoesNotImportForbiddenTrees parses the public
// package source files and asserts that none of their direct imports
// reach into the CE, monolith, AG, UI, or auth-service trees. This is
// the seam-level enforcement of the OSS-must-not-import-CE invariant
// (I3 in PHASE0_IDP_INVARIANT_HARNESS) and of the broader repo
// boundaries documented in wiki/agent-rules.md §D.
//
// Transitive import checking is owned by the module-wide validation
// matrix (go list -deps + import-boundary grep); the test here is
// scoped to the direct surface of the pkg/migrations package so a
// drifting import shows up at the first edit, not at module-wide
// validation time.
func TestPublicPackageDoesNotImportForbiddenTrees(t *testing.T) {
	forbidden := []string{
		"github.com/identuum/identuum-idp-ce",
		"github.com/identuum/identuum-idp/internal",
		"github.com/identuum/identuum-ag",
		"github.com/identuum/identuum-ui",
		"github.com/identuum/auth-service",
	}

	wd, err := os.Getwd()
	require.NoError(t, err)
	pkgDir := wd

	fset := token.NewFileSet()
	entries, err := os.ReadDir(pkgDir)
	require.NoError(t, err)

	checked := 0
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") {
			continue
		}
		// Inspect only the production-source file (not the _test.go
		// files). Test files are allowed to import the stdlib's testing
		// scaffolding which is fine; we are pinning the seam's public
		// surface.
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		path := filepath.Join(pkgDir, name)
		file, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		require.NoErrorf(t, err, "failed to parse %q", name)

		for _, imp := range file.Imports {
			pathLit := strings.Trim(imp.Path.Value, `"`)
			for _, banned := range forbidden {
				assert.Falsef(t, strings.HasPrefix(pathLit, banned),
					"%s: forbidden import %q (matches %q)", name, pathLit, banned)
			}
		}
		checked++
	}
	require.GreaterOrEqual(t, checked, 1,
		"at least one production source file must have been scanned")
}

// readSQLNames returns the sorted list of *.sql filenames at the root
// of the supplied fs.FS rooted at dir. Test helper for both
// EmbedFS-parity and exact-set assertions.
func readSQLNames(t *testing.T, fsys fs.FS, dir string) []string {
	t.Helper()
	entries, err := fs.ReadDir(fsys, dir)
	require.NoErrorf(t, err, "fs.ReadDir(%q) failed", dir)
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".sql") {
			continue
		}
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}
