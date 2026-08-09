package migrations_test

import (
	"io/fs"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/identuum/identuum-idp-oss/migrations"
)

// expectedOSSFiles is the exact set of SQL filenames that must exist in
// the OSS embedded migrations FS. Any addition / removal MUST be a
// deliberate slice and the corresponding entry updated here.
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
}

// excludedCommercialTables is the set of commercial-only table names that
// must never appear in OSS-side SQL. Surfaces accidental drift if a future
// slice copies CE schema into OSS.
var excludedCommercialTables = []string{
	// Owner decision (L-2, 2026-07-25): OSS gets a PLAIN persistent
	// audit_events log (migration 0025), so "audit_events" is no longer a
	// commercial-only table and was removed from this list. The COMMERCIAL
	// line is the tamper-evident chain and anomaly detection — audit_chain_tail
	// and audit_anomalies stay excluded (they must never appear in OSS SQL).
	"audit_chain_tail",
	"audit_anomalies",
	"system_backups",
	"organization_backups",
	"organization_backup_restore_jobs",
	"compliance_attestations",
	"webhook_endpoints",
	"webhook_outbox",
	"spiffe_federation_peers",
	"spiffe_trust_bundles",
	"spiffe_mapping_rules",
	"trusted_assertion_issuers",
	"dynamic_registration_tokens",
}

// requiredOSSTables is the set of table names backing the 19-field OSS
// postgres.Repositories aggregate. Each must be created by SOME OSS
// migration.
var requiredOSSTables = []string{
	"audit_events",
	"organizations",
	"users",
	"sessions",
	"webauthn_credentials",
	"password_resets",
	"service_accounts",
	"organization_claims",
	"oauth_clients",
	"api_resources",
	"api_resource_scopes",
	"oauth2_consents",
	"auth_codes",
	"oidc_states",
	"scope_templates",
	"identity_providers",
	"org_roles",
	"org_role_scopes",
	"user_roles",
	"signing_keys",
	"jobs",
	"organization_domains",
	"oauth_token_revocations",
	"oauth_refresh_tokens",
	"oauth_client_assertion_replays",
	"oauth_authorization_codes",
	"oauth_consents",
	"login_attempts",
	"browser_session_tokens",
	"backchannel_logout_deliveries",
}

// TestEmbedFSOpens verifies the embedded migration FS opens at all and
// returns at least one entry. A failure here would mean the //go:embed
// directive did not resolve any files.
func TestEmbedFSOpens(t *testing.T) {
	entries, err := fs.ReadDir(migrations.EmbedFS, ".")
	if err != nil {
		t.Fatalf("failed to read embedded migrations FS: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("embedded migrations FS contains zero entries")
	}
}

// TestExactFileSetMatches enforces that the embedded FS contains exactly
// the 5 SQL filenames in expectedOSSFiles — no more, no fewer.
func TestExactFileSetMatches(t *testing.T) {
	entries, err := fs.ReadDir(migrations.EmbedFS, ".")
	if err != nil {
		t.Fatalf("failed to read embedded migrations FS: %v", err)
	}

	var actual []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		actual = append(actual, e.Name())
	}
	sort.Strings(actual)

	expected := make([]string, len(expectedOSSFiles))
	copy(expected, expectedOSSFiles)
	sort.Strings(expected)

	if len(actual) != len(expected) {
		t.Fatalf("expected %d SQL files, found %d: actual=%v expected=%v",
			len(expected), len(actual), actual, expected)
	}
	for i := range actual {
		if actual[i] != expected[i] {
			t.Errorf("file[%d]: got %q, want %q", i, actual[i], expected[i])
		}
	}
}

// TestCurrentReturnsLatestMigration verifies the Current() helper returns
// the highest version number embedded in the OSS history. If this fails,
// either a new migration was added without updating expectedOSSFiles, or
// one was removed without updating it.
func TestCurrentReturnsLatestMigration(t *testing.T) {
	got := migrations.Current()
	want := "0030"
	if got != want {
		t.Errorf("Current() = %q, want %q", got, want)
	}
}

// TestEveryFileHasGooseAnnotations is a structural lint guard ensuring
// every embedded .sql file contains both a "-- +goose Up" and a
// "-- +goose Down" annotation, with Up appearing before Down. A missing
// Down block would only be discovered at rollback time in production
// without this test.
func TestEveryFileHasGooseAnnotations(t *testing.T) {
	for _, name := range expectedOSSFiles {
		t.Run(name, func(t *testing.T) {
			data, err := migrations.EmbedFS.ReadFile(name)
			if err != nil {
				t.Fatalf("failed to read %q: %v", name, err)
			}
			body := string(data)
			upIdx := strings.Index(body, "-- +goose Up")
			downIdx := strings.Index(body, "-- +goose Down")
			if upIdx < 0 {
				t.Errorf("missing -- +goose Up annotation in %q", name)
			}
			if downIdx < 0 {
				t.Errorf("missing -- +goose Down annotation in %q", name)
			}
			if upIdx >= 0 && downIdx >= 0 && upIdx >= downIdx {
				t.Errorf("-- +goose Up appears at or after -- +goose Down in %q (up=%d down=%d)",
					name, upIdx, downIdx)
			}
		})
	}
}

// TestNoCommercialTablesPresent surfaces drift if a future slice
// accidentally copies CE-only schema into the OSS migration set. The
// matcher is literal substring so a table-creation, foreign-key, or
// index reference to any commercial name will fail the test.
func TestNoCommercialTablesPresent(t *testing.T) {
	for _, name := range expectedOSSFiles {
		t.Run(name, func(t *testing.T) {
			data, err := migrations.EmbedFS.ReadFile(name)
			if err != nil {
				t.Fatalf("failed to read %q: %v", name, err)
			}
			body := string(data)
			for _, banned := range excludedCommercialTables {
				if containsTableReference(body, banned) {
					t.Errorf("OSS migration %q references commercial table %q — "+
						"that schema belongs in the CE overlay, not OSS",
						name, banned)
				}
			}
		})
	}
}

// TestEveryRequiredTableIsCreated confirms that every table backing the
// 19-field OSS postgres.Repositories aggregate is created by at least
// one OSS migration. Looks for "CREATE TABLE <name>" as a substring; a
// rename of any required table would fail loudly here.
func TestEveryRequiredTableIsCreated(t *testing.T) {
	var combined strings.Builder
	for _, name := range expectedOSSFiles {
		data, err := migrations.EmbedFS.ReadFile(name)
		if err != nil {
			t.Fatalf("failed to read %q: %v", name, err)
		}
		combined.Write(data)
		combined.WriteString("\n")
	}
	body := combined.String()

	for _, required := range requiredOSSTables {
		needle := "CREATE TABLE " + required
		if !strings.Contains(body, needle) {
			t.Errorf("required OSS table %q is not created by any embedded migration "+
				"(searched for substring %q)", required, needle)
		}
	}
}

// TestFilenamesAreSequentiallyNumbered confirms the embedded set is
// numbered 0001..N with no gaps. The OSS history is intentionally
// consolidated; gaps here would indicate a missed slice.
func TestFilenamesAreSequentiallyNumbered(t *testing.T) {
	entries, err := fs.ReadDir(migrations.EmbedFS, ".")
	if err != nil {
		t.Fatalf("failed to read embedded migrations FS: %v", err)
	}
	var versions []int
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		name := e.Name()
		underscoreIdx := strings.Index(name, "_")
		if underscoreIdx < 0 {
			t.Errorf("filename %q is missing the underscore separator", name)
			continue
		}
		v, err := strconv.Atoi(name[:underscoreIdx])
		if err != nil {
			t.Errorf("filename %q has non-numeric prefix: %v", name, err)
			continue
		}
		versions = append(versions, v)
	}
	sort.Ints(versions)
	for i, v := range versions {
		want := i + 1
		if v != want {
			t.Errorf("expected version %d at index %d, got %d", want, i, v)
		}
	}
}

// containsTableReference scans non-comment SQL lines for the table name
// with identifier-boundary delimiters on both sides. Lines whose first
// non-whitespace characters are "--" are skipped so the explanatory
// header comments in each migration can name CE tables without
// triggering the lint. Avoids false positives like
// "audit_events_prevent_truncate" matching "audit_events".
func containsTableReference(body, table string) bool {
	for _, line := range strings.Split(body, "\n") {
		trimmed := strings.TrimLeft(line, " \t")
		if strings.HasPrefix(trimmed, "--") {
			continue
		}
		if matchTableInLine(line, table) {
			return true
		}
	}
	return false
}

func matchTableInLine(line, table string) bool {
	for i := 0; i+len(table) <= len(line); i++ {
		if line[i:i+len(table)] != table {
			continue
		}
		if i > 0 {
			prev := line[i-1]
			if isIdentChar(prev) {
				continue
			}
		}
		if i+len(table) < len(line) {
			next := line[i+len(table)]
			if isIdentChar(next) {
				continue
			}
		}
		return true
	}
	return false
}

func isIdentChar(b byte) bool {
	return (b >= 'a' && b <= 'z') ||
		(b >= 'A' && b <= 'Z') ||
		(b >= '0' && b <= '9') ||
		b == '_'
}
