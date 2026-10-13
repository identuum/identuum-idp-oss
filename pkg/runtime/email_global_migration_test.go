package runtime_test

import (
	"context"
	"database/sql"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/identuum/identuum-idp-oss/internal/postgres"
)

// emailGlobalVersion is the migration that makes one live address one account
// across the server (OSS-0914-STAGE-2, owner decision EMAIL-SCOPE (a)).
const emailGlobalVersion = 56

// seedEmailOrgs inserts two active organizations at schema 55 and returns their
// ids. Plain SQL: the repositories write the current schema, not 55.
func seedEmailOrgs(t *testing.T, db *sql.DB) (string, string) {
	t.Helper()
	ids := [2]string{}
	for i, slug := range []string{"eg-one", "eg-two"} {
		if err := db.QueryRow(`INSERT INTO organizations (name, domain, org_slug, active) VALUES ($1, $2, $1, true) RETURNING id`,
			slug, slug+".example.invalid").Scan(&ids[i]); err != nil {
			t.Fatalf("seed organization %s: %v", slug, err)
		}
	}
	return ids[0], ids[1]
}

func seedEmailUser(t *testing.T, db *sql.DB, org, email string, deleted bool) {
	t.Helper()
	q := `INSERT INTO users (email, password_hash, organization_id, role) VALUES ($1, 'x', $2, 'org_user')`
	if deleted {
		q = `INSERT INTO users (email, password_hash, organization_id, role, deleted_at) VALUES ($1, 'x', $2, 'org_user', NOW())`
	}
	if _, err := db.Exec(q, email, org); err != nil {
		t.Fatalf("seed a user: %v", err)
	}
}

func appliedVersion(t *testing.T, db *sql.DB) int64 {
	t.Helper()
	var v int64
	if err := db.QueryRow(postgres.AppliedSchemaVersionSQL).Scan(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

// A database where one address belongs to two live accounts (in two
// organizations, or in one organization in two cases) is refused by the
// migration: nothing changes, the database stays at 55, and a server started
// on it is NOT-SERVING with the schema fault. The refusal names how many
// addresses and never an address.
//
// RULE: EMAIL-GLOBAL-UNIQUE-MIGRATION-1
func TestMigration0056_RefusesDuplicateLiveAddresses(t *testing.T) {
	for _, tc := range []struct {
		name string
		seed func(t *testing.T, db *sql.DB, one, two string)
	}{
		{"cross_org", func(t *testing.T, db *sql.DB, one, two string) {
			seedEmailUser(t, db, one, "dup@example.invalid", false)
			seedEmailUser(t, db, two, "dup@example.invalid", false)
		}},
		{"case_only", func(t *testing.T, db *sql.DB, one, _ string) {
			seedEmailUser(t, db, one, "dup@example.invalid", false)
			seedEmailUser(t, db, one, "Dup@Example.Invalid", false)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dsn, db := scratchDatabase(t, "identuum_idp_oss_test_eg_"+tc.name)
			migrateTo(t, db, emailGlobalVersion-1)
			one, two := seedEmailOrgs(t, db)
			tc.seed(t, db, one, two)
			before := rowCounts(t, db)

			_, err := postgres.RunMigrations(context.Background(), db)
			if err == nil || !postgres.IsMigrationRefused(err) {
				t.Fatalf("migrate = %v; want the refusal of migration %d", err, emailGlobalVersion)
			}
			if !strings.Contains(err.Error(), "1 email address") || strings.Contains(strings.ToLower(err.Error()), "dup@") {
				t.Errorf("the refusal says %q; want the count of addresses and no address", err.Error())
			}
			if v := appliedVersion(t, db); v != emailGlobalVersion-1 {
				t.Errorf("database at version %d after the refusal; want %d", v, emailGlobalVersion-1)
			}
			if after := rowCounts(t, db); !reflect.DeepEqual(before, after) {
				t.Errorf("the refused migration changed data")
			}

			rt, addr, _, err := startOn(t, dsn, t.TempDir())
			if err != nil {
				t.Fatalf("a refused migration leaves the server NOT-SERVING, not a Start error: %v", err)
			}
			if code, _ := body(t, addr, "/api/v1/component"); code != http.StatusServiceUnavailable {
				t.Errorf("a normal route answered %d; want 503", code)
			}
			if h := rt.Health(); h.Serving {
				t.Errorf("the server serves on a database the migration refused")
			}
			if err := shutdown(t, rt); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// EMAIL-GLOBAL-UNIQUE-MIGRATION-1, its applying half.
//
// Without duplicates the migration applies: a soft-deleted account does not
// count, and afterwards the database itself refuses a second live account
// with the address in any case and organization.
func TestMigration0056_AppliesAndTheIndexRefusesASecondAccount(t *testing.T) {
	_, db := scratchDatabase(t, "identuum_idp_oss_test_eg_apply")
	migrateTo(t, db, emailGlobalVersion-1)
	one, two := seedEmailOrgs(t, db)
	seedEmailUser(t, db, one, "held@example.invalid", false)
	seedEmailUser(t, db, two, "Held@Example.Invalid", true)

	if _, err := postgres.RunMigrations(context.Background(), db); err != nil {
		t.Fatalf("migrate without duplicates: %v", err)
	}
	if v := appliedVersion(t, db); v < emailGlobalVersion {
		t.Fatalf("database at version %d; want at least %d", v, emailGlobalVersion)
	}
	for _, tc := range []struct{ name, org, email string }{
		{"another organization", two, "held@example.invalid"},
		{"another case", one, "HELD@example.invalid"},
	} {
		_, err := db.Exec(`INSERT INTO users (email, password_hash, organization_id, role) VALUES ($1, 'x', $2, 'org_user')`, tc.email, tc.org)
		if err == nil || !strings.Contains(err.Error(), "23505") {
			t.Errorf("%s: a second live account = %v; want a unique violation", tc.name, err)
		}
	}
}
