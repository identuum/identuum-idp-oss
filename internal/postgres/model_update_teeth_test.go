//go:build integration

package postgres_test

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Rg1 / Rg2 — the UPDATE-shaped brick vectors, asserted against a live schema.
//
// These correspond to gaps G1 and G2 of the third-party compliance audit, both
// REPRODUCED before the fix. The audit's wording for G2 was slightly off and
// the measurement is recorded here instead: demotion alone is refused by the
// System-org membership CHECK, so the working vector was demote-and-move in one
// statement, which left the installation with ZERO live site_admins.
//
// WHY THESE ARE DB TESTS AND NOT SERVICE TESTS. Every one of these statements
// goes around the Go layer entirely — a support script, a migration, a psql
// session, a restore. A guard that only exists in a service is a guard for
// callers who chose to use it.

func modelTeethDBURL(t *testing.T) string {
	t.Helper()
	for _, env := range []string{"IDENTUUM_IDP_TEST_DATABASE_URL", "IDENTUUM_IDP_DATABASE_URL"} {
		if v := os.Getenv(env); v != "" {
			return v
		}
	}
	// FAIL, DO NOT SKIP (CE-DB-PROVISION). A skip here would retire the model's
	// last line of defence while the run still printed `ok`.
	t.Fatal("IDENTUUM_IDP_TEST_DATABASE_URL (or IDENTUUM_IDP_DATABASE_URL) is not set; " +
		"the model UPDATE teeth were requested via -tags integration and require a live " +
		"Postgres DSN. `make integration-test` supplies it automatically (Makefile)")
	return ""
}

func modelTeethPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool, err := pgxpool.New(context.Background(), modelTeethDBURL(t))
	if err != nil {
		t.Fatalf("open pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

const (
	systemOrgID   = "00000000-0000-7000-0000-000000000000"
	siteAdminID   = "00000000-0000-7000-0000-000000000001"
	wantRefusedBy = "AdminPermissionsModel.md"
)

// requireSentinels makes the test's PREMISE explicit.
//
// FOUND BY A FROM-SCRATCH CONTROL. Run against a freshly migrated database —
// orgs=1 users=0 — every probe below "succeeded", because `UPDATE … WHERE
// id='…0001'` matching NO ROWS returns no error. The test then reported the
// guards as missing when what was missing was the row they guard. An assertion
// that cannot tell "refused" from "nothing there to refuse" measures nothing,
// and the failure mode is the dangerous direction: a green run on an empty
// database would have looked like proof.
//
// Seeding is legitimate here — this is what setup does — and it makes the
// result the same on any stack instead of depending on how the database was
// arrived at.
func requireSentinels(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `
INSERT INTO organizations (id, name, domain, org_slug, active)
VALUES ($1, 'System Organization', 'system.local', 'system-local', true)
ON CONFLICT (id) DO NOTHING`, systemOrgID); err != nil {
		t.Fatalf("seed System organization: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO users (id, email, organization_id, role, password_hash)
VALUES ($1, 'site_admin@system.local', $2, 'site_admin', 'x')
ON CONFLICT (id) DO NOTHING`, siteAdminID, systemOrgID); err != nil {
		t.Fatalf("seed sentinel site_admin: %v", err)
	}
	var n int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM users WHERE id = $1`, siteAdminID).Scan(&n); err != nil {
		t.Fatalf("verify sentinel: %v", err)
	}
	if n != 1 {
		t.Fatalf("PREMISE FAILED: no sentinel site_admin row to guard (%d) — every probe below "+
			"would report SUCCEEDED for a statement that simply matched nothing", n)
	}
}

// mustRefuse runs a statement that the model forbids and requires the DATABASE
// to refuse it, naming the model in the message so an operator who hits it
// learns why rather than just that.
//
// It also requires the statement to have had SOMETHING to act on: see
// requireSentinels for why "no error" and "no rows" are not the same answer.
func mustRefuse(t *testing.T, pool *pgxpool.Pool, what, sql string, args ...any) {
	t.Helper()
	_, err := pool.Exec(context.Background(), sql, args...)
	if err == nil {
		t.Errorf("%s SUCCEEDED. The database permitted it, so every path that does not go "+
			"through the Go service layer — a support script, a restore, a psql session — can "+
			"do it too.\n    statement: %s", what, strings.TrimSpace(sql))
		return
	}
	if !strings.Contains(err.Error(), wantRefusedBy) {
		t.Errorf("%s was refused, but not by a model guard: %v", what, err)
	}
}

// RULE: RG1
func TestRg1_SystemOrganizationCannotBeSuspendedOrSoftDeleted(t *testing.T) {
	pool := modelTeethPool(t)
	requireSentinels(t, pool)

	// BEFORE THE FIX both of these answered `UPDATE 1`. Suspending the System
	// organization cascade-revokes every session in it — the site_admin's
	// included — so it is "cannot be deleted" by another spelling.
	mustRefuse(t, pool, "suspending the System organization",
		`UPDATE organizations SET active = false WHERE id = $1`, systemOrgID)
	mustRefuse(t, pool, "soft-deleting the System organization",
		`UPDATE organizations SET deleted_at = now() WHERE id = $1`, systemOrgID)

	// CONTROL: the guard must be specific to the sentinel. If it refused every
	// organization, the assertions above would pass while the product lost the
	// ability to suspend a tenant at all — a green test hiding a broken feature.
	// SELF-SEEDED (THE-STANDING-FLOOR): the control used to SELECT any
	// existing tenant and SKIP when the database was fresh — but a skip
	// under --run-profile is CANNOT-EVALUATE, and `make validate` runs on a
	// fresh database by design. Seeding follows requireSentinels' logic:
	// it makes the result identical on any stack.
	tenant := seedScratchOrg(t, pool)
	// ASSERT THE CONTROL ACTED ON A ROW. `err == nil` alone cannot tell
	// "suspended a tenant" from "matched nothing" — the same no-rows-no-error
	// hole requireSentinels was written for, one statement lower down.
	// Measured: pointing this UPDATE at a row that does not exist left the test
	// GREEN, so the control could not distinguish a working guard from a guard
	// that refuses every organization.
	if tag, err := pool.Exec(context.Background(),
		`UPDATE organizations SET active = false WHERE id = $1`, tenant); err != nil {
		t.Fatalf("CONTROL FAILED: an ordinary organization can no longer be suspended: %v", err)
	} else if tag.RowsAffected() != 1 {
		t.Fatalf("CONTROL VACUOUS: suspending the tenant touched %d rows, want 1 — the control "+
			"proved nothing, and it is the only thing standing between this test and a guard "+
			"that refuses every organization", tag.RowsAffected())
	}
	if _, err := pool.Exec(context.Background(),
		`UPDATE organizations SET active = true WHERE id = $1`, tenant); err != nil {
		t.Fatalf("restore tenant: %v", err)
	}

	// And the state is intact afterwards.
	var active bool
	var deletedAt *string
	if err := pool.QueryRow(context.Background(),
		`SELECT active, deleted_at::text FROM organizations WHERE id = $1`, systemOrgID).
		Scan(&active, &deletedAt); err != nil {
		t.Fatalf("read System org: %v", err)
	}
	if !active || deletedAt != nil {
		t.Errorf("the System organization is active=%v deleted_at=%v — a refused statement "+
			"still changed the row", active, deletedAt)
	}
}

// RULE: RG2
func TestRg2_SiteAdminCannotBeBannedDemotedOrSoftDeleted(t *testing.T) {
	pool := modelTeethPool(t)
	requireSentinels(t, pool)

	mustRefuse(t, pool, "banning the site_admin",
		`UPDATE users SET banned = true WHERE id = $1`, siteAdminID)
	mustRefuse(t, pool, "soft-deleting the site_admin",
		`UPDATE users SET deleted_at = now() WHERE id = $1`, siteAdminID)
	mustRefuse(t, pool, "moving the site_admin out of the System organization",
		`UPDATE users SET organization_id = (SELECT id FROM organizations WHERE id <> $1 LIMIT 1) WHERE id = $2`,
		systemOrgID, siteAdminID)

	// THE VECTOR THAT ACTUALLY WORKED. Demotion alone trips the System-org
	// membership CHECK, so the audit's "self-demotion" needed the move in the
	// SAME statement — and it left the installation with zero live site_admins.
	mustRefuse(t, pool, "demoting the site_admin while moving it to a tenant",
		`UPDATE users SET role = 'org_user',
		        organization_id = (SELECT id FROM organizations WHERE id <> $1 LIMIT 1)
		  WHERE id = $2`, systemOrgID, siteAdminID)

	// THE INVARIANT THE WHOLE RULE EXISTS FOR.
	var live int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM users WHERE role = 'site_admin' AND deleted_at IS NULL`).Scan(&live); err != nil {
		t.Fatalf("count site_admins: %v", err)
	}
	if live != 1 {
		t.Errorf("live site_admins = %d, want exactly 1 — the model says the site_admin cannot "+
			"be deleted and there can only be one", live)
	}

	// CONTROL: an ordinary user is still bannable. Without this, a guard that
	// refused every UPDATE on every user would read as a pass here.
	// SELF-SEEDED (THE-STANDING-FLOOR): same reasoning as Rg1's control —
	// a fresh database has no ordinary user, and a skip is not a proof.
	scratchOrg := seedScratchOrg(t, pool)
	var other string
	if err := pool.QueryRow(context.Background(), `
INSERT INTO users (id, email, organization_id, role, password_hash)
VALUES (gen_random_uuid(), 'control-user-' || substr(md5(random()::text), 1, 8) || '@scratch.test', $1::uuid, 'org_user', 'x')
RETURNING id::text`, scratchOrg).Scan(&other); err != nil {
		t.Fatalf("seed control user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id = $1::uuid`, other)
	})
	// ASSERT THE CONTROL ACTED ON A ROW — see the twin in Rg1. Measured:
	// pointing this UPDATE at a row that does not exist left the test GREEN.
	if tag, err := pool.Exec(context.Background(),
		`UPDATE users SET banned = true WHERE id = $1`, other); err != nil {
		t.Fatalf("CONTROL FAILED: an ordinary user can no longer be banned: %v", err)
	} else if tag.RowsAffected() != 1 {
		t.Fatalf("CONTROL VACUOUS: banning the ordinary user touched %d rows, want 1 — the control "+
			"proved nothing, and it is the only thing standing between this test and a guard "+
			"that refuses every user", tag.RowsAffected())
	}
	if _, err := pool.Exec(context.Background(),
		`UPDATE users SET banned = false WHERE id = $1`, other); err != nil {
		t.Fatalf("restore ordinary user: %v", err)
	}
}

// Rg3 — the 0027 identity guards: the System organization's name, slug and id
// are pinned at the database. Same posture as Rg1/Rg2: FAIL, never skip.
// RULE: RG3
func TestRg3_SystemOrgIdentityCannotBeChanged(t *testing.T) {
	pool := modelTeethPool(t)
	requireSentinels(t, pool)

	mustRefuse(t, pool, "renaming the System organization",
		`UPDATE organizations SET name = 'Hacked' WHERE id = $1`, systemOrgID)
	mustRefuse(t, pool, "changing the System organization's slug",
		`UPDATE organizations SET org_slug = 'hacked' WHERE id = $1`, systemOrgID)
	// The id guard predates the model wording and names the sentinel rather
	// than the model file, so it gets its own refusal check.
	if _, err := pool.Exec(context.Background(),
		`UPDATE organizations SET id = gen_random_uuid() WHERE id = $1`, systemOrgID); err == nil {
		t.Error("changing the System organization's id SUCCEEDED")
	} else if !strings.Contains(err.Error(), "reserved sentinel") {
		t.Errorf("id change refused, but not by the sentinel guard: %v", err)
	}

	// CONTROL: the guard must be sentinel-specific — an ordinary organization
	// stays renameable, and the control must have acted on a real row.
	scratch := seedScratchOrg(t, pool)
	tag, err := pool.Exec(context.Background(),
		`UPDATE organizations SET name = 'Renamed OK' WHERE id = $1::uuid`, scratch)
	if err != nil {
		t.Fatalf("control rename refused: %v — the guard is not sentinel-specific", err)
	}
	if tag.RowsAffected() != 1 {
		t.Fatalf("control matched %d rows, want 1", tag.RowsAffected())
	}
}

// Rg4 — the 0027 structural caps: at most one LIVE site_admin row (partial
// unique index) and no non-site_admin member of the System organization
// (CHECK). These refusals come from the schema, not a trigger, so the error
// names the constraint rather than the model file.
// RULE: RG4
func TestRg4_SchemaCapsSiteAdminsAndSystemOrgMembership(t *testing.T) {
	pool := modelTeethPool(t)
	requireSentinels(t, pool)
	ctx := context.Background()

	_, err := pool.Exec(ctx, `
INSERT INTO users (id, email, organization_id, role, password_hash)
VALUES (gen_random_uuid(), 'second-admin@system.local', $1, 'site_admin', 'x')`, systemOrgID)
	if err == nil {
		_, _ = pool.Exec(ctx, `DELETE FROM users WHERE email = 'second-admin@system.local'`)
		t.Fatal("a SECOND live site_admin row was accepted; uq_model_single_site_admin is not holding")
	}
	if !strings.Contains(err.Error(), "single_site_admin") {
		t.Errorf("second site_admin refused, but not by the singleton index: %v", err)
	}

	_, err = pool.Exec(ctx, `
INSERT INTO users (id, email, organization_id, role, password_hash)
VALUES (gen_random_uuid(), 'intruder@system.local', $1, 'org_user', 'x')`, systemOrgID)
	if err == nil {
		_, _ = pool.Exec(ctx, `DELETE FROM users WHERE email = 'intruder@system.local'`)
		t.Fatal("an org_user row inside the System organization was accepted; chk_model_system_org_members is not holding")
	}
	if !strings.Contains(err.Error(), "chk_model_system_org_members") {
		t.Errorf("System-org intruder refused, but not by the membership CHECK: %v", err)
	}
}
