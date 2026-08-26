// rotate_encryption_key_test.go — KEY-ROTATE-1.
//
// THE-KEY-ROTATION-TRUTH (2026-08-26): the rotation tool's safety story is
// (a) ATOMIC — one transaction, and any value that decrypts under neither
// key aborts it, so a wrong old key changes zero rows; (b) IDEMPOTENT /
// RESUMABLE — a v2 ciphertext already naming the new key id is skipped,
// so a rerun (or a database left mixed by any earlier means) converges.
// These tests hold the per-value decision (the hinge of both claims) and
// the identity_providers JSON rewrite without a database, then exercise
// the real SQL against the live test schema inside one rolled-back
// transaction (nothing this test does is ever visible outside it).
package main

import (
	"context"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/identuum/identuum-idp-oss/internal/crypto"
	"github.com/identuum/identuum-idp-oss/internal/postgres"
	"github.com/identuum/identuum-idp-oss/internal/testsupport"
)

const (
	rotTestOldKey   = "0101010101010101010101010101010101010101010101010101010101010101"
	rotTestNewKey   = "0202020202020202020202020202020202020202020202020202020202020202"
	rotTestWrongKey = "0303030303030303030303030303030303030303030303030303030303030303"
)

// rotTestCipher returns the rotation-shaped cipher (active=NEW,
// previous={OLD}) plus the new key id, mirroring dispatch's construction.
func rotTestCipher(t *testing.T) (*crypto.CryptoService, string) {
	t.Helper()
	cs, err := crypto.NewCryptoService(rotTestOldKey)
	if err != nil {
		t.Fatalf("old cipher: %v", err)
	}
	_, newID, swapped, err := cs.SwapActive(rotTestNewKey)
	if err != nil || !swapped {
		t.Fatalf("swap to new: %v (swapped=%v)", err, swapped)
	}
	return cs, newID
}

// sealUnder encrypts plaintext under a single-key cipher built from hexKey.
func sealUnder(t *testing.T, hexKey, plaintext string) string {
	t.Helper()
	cs, err := crypto.NewCryptoService(hexKey)
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}
	ct, err := cs.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	return ct
}

// newOnlyDecrypt proves a rotated value needs ONLY the new key — the old
// key is genuinely retirable after rotation.
func newOnlyDecrypt(t *testing.T, val string) string {
	t.Helper()
	cs, err := crypto.NewCryptoService(rotTestNewKey)
	if err != nil {
		t.Fatalf("new-only cipher: %v", err)
	}
	pt, err := cs.Decrypt(val)
	if err != nil {
		t.Fatalf("rotated value must decrypt under the NEW key alone: %v", err)
	}
	return pt
}

func TestRotateCiphertext_ConvertsEveryLegacyFormatToTheNewKey(t *testing.T) {
	cs, newID := rotTestCipher(t)
	oldSealed := sealUnder(t, rotTestOldKey, "seed-1")
	v2Body := strings.SplitN(oldSealed, ":", 3)[2]

	cases := map[string]string{
		"v2-under-old-key": oldSealed,
		"v1-unkeyed":       "v1:" + v2Body,
		"legacy-bare":      v2Body,
	}
	for name, val := range cases {
		out, changed, err := rotateCiphertext(cs, newID, val, false)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !changed || !strings.HasPrefix(out, "v2:"+newID+":") {
			t.Fatalf("%s: want a converted v2:%s ciphertext, got changed=%v %q", name, newID, changed, out[:20])
		}
		if pt := newOnlyDecrypt(t, out); pt != "seed-1" {
			t.Fatalf("%s: round-trip lost the plaintext", name)
		}
	}
}

// The idempotence/resumability hinge: values already under the new key,
// and empty values, are untouched — a rerun converges instead of
// rewriting the world.
//
// RULE: KEY-ROTATE-1
func TestRotateCiphertext_RerunConvergesOnMixedInput(t *testing.T) {
	cs, newID := rotTestCipher(t)
	mixed := []string{
		"",
		sealUnder(t, rotTestOldKey, "a"),
		sealUnder(t, rotTestNewKey, "b"), // already current
		"v1:" + strings.SplitN(sealUnder(t, rotTestOldKey, "c"), ":", 3)[2],
	}

	firstChanged := 0
	after := make([]string, len(mixed))
	for i, v := range mixed {
		out, changed, err := rotateCiphertext(cs, newID, v, false)
		if err != nil {
			t.Fatalf("first pass [%d]: %v", i, err)
		}
		if changed {
			firstChanged++
		}
		after[i] = out
	}
	if firstChanged != 2 {
		t.Fatalf("first pass: want exactly the 2 old-sealed values converted, got %d", firstChanged)
	}

	for i, v := range after {
		out, changed, err := rotateCiphertext(cs, newID, v, false)
		if err != nil {
			t.Fatalf("second pass [%d]: %v", i, err)
		}
		if changed || out != v {
			t.Fatalf("second pass [%d]: rerun must be a no-op (idempotent), got changed=%v", i, changed)
		}
	}
}

// A value neither key opens is an ERROR, never a skip: skipping would
// strand the row under a retired key and hide a wrong-old-key run — the
// half-converted-database failure this tool exists to make impossible.
func TestRotateCiphertext_UndecryptableIsErrorNeverSkip(t *testing.T) {
	cs, newID := rotTestCipher(t)
	poisoned := sealUnder(t, rotTestWrongKey, "not-ours")
	_, changed, err := rotateCiphertext(cs, newID, poisoned, false)
	if err == nil {
		t.Fatal("a value sealed under neither key must abort the rotation, got nil error")
	}
	if changed {
		t.Fatal("an undecryptable value must not report changed")
	}
	if !strings.Contains(err.Error(), "NEITHER") {
		t.Fatalf("the error must say the value opens under neither key, got: %v", err)
	}
}

func TestRotateCiphertext_LegacyPlaintextPEMIsSealedOnlyWherePermitted(t *testing.T) {
	cs, newID := rotTestCipher(t)
	pem := "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----"

	out, changed, err := rotateCiphertext(cs, newID, pem, true)
	if err != nil || !changed {
		t.Fatalf("signing-key plaintext PEM must be sealed under the new key (changed=%v err=%v)", changed, err)
	}
	if pt := newOnlyDecrypt(t, out); pt != pem {
		t.Fatal("sealed PEM round-trip lost the material")
	}

	if _, _, err := rotateCiphertext(cs, newID, pem, false); err == nil {
		t.Fatal("outside signing keys a plaintext-PEM-shaped value is undecryptable garbage and must error")
	}
}

func TestRotateProviderConfigJSON_RotatesBothSealedFieldsAndPreservesTheRest(t *testing.T) {
	cs, newID := rotTestCipher(t)
	raw := `{"issuer_url":"https://idp.example","client_id":"c1",` +
		`"client_secret_encrypted":` + jsonStr(sealUnder(t, rotTestOldKey, "cs-plain")) + `,` +
		`"bind_password_encrypted":` + jsonStr(sealUnder(t, rotTestOldKey, "bp-plain")) + `,` +
		`"attribute_mapping":{"mail":"email"}}`

	out, changed, err := rotateProviderConfigJSON(cs, newID, raw)
	if err != nil || !changed {
		t.Fatalf("want both sealed fields rotated (changed=%v err=%v)", changed, err)
	}
	for field, want := range map[string]string{"client_secret_encrypted": "cs-plain", "bind_password_encrypted": "bp-plain"} {
		val := jsonField(t, out, field)
		if !strings.HasPrefix(val, "v2:"+newID+":") {
			t.Fatalf("%s must be re-sealed under the new key", field)
		}
		if newOnlyDecrypt(t, val) != want {
			t.Fatalf("%s round-trip lost the plaintext", field)
		}
	}
	if jsonField(t, out, "issuer_url") != "https://idp.example" || jsonField(t, out, "client_id") != "c1" {
		t.Fatal("non-sealed fields must be preserved")
	}

	// Rerun converges here too.
	if _, changed, err := rotateProviderConfigJSON(cs, newID, out); err != nil || changed {
		t.Fatalf("rerun over a rotated config must be a no-op (changed=%v err=%v)", changed, err)
	}
}

// The real SQL against the live test schema, entirely inside ONE
// transaction that is always rolled back: seed a signing key sealed under
// the old key plus a legacy plaintext PEM row, run the core, assert both
// convert; run the core AGAIN and assert full skip (idempotence); then
// poison a row under a third key and assert the core errors naming it.
// The rollback guarantees nothing here is ever visible to other suites.
func TestRotateEncryptionKeyCore_LiveSchema_ConvertsIdempotentlyAndAbortsOnPoison(t *testing.T) {
	dbURL := os.Getenv("IDENTUUM_IDP_TEST_DATABASE_URL")
	if dbURL == "" {
		if os.Getenv("IDENTUUM_IDP_REQUIRE_DB_TESTS") != "" {
			t.Fatal("IDENTUUM_IDP_REQUIRE_DB_TESTS is set but IDENTUUM_IDP_TEST_DATABASE_URL is not")
		}
		t.Skip("IDENTUUM_IDP_TEST_DATABASE_URL not set; skipping DB-backed rotation test")
	}
	if err := testsupport.RequireTestDatabase(dbURL); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	pool, err := postgres.NewPool(ctx, dbURL, nil)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	defer pool.Close()

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Work on an empty five-family surface WITHIN the transaction so the
	// core's counts are exactly ours. Discarded by the rollback.
	for _, del := range []string{
		`DELETE FROM oidc_states`, `DELETE FROM mfa_pending_login_sessions`,
		`DELETE FROM identity_providers`, `DELETE FROM signing_keys`, `UPDATE users SET mfa_secret = NULL`,
	} {
		if _, err := tx.Exec(ctx, del); err != nil {
			t.Fatalf("clear %q: %v", del, err)
		}
	}

	cs, newID := rotTestCipher(t)
	oldSealed := sealUnder(t, rotTestOldKey, "-----BEGIN PRIVATE KEY-----\nold\n-----END PRIVATE KEY-----")
	pem := "-----BEGIN PRIVATE KEY-----\nplain\n-----END PRIVATE KEY-----"
	seed := `INSERT INTO signing_keys (kid, algorithm, public_key, private_key, state, created_by)
	         VALUES ($1, 'EdDSA', 'pub', $2, 'deprecated', NULL)`
	if _, err := tx.Exec(ctx, seed, "rot-test-old", oldSealed); err != nil {
		t.Fatalf("seed old-sealed: %v", err)
	}
	if _, err := tx.Exec(ctx, seed, "rot-test-pem", pem); err != nil {
		t.Fatalf("seed plaintext pem: %v", err)
	}

	report, err := rotateEncryptionKeyCore(ctx, tx, cs, newID)
	if err != nil {
		t.Fatalf("core: %v", err)
	}
	if got := report["signing_keys.private_key"].converted; got != 2 {
		t.Fatalf("want both seeded signing keys converted, got %d", got)
	}
	var stored string
	if err := tx.QueryRow(ctx, `SELECT private_key FROM signing_keys WHERE kid = 'rot-test-old'`).Scan(&stored); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if !strings.HasPrefix(stored, "v2:"+newID+":") {
		t.Fatal("stored ciphertext must name the new key id")
	}

	// Idempotence against the real rows: a second run converts nothing.
	report2, err := rotateEncryptionKeyCore(ctx, tx, cs, newID)
	if err != nil {
		t.Fatalf("second core run: %v", err)
	}
	if c := report2["signing_keys.private_key"]; c.converted != 0 || c.skipped != 2 {
		t.Fatalf("second run must skip both rows (converted=%d skipped=%d)", c.converted, c.skipped)
	}

	// Poison: a row sealed under a third key aborts with the row named.
	if _, err := tx.Exec(ctx, seed, "rot-test-poison", sealUnder(t, rotTestWrongKey, "x")); err != nil {
		t.Fatalf("seed poison: %v", err)
	}
	if _, err := rotateEncryptionKeyCore(ctx, tx, cs, newID); err == nil {
		t.Fatal("a poisoned row must abort the rotation core")
	} else if !strings.Contains(err.Error(), "rot-test-poison") {
		t.Fatalf("the abort must name the poisoned row: %v", err)
	}
}

// The guard's PURE decision: a column outside the sealedFamilies table
// stays a candidate — including one whose NAME matches a known column in
// a foreign table — while every known family column is excluded. This is
// the always-running half of the guard's teeth; the fixture test below
// proves the live probe.
//
// RULE: ROTATE-GUARD-1
func TestGuardCandidateColumns_ExcludesExactlyTheKnownFamilies(t *testing.T) {
	all := []guardColumn{
		{tbl: "signing_keys", col: "private_key", typ: "text"},                               // known
		{tbl: "users", col: "mfa_secret", typ: "text"},                                       // known
		{tbl: "identity_providers", col: "config", typ: "jsonb"},                             // known
		{tbl: "trusted_assertion_issuers", col: "oidc_client_secret_encrypted", typ: "text"}, // the measured threat
		{tbl: "foreign_table", col: "private_key", typ: "text"},                              // known NAME, foreign table
	}
	got := guardCandidateColumns(all)
	if len(got) != 2 {
		t.Fatalf("want exactly the 2 foreign columns kept as candidates, got %d: %v", len(got), got)
	}
	if got[0].tbl != "trusted_assertion_issuers" || got[1].tbl != "foreign_table" {
		t.Fatalf("wrong candidates survived: %v", got)
	}
	// Every family in the shared table must be excluded — a family added
	// there must never re-appear as its own guard candidate.
	var famCols []guardColumn
	for _, f := range sealedFamilies {
		famCols = append(famCols, guardColumn{tbl: f.table, col: f.column, typ: "text"})
	}
	if left := guardCandidateColumns(famCols); len(left) != 0 {
		t.Fatalf("sealedFamilies columns must all be excluded, %d survived: %v", len(left), left)
	}
}

// The sealed-value shapes, unit-tested through Go regexp with the SAME
// character-class patterns the Postgres probe runs: this cipher's output
// is recognized, ordinary text and PEMs are not.
func TestSealedValuePatterns_MatchCipherOutputOnly(t *testing.T) {
	v2 := regexp.MustCompile(sealedV2Pattern)
	v1 := regexp.MustCompile(sealedV1Pattern)
	jv2 := regexp.MustCompile(sealedJSONV2Pattern)

	sealed := sealUnder(t, rotTestOldKey, "x")
	if !v2.MatchString(sealed) {
		t.Fatal("a real v2 ciphertext must match the v2 probe shape")
	}
	if !v1.MatchString("v1:" + strings.SplitN(sealed, ":", 3)[2]) {
		t.Fatal("a real v1-format ciphertext must match the v1 probe shape")
	}
	if !jv2.MatchString(`{"secret":"` + sealed + `"}`) {
		t.Fatal("a v2 ciphertext embedded in JSON must match the JSON probe shape")
	}
	for _, clean := range []string{
		"plain words", "-----BEGIN PRIVATE KEY-----", "v2:short:x", "v2:NOTHEXNOTHEX0000:x",
		"v1:not base64 spaces", "https://v1.example/path",
	} {
		if v2.MatchString(clean) || v1.MatchString(clean) {
			t.Fatalf("non-ciphertext %q must not trip the probe shapes", clean)
		}
	}
}

// The UNKNOWN-SCHEMA GUARD, proven against a live fixture schema: a
// table this tool's family list does not know, created inside the
// rolled-back transaction, carrying (a) a v2-sealed text column, (b) a
// v1-shaped text column, and (c) a jsonb column with an embedded sealed
// value — the guard must name all three; the clean base schema must
// probe empty. This is the door THE-KEY-ROTATION-TRUTH item 4 did not
// look at: a pre-split/CE database (e.g. trusted_assertion_issuers.
// oidc_client_secret_encrypted) would otherwise half-convert under a
// green DONE.
func TestProbeUnknownSealedColumns_RefusesForeignSealedColumnsByName(t *testing.T) {
	dbURL := os.Getenv("IDENTUUM_IDP_TEST_DATABASE_URL")
	if dbURL == "" {
		if os.Getenv("IDENTUUM_IDP_REQUIRE_DB_TESTS") != "" {
			t.Fatal("IDENTUUM_IDP_REQUIRE_DB_TESTS is set but IDENTUUM_IDP_TEST_DATABASE_URL is not")
		}
		t.Skip("IDENTUUM_IDP_TEST_DATABASE_URL not set; skipping DB-backed guard test")
	}
	if err := testsupport.RequireTestDatabase(dbURL); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	pool, err := postgres.NewPool(ctx, dbURL, nil)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	defer pool.Close()

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// The base schema must be clean BEFORE the fixture lands — a hit here
	// would mean the family list itself has drifted from the migrations.
	// The dispatch test's committed fixture table is tolerated: two test
	// processes can share this database, and that table is a named test
	// artifact, not schema drift.
	if hits, err := probeUnknownSealedColumns(ctx, tx); err != nil {
		t.Fatalf("guard on base schema: %v", err)
	} else {
		for _, h := range hits {
			if !strings.HasPrefix(h, "rot_guard_dispatch_fixture.") {
				t.Fatalf("base schema must probe clean, got hit: %v (all: %v)", h, hits)
			}
		}
	}

	if _, err := tx.Exec(ctx, `CREATE TABLE rot_guard_fixture (
		id int PRIMARY KEY,
		oidc_client_secret_encrypted text,
		legacy_secret text,
		payload jsonb,
		harmless text
	)`); err != nil {
		t.Fatalf("create fixture: %v", err)
	}
	v2 := sealUnder(t, rotTestOldKey, "foreign-sealed")
	if _, err := tx.Exec(ctx,
		`INSERT INTO rot_guard_fixture (id, oidc_client_secret_encrypted, legacy_secret, payload, harmless)
		 VALUES (1, $1, $2, $3::jsonb, 'plain words')`,
		v2, "v1:"+strings.SplitN(v2, ":", 3)[2], `{"nested":{"secret":"`+v2+`"}}`); err != nil {
		t.Fatalf("seed fixture: %v", err)
	}

	hits, err := probeUnknownSealedColumns(ctx, tx)
	if err != nil {
		t.Fatalf("guard on fixture schema: %v", err)
	}
	want := map[string]bool{
		"rot_guard_fixture.oidc_client_secret_encrypted": true,
		"rot_guard_fixture.legacy_secret":                true,
		"rot_guard_fixture.payload":                      true,
	}
	var mine []string
	for _, h := range hits {
		if strings.HasPrefix(h, "rot_guard_fixture.") {
			mine = append(mine, h)
		}
	}
	if len(mine) != len(want) {
		t.Fatalf("want exactly the 3 seeded sealed columns named, got %v", mine)
	}
	for _, h := range mine {
		if !want[h] {
			t.Fatalf("unexpected hit %q (all: %v)", h, hits)
		}
	}
}

// The WIRING is load-bearing too: the dispatch path must refuse — rc 1,
// the foreign column named on stderr, zero rows changed — when the
// database holds a sealed column outside the family list. This drives
// the REAL subcommand path (env keys, lease, transaction), so the
// fixture table must be committed and is dropped in cleanup.
func TestDispatchRotateEncryptionKey_RefusesUnknownSchemaByName(t *testing.T) {
	dbURL := os.Getenv("IDENTUUM_IDP_TEST_DATABASE_URL")
	if dbURL == "" {
		if os.Getenv("IDENTUUM_IDP_REQUIRE_DB_TESTS") != "" {
			t.Fatal("IDENTUUM_IDP_REQUIRE_DB_TESTS is set but IDENTUUM_IDP_TEST_DATABASE_URL is not")
		}
		t.Skip("IDENTUUM_IDP_TEST_DATABASE_URL not set; skipping DB-backed dispatch test")
	}
	if err := testsupport.RequireTestDatabase(dbURL); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	pool, err := postgres.NewPool(ctx, dbURL, nil)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	defer pool.Close()

	if _, err := pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS rot_guard_dispatch_fixture (id int PRIMARY KEY, sealed text)`); err != nil {
		t.Fatalf("create fixture: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DROP TABLE IF EXISTS rot_guard_dispatch_fixture`)
	})
	if _, err := pool.Exec(ctx,
		`INSERT INTO rot_guard_dispatch_fixture (id, sealed) VALUES (1, $1) ON CONFLICT (id) DO NOTHING`,
		sealUnder(t, rotTestWrongKey, "foreign")); err != nil {
		t.Fatalf("seed fixture: %v", err)
	}

	t.Setenv(rotateNewKeyEnv, rotTestNewKey)
	t.Setenv(rotateOldKeyEnv, rotTestOldKey)
	var out, errBuf strings.Builder
	rc := dispatchRotateEncryptionKey(ctx, []string{dbURL}, &out, &errBuf)
	if rc == 0 {
		t.Fatalf("dispatch must refuse the unknown-schema database, got rc 0 (stdout: %s)", out.String())
	}
	if !strings.Contains(errBuf.String(), "rot_guard_dispatch_fixture.sealed") {
		t.Fatalf("the refusal must name the foreign sealed column, got: %s", errBuf.String())
	}
	if !strings.Contains(errBuf.String(), "zero rows changed") {
		t.Fatalf("the refusal must state zero rows changed, got: %s", errBuf.String())
	}
}

func jsonStr(s string) string { return `"` + s + `"` }

func jsonField(t *testing.T, rawJSON, field string) string {
	t.Helper()
	marker := `"` + field + `":"`
	i := strings.Index(rawJSON, marker)
	if i < 0 {
		t.Fatalf("field %s missing in %s", field, rawJSON)
	}
	rest := rawJSON[i+len(marker):]
	return rest[:strings.IndexByte(rest, '"')]
}
