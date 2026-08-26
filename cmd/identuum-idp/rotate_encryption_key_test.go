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
