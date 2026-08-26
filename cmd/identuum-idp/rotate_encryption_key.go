// rotate_encryption_key.go — the `rotate-encryption-key` operator one-shot.
//
// THE-KEY-ROTATION-TRUTH (2026-08-26): before this subcommand, a customer
// who had to rotate (or had leaked) IDENTUUM_IDP_ENCRYPTION_KEY had exactly
// one path: factory-reset. The cipher already speaks rotation — every v2
// ciphertext names its key id and CryptoService holds an active key plus a
// previous-keys pool — but nothing re-encrypted the at-rest rows, so the
// old key could never actually be retired.
//
// The sealed set is CLOSED and BOUNDED (measured with gograph, five
// families, no cross-row invariants):
//
//	signing_keys.private_key
//	users.mfa_secret
//	mfa_pending_login_sessions.secret
//	oidc_states.pkce_verifier_encrypted
//	identity_providers.config -> client_secret_encrypted,
//	                             bind_password_encrypted (JSON fields)
//
// CONTRACT
//   - Keys come from the ENVIRONMENT only, never argv (argv is visible in
//     `ps`): IDENTUUM_IDP_ENCRYPTION_KEY is the NEW key — the value the
//     platform will run with after rotation — and
//     IDENTUUM_IDP_OLD_ENCRYPTION_KEY is the key being retired.
//   - OFFLINE ONLY: the tool takes the single-replica instance lease with
//     a single non-retrying attempt. A live serving process holds that
//     lease, so rotation REFUSES while anything serves. (A server booting
//     mid-rotation cannot half-read either: the rewrite is one
//     transaction, and a boot under the new key against uncommitted old
//     rows lands in SIGNING-KEY-SEAL-1's NOT-SERVING fault, proven
//     red-provable this same slice.)
//   - ATOMIC: every row of every family is rewritten in ONE transaction.
//     Any value that decrypts under neither key aborts the transaction —
//     a wrong old key changes ZERO rows.
//   - IDEMPOTENT / RESUMABLE: a v2 ciphertext already naming the new key
//     id is skipped, so re-running (same old/new pair) converges and a
//     database left mixed by any earlier means is finished, not broken.
//   - Identical old and new keys are refused as misconfiguration (the
//     operator forgot to change one of the two envs).
//
// One-shot operator tooling: exits by rc like migrate/bootstrap (the
// P-018 exemption); the serving process is untouched.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/identuum/identuum-idp-oss/internal/crypto"
	"github.com/identuum/identuum-idp-oss/internal/lease"
	"github.com/identuum/identuum-idp-oss/internal/postgres"
)

const (
	rotateNewKeyEnv = "IDENTUUM_IDP_ENCRYPTION_KEY"
	rotateOldKeyEnv = "IDENTUUM_IDP_OLD_ENCRYPTION_KEY"
)

// rotationCounts is one family's outcome tally.
type rotationCounts struct {
	converted int
	skipped   int
}

// sealedFamily describes one at-rest sealed surface. This slice is the
// SINGLE source of truth for three consumers: the rotation core (selKV /
// upd), the unknown-schema guard (table+column form the exclusion set),
// and the doctor's at-rest key-id census (aggSQL). A new sealed column
// added here lands in all three at once; a sealed column NOT added here
// is what the guard exists to catch.
type sealedFamily struct {
	family string // operator-facing name, e.g. "signing_keys.private_key"
	table  string
	column string
	selKV  string // rotation: (key, value) read
	upd    string // rotation: write-back by key
	pemOK  bool   // signing keys: legacy plaintext PEM is sealed, not skipped
	json   bool   // sealed values live INSIDE a JSON document (identity_providers.config)
	aggSQL string // doctor: value -> key-id census ('plaintext'/'legacy' for non-v2 shapes)
}

// keyIDCensus is the shared doctor aggregation: v2 values report their
// key id, plaintext PEMs report 'plaintext', anything else 'legacy'.
const keyIDCensus = `SELECT COALESCE(substring(%[1]s FROM '^v2:([0-9a-f]{16}):'),
	       CASE WHEN %[1]s LIKE '-----BEGIN%%' THEN 'plaintext' ELSE 'legacy' END) AS kid, count(*)
	FROM %[2]s WHERE %[1]s IS NOT NULL AND %[1]s <> '' GROUP BY 1 ORDER BY 1`

var sealedFamilies = []sealedFamily{
	{
		family: "signing_keys.private_key",
		table:  "signing_keys", column: "private_key",
		selKV:  `SELECT kid, private_key FROM signing_keys WHERE private_key <> ''`,
		upd:    `UPDATE signing_keys SET private_key = $2 WHERE kid = $1`,
		pemOK:  true,
		aggSQL: fmt.Sprintf(keyIDCensus, "private_key", "signing_keys"),
	},
	{
		family: "users.mfa_secret",
		table:  "users", column: "mfa_secret",
		selKV:  `SELECT id::text, mfa_secret FROM users WHERE mfa_secret IS NOT NULL AND mfa_secret <> ''`,
		upd:    `UPDATE users SET mfa_secret = $2 WHERE id::text = $1`,
		aggSQL: fmt.Sprintf(keyIDCensus, "mfa_secret", "users"),
	},
	{
		family: "mfa_pending_login_sessions.secret",
		table:  "mfa_pending_login_sessions", column: "secret",
		selKV:  `SELECT id::text, secret FROM mfa_pending_login_sessions WHERE secret IS NOT NULL AND secret <> ''`,
		upd:    `UPDATE mfa_pending_login_sessions SET secret = $2 WHERE id::text = $1`,
		aggSQL: fmt.Sprintf(keyIDCensus, "secret", "mfa_pending_login_sessions"),
	},
	{
		family: "oidc_states.pkce_verifier_encrypted",
		table:  "oidc_states", column: "pkce_verifier_encrypted",
		selKV:  `SELECT state, pkce_verifier_encrypted FROM oidc_states WHERE pkce_verifier_encrypted <> ''`,
		upd:    `UPDATE oidc_states SET pkce_verifier_encrypted = $2 WHERE state = $1`,
		aggSQL: fmt.Sprintf(keyIDCensus, "pkce_verifier_encrypted", "oidc_states"),
	},
	{
		family: "identity_providers.config (2 sealed fields)",
		table:  "identity_providers", column: "config",
		selKV: `SELECT id::text, config::text FROM identity_providers WHERE config IS NOT NULL`,
		upd:   `UPDATE identity_providers SET config = $2::jsonb WHERE id::text = $1`,
		json:  true,
		aggSQL: `SELECT COALESCE(substring(v FROM '^v2:([0-9a-f]{16}):'), 'legacy') AS kid, count(*)
			FROM (SELECT config->>'client_secret_encrypted' AS v FROM identity_providers
			      UNION ALL SELECT config->>'bind_password_encrypted' FROM identity_providers) s
			WHERE v IS NOT NULL AND v <> '' GROUP BY 1 ORDER BY 1`,
	},
}

// dispatchRotateEncryptionKey wires the one-shot: env keys, pool, the
// offline lease guard, then the single-transaction core.
func dispatchRotateEncryptionKey(ctx context.Context, rest []string, stdout, stderr io.Writer) int {
	databaseURL, ok := requirePositionalURL("rotate-encryption-key", rest, stderr)
	if !ok {
		return 2
	}

	newHex := strings.TrimSpace(os.Getenv(rotateNewKeyEnv))
	oldHex := strings.TrimSpace(os.Getenv(rotateOldKeyEnv))
	if newHex == "" || oldHex == "" {
		fmt.Fprintf(stderr, "identuum-idp: rotate-encryption-key: both %s (the NEW key) and %s (the key being retired) must be set; key material is never accepted on the command line\n",
			rotateNewKeyEnv, rotateOldKeyEnv)
		return 2
	}

	// active = NEW (every re-encrypt), previous = {OLD} (every decrypt of
	// not-yet-rotated rows). Built by installing OLD then swapping NEW in,
	// which also validates both keys and derives both ids.
	cs, err := crypto.NewCryptoService(oldHex)
	if err != nil {
		fmt.Fprintf(stderr, "identuum-idp: rotate-encryption-key: %s invalid: %v\n", rotateOldKeyEnv, err)
		return 2
	}
	oldID, newID, swapped, err := cs.SwapActive(newHex)
	if err != nil {
		fmt.Fprintf(stderr, "identuum-idp: rotate-encryption-key: %s invalid: %v\n", rotateNewKeyEnv, err)
		return 2
	}
	if !swapped {
		fmt.Fprintf(stderr, "identuum-idp: rotate-encryption-key: %s and %s hold the SAME key (id %s) — nothing would rotate; set %s to the key being retired\n",
			rotateNewKeyEnv, rotateOldKeyEnv, newID, rotateOldKeyEnv)
		return 2
	}

	pool, err := postgres.NewPool(ctx, databaseURL, nil)
	if err != nil {
		fmt.Fprintln(stderr, "identuum-idp: rotate-encryption-key: open pool failed:", redactURL(err, databaseURL))
		return 1
	}
	defer pool.Close()

	// OFFLINE GUARD: one attempt, no retry window. A live serving process
	// heartbeats the singleton lease and this upsert then matches nothing.
	leaseRepo := postgres.NewPgxInstanceLeaseRepository(pool)
	instanceID := "rotate-encryption-key/" + lease.NewInstanceID()
	out, err := leaseRepo.TryAcquire(ctx, instanceID, lease.DefaultTTL)
	if err != nil {
		fmt.Fprintln(stderr, "identuum-idp: rotate-encryption-key: lease check failed:", redactURL(err, databaseURL))
		return 1
	}
	if !out.Acquired {
		fmt.Fprintf(stderr, "identuum-idp: rotate-encryption-key: REFUSING — a process holds the single-replica instance lease (incumbent=%q). Stop the IdP first; rotation is offline-only.\n",
			out.Holder)
		return 1
	}
	defer func() {
		if relErr := leaseRepo.Release(ctx, instanceID); relErr != nil {
			fmt.Fprintln(stderr, "identuum-idp: rotate-encryption-key: lease release failed (a stale lease expires on its own):", relErr)
		}
	}()

	tx, err := pool.Begin(ctx)
	if err != nil {
		fmt.Fprintln(stderr, "identuum-idp: rotate-encryption-key: begin transaction failed:", redactURL(err, databaseURL))
		return 1
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op after a successful commit

	// UNKNOWN-SCHEMA GUARD: refuse before the first rewrite when the
	// database holds sealed columns outside the family list — converting
	// only what this build knows would half-rotate the customer's data.
	unknown, err := probeUnknownSealedColumns(ctx, tx)
	if err != nil {
		fmt.Fprintln(stderr, "identuum-idp: rotate-encryption-key: schema guard failed, zero rows changed:", err)
		return 1
	}
	if len(unknown) > 0 {
		fmt.Fprintf(stderr, "identuum-idp: rotate-encryption-key: REFUSING, zero rows changed — the schema holds sealed value(s) in column(s) this tool does not know: %s. Converting only the known families would HALF-ROTATE this database (is this an identuum-idp-oss database, and is this binary current?).\n",
			strings.Join(unknown, ", "))
		return 1
	}

	report, coreErr := rotateEncryptionKeyCore(ctx, tx, cs, newID)
	if coreErr != nil {
		fmt.Fprintf(stderr, "identuum-idp: rotate-encryption-key: ABORTED, zero rows changed (the transaction rolled back): %v\n", coreErr)
		return 1
	}
	if err := tx.Commit(ctx); err != nil {
		fmt.Fprintln(stderr, "identuum-idp: rotate-encryption-key: commit failed, zero rows changed:", err)
		return 1
	}

	total := 0
	for family, c := range report {
		fmt.Fprintf(stdout, "identuum-idp: rotate-encryption-key: %-42s converted %d, already-current %d\n", family, c.converted, c.skipped)
		total += c.converted
	}
	fmt.Fprintf(stdout, "identuum-idp: rotate-encryption-key: DONE — %d value(s) now sealed under key id %s (old key id %s is retirable)\n", total, newID, oldID)
	return 0
}

// rotateEncryptionKeyCore rewrites every sealed value inside the caller's
// transaction. It returns per-family counts, or the first error — the
// caller rolls back, so an error means zero rows changed.
func rotateEncryptionKeyCore(ctx context.Context, tx pgx.Tx, cs *crypto.CryptoService, newID string) (map[string]rotationCounts, error) {
	report := make(map[string]rotationCounts)

	for _, fam := range sealedFamilies {
		rows, err := collectKV(ctx, tx, fam.selKV)
		if err != nil {
			return nil, fmt.Errorf("%s: read: %w", fam.family, err)
		}
		var c rotationCounts
		for _, kv := range rows {
			var (
				next    string
				changed bool
			)
			if fam.json {
				// identity_providers.config carries its sealed values
				// INSIDE a JSON document.
				next, changed, err = rotateProviderConfigJSON(cs, newID, kv.v)
			} else {
				next, changed, err = rotateCiphertext(cs, newID, kv.v, fam.pemOK)
			}
			if err != nil {
				return nil, fmt.Errorf("%s (row %s): %w", fam.family, kv.k, err)
			}
			if !changed {
				c.skipped++
				continue
			}
			if _, err := tx.Exec(ctx, fam.upd, kv.k, next); err != nil {
				return nil, fmt.Errorf("%s (row %s): write: %w", fam.family, kv.k, err)
			}
			c.converted++
		}
		report[fam.family] = c
	}

	return report, nil
}

// probeUnknownSealedColumns is the UNKNOWN-SCHEMA GUARD (THE-ROTATION-
// GUARD): before any rewrite, every base-table text/varchar/json/jsonb
// column in the public schema OUTSIDE the sealedFamilies list is probed
// for values shaped like this cipher's output (v2:<16-hex-keyid>: — or
// a v1: base64 body; JSON documents are probed for embedded v2 values).
// One hit means the database holds sealed data this tool would leave
// under the retired key while printing DONE — the half-converted
// outcome the tool exists to make impossible (measured threat: a
// pre-split/CE schema's trusted_assertion_issuers.oidc_client_secret_
// encrypted, sealed by the SAME CryptoService). The caller must REFUSE,
// naming every hit. STATED LIMIT: pre-v1 bare-base64 ciphertexts carry
// no recognizable shape and cannot be probed for; a false-positive
// (an unrelated column whose text matches the v1/v2 shape) refuses
// loudly rather than converts — fail-closed is the only safe direction
// for a data-converting tool.
// The sealed-value shapes the guard probes for. Character classes only —
// identical semantics under Go regexp (unit-tested) and Postgres `~`
// (fixture-tested), so the always-running unit teeth and the live probe
// can never drift apart.
const (
	sealedV2Pattern     = `^v2:[0-9a-f]{16}:`
	sealedV1Pattern     = `^v1:[A-Za-z0-9_=+/-]+$`
	sealedJSONV2Pattern = `"v2:[0-9a-f]{16}:`
)

// guardColumn is one live-schema column the guard considers.
type guardColumn struct{ tbl, col, typ string }

// guardCandidateColumns is the guard's PURE decision: which enumerated
// columns get probed. Everything except the sealedFamilies columns — a
// family added to the shared table is auto-excluded here, and a sealed
// column that is NOT in the table is exactly what must remain a
// candidate.
func guardCandidateColumns(all []guardColumn) []guardColumn {
	known := make(map[string]bool, len(sealedFamilies))
	for _, f := range sealedFamilies {
		known[f.table+"."+f.column] = true
	}
	out := make([]guardColumn, 0, len(all))
	for _, c := range all {
		if !known[c.tbl+"."+c.col] {
			out = append(out, c)
		}
	}
	return out
}

func probeUnknownSealedColumns(ctx context.Context, tx pgx.Tx) ([]string, error) {
	cols, err := tx.Query(ctx, `
		SELECT c.table_name, c.column_name, c.data_type
		FROM information_schema.columns c
		JOIN information_schema.tables t
		  ON t.table_schema = c.table_schema AND t.table_name = c.table_name
		WHERE c.table_schema = 'public'
		  AND t.table_type = 'BASE TABLE'
		  AND c.data_type IN ('text', 'character varying', 'json', 'jsonb')
		ORDER BY c.table_name, c.column_name`)
	if err != nil {
		return nil, fmt.Errorf("schema guard: enumerate columns: %w", err)
	}
	var all []guardColumn
	for cols.Next() {
		var c guardColumn
		if err := cols.Scan(&c.tbl, &c.col, &c.typ); err != nil {
			cols.Close()
			return nil, fmt.Errorf("schema guard: scan: %w", err)
		}
		all = append(all, c)
	}
	cols.Close()
	if err := cols.Err(); err != nil {
		return nil, fmt.Errorf("schema guard: enumerate columns: %w", err)
	}

	var hits []string
	for _, c := range guardCandidateColumns(all) {
		tbl := pgx.Identifier{c.tbl}.Sanitize()
		col := pgx.Identifier{c.col}.Sanitize()
		var probe string
		if c.typ == "json" || c.typ == "jsonb" {
			probe = fmt.Sprintf(`SELECT 1 FROM %s WHERE %s::text ~ '%s' LIMIT 1`, tbl, col, sealedJSONV2Pattern)
		} else {
			probe = fmt.Sprintf(`SELECT 1 FROM %s WHERE %s ~ '%s' OR %s ~ '%s' LIMIT 1`, tbl, col, sealedV2Pattern, col, sealedV1Pattern)
		}
		var one int
		err := tx.QueryRow(ctx, probe).Scan(&one)
		switch {
		case err == nil:
			hits = append(hits, c.tbl+"."+c.col)
		case err == pgx.ErrNoRows:
			// clean column
		default:
			return nil, fmt.Errorf("schema guard: probe %s.%s: %w", c.tbl, c.col, err)
		}
	}
	return hits, nil
}

// familyKeyIDCensus is the doctor's view of one sealed family: how many
// values sit under which key id ('plaintext'/'legacy' for pre-v2
// shapes). Key ids are safe to print (crypto.deriveKeyID is a hash
// prefix, never material).
type familyKeyIDCensus struct {
	family  string
	entries []keyIDCount // ordered by kid
}

type keyIDCount struct {
	kid string
	n   int
}

// atRestKeyIDCensus runs the per-family key-id census for doctor. It
// reads over the SAME sealedFamilies table the rotation and the schema
// guard use, so the three views can never disagree about what is sealed.
type atRestKeyIDCensus struct{ db postgres.DBTX }

func (c atRestKeyIDCensus) AtRestKeyIDs(ctx context.Context) ([]familyKeyIDCensus, error) {
	out := make([]familyKeyIDCensus, 0, len(sealedFamilies))
	for _, fam := range sealedFamilies {
		rows, err := c.db.Query(ctx, fam.aggSQL)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", fam.family, err)
		}
		f := familyKeyIDCensus{family: fam.family}
		for rows.Next() {
			var e keyIDCount
			if err := rows.Scan(&e.kid, &e.n); err != nil {
				rows.Close()
				return nil, fmt.Errorf("%s: %w", fam.family, err)
			}
			f.entries = append(f.entries, e)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, fmt.Errorf("%s: %w", fam.family, err)
		}
		out = append(out, f)
	}
	return out, nil
}

type kvRow struct{ k, v string }

// collectKV drains a two-column (key, value) query fully before any
// writes run — pgx allows one active query per transaction connection.
func collectKV(ctx context.Context, tx pgx.Tx, sel string) ([]kvRow, error) {
	rows, err := tx.Query(ctx, sel)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []kvRow
	for rows.Next() {
		var kv kvRow
		if err := rows.Scan(&kv.k, &kv.v); err != nil {
			return nil, err
		}
		out = append(out, kv)
	}
	return out, rows.Err()
}

// rotateCiphertext is the per-value decision. Pure over the cipher:
//
//	""                        -> skip (nothing sealed)
//	"v2:<newID>:..."          -> skip (already under the new key — the
//	                             idempotence/resumability hinge)
//	legacy plaintext PEM      -> seal under the new key when pemOK
//	                             (finishing the P3-5 boot sweep's job)
//	anything else             -> decrypt (old key via the previous pool,
//	                             v1/legacy tried against both), re-seal
//	                             under the new key; an undecryptable
//	                             value is an ERROR, never a skip — a
//	                             value neither key opens means the wrong
//	                             old key was supplied, and continuing
//	                             would strand the row silently.
func rotateCiphertext(cs *crypto.CryptoService, newID, val string, pemOK bool) (string, bool, error) {
	if val == "" {
		return val, false, nil
	}
	if strings.HasPrefix(val, "v2:"+newID+":") {
		return val, false, nil
	}
	if pemOK && strings.HasPrefix(val, "-----BEGIN") {
		sealed, err := cs.Encrypt(val)
		if err != nil {
			return "", false, fmt.Errorf("seal legacy plaintext value: %w", err)
		}
		return sealed, true, nil
	}
	plain, err := cs.Decrypt(val)
	if err != nil {
		return "", false, fmt.Errorf("value decrypts under NEITHER the new nor the old key (wrong %s?): %w", rotateOldKeyEnv, err)
	}
	sealed, err := cs.Encrypt(plain)
	if err != nil {
		return "", false, fmt.Errorf("re-seal: %w", err)
	}
	return sealed, true, nil
}

// rotateProviderConfigJSON rewrites the two sealed fields inside one
// identity_providers.config document, preserving every other field
// byte-for-byte semantically (decode -> rotate -> re-encode).
func rotateProviderConfigJSON(cs *crypto.CryptoService, newID, rawJSON string) (string, bool, error) {
	var doc map[string]any
	if err := json.Unmarshal([]byte(rawJSON), &doc); err != nil {
		return "", false, fmt.Errorf("config is not valid JSON: %w", err)
	}
	changed := false
	for _, field := range []string{"client_secret_encrypted", "bind_password_encrypted"} {
		cur, ok := doc[field].(string)
		if !ok || cur == "" {
			continue
		}
		next, fieldChanged, err := rotateCiphertext(cs, newID, cur, false)
		if err != nil {
			return "", false, fmt.Errorf("field %s: %w", field, err)
		}
		if fieldChanged {
			doc[field] = next
			changed = true
		}
	}
	if !changed {
		return rawJSON, false, nil
	}
	out, err := json.Marshal(doc)
	if err != nil {
		return "", false, fmt.Errorf("re-encode config: %w", err)
	}
	return string(out), true, nil
}
