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

	simple := []struct {
		family string
		sel    string
		upd    string
		pemOK  bool // signing keys: a legacy plaintext PEM is sealed, not skipped
	}{
		{
			family: "signing_keys.private_key",
			sel:    `SELECT kid, private_key FROM signing_keys WHERE private_key <> ''`,
			upd:    `UPDATE signing_keys SET private_key = $2 WHERE kid = $1`,
			pemOK:  true,
		},
		{
			family: "users.mfa_secret",
			sel:    `SELECT id::text, mfa_secret FROM users WHERE mfa_secret IS NOT NULL AND mfa_secret <> ''`,
			upd:    `UPDATE users SET mfa_secret = $2 WHERE id::text = $1`,
		},
		{
			family: "mfa_pending_login_sessions.secret",
			sel:    `SELECT id::text, secret FROM mfa_pending_login_sessions WHERE secret IS NOT NULL AND secret <> ''`,
			upd:    `UPDATE mfa_pending_login_sessions SET secret = $2 WHERE id::text = $1`,
		},
		{
			family: "oidc_states.pkce_verifier_encrypted",
			sel:    `SELECT state, pkce_verifier_encrypted FROM oidc_states WHERE pkce_verifier_encrypted <> ''`,
			upd:    `UPDATE oidc_states SET pkce_verifier_encrypted = $2 WHERE state = $1`,
		},
	}

	for _, fam := range simple {
		rows, err := collectKV(ctx, tx, fam.sel)
		if err != nil {
			return nil, fmt.Errorf("%s: read: %w", fam.family, err)
		}
		var c rotationCounts
		for _, kv := range rows {
			next, changed, err := rotateCiphertext(cs, newID, kv.v, fam.pemOK)
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

	// identity_providers.config carries its sealed values INSIDE a JSON
	// document (client_secret_encrypted / bind_password_encrypted).
	rows, err := collectKV(ctx, tx, `SELECT id::text, config::text FROM identity_providers WHERE config IS NOT NULL`)
	if err != nil {
		return nil, fmt.Errorf("identity_providers.config: read: %w", err)
	}
	var c rotationCounts
	for _, kv := range rows {
		next, changed, err := rotateProviderConfigJSON(cs, newID, kv.v)
		if err != nil {
			return nil, fmt.Errorf("identity_providers.config (row %s): %w", kv.k, err)
		}
		if !changed {
			c.skipped++
			continue
		}
		if _, err := tx.Exec(ctx, `UPDATE identity_providers SET config = $2::jsonb WHERE id::text = $1`, kv.k, next); err != nil {
			return nil, fmt.Errorf("identity_providers.config (row %s): write: %w", kv.k, err)
		}
		c.converted++
	}
	report["identity_providers.config (2 sealed fields)"] = c

	return report, nil
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
