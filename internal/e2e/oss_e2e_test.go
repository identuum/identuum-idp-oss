//go:build integration

// Package e2e provides OSS integration tests for the identuum-idp-oss
// smoke + discovery surface.
//
// Prerequisites:
//   - Set IDENTUUM_IDP_TEST_DATABASE_URL (or IDENTUUM_IDP_DATABASE_URL)
//     to a Postgres connection string. The test applies OSS migrations
//     automatically before each test.
//   - The integration tag means these tests were explicitly requested.
//     If neither env var is set, tests FAIL LOUDLY (t.Fatalf) rather
//     than skip — a silent skip under -tags integration would report
//     "ok" while proving nothing. make integration-test / make
//     verify-oss supply the DSN automatically (see Makefile).
//
// Run:
//
//	go test -tags integration -v ./internal/e2e/...
//
// Safety:
//   - No raw tokens, IDs, cookies, signing-key material, or DB URLs are
//     logged, persisted, or echoed.
//   - JWKS / discovery assertions are structural only.
//   - The DB URL is sourced from env and never appears in any assertion
//     message, log line, or t.Errorf body.
package e2e

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/identuum/identuum-idp-oss/internal/crypto"
	"github.com/identuum/identuum-idp-oss/internal/postgres"
	"github.com/identuum/identuum-idp-oss/internal/server"
)

// e2eSigningKeyCipher returns a throwaway P3-5 at-rest cipher for the e2e
// repository aggregate (32-byte hex key). The hex is a valid key, so the
// error is ignored. Tests that never touch signing keys are unaffected; those
// that create/read them get a working cipher.
func e2eSigningKeyCipher() postgres.PrivateKeyCipher {
	cs, _ := crypto.NewCryptoService("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
	return cs
}

// testDBURL returns the integration-test DB URL. The integration build
// tag means these tests were explicitly requested, so a missing DSN is
// a hard failure (P2-20) — NOT a skip. A silent skip here would let
// `go test -tags integration ./...` print "ok" while running nothing.
// The returned URL is treated as a credential by the rest of the test —
// it is passed only into postgres.OpenStdlibDB / postgres.NewPool and
// is never echoed.
func testDBURL(t *testing.T) string {
	t.Helper()
	for _, env := range []string{"IDENTUUM_IDP_TEST_DATABASE_URL", "IDENTUUM_IDP_DATABASE_URL"} {
		if v := os.Getenv(env); v != "" {
			return v
		}
	}
	t.Fatalf("IDENTUUM_IDP_TEST_DATABASE_URL (or IDENTUUM_IDP_DATABASE_URL) is not set; " +
		"integration tests were requested via -tags integration and require a live Postgres DSN. " +
		"`make integration-test` / `make verify-oss` supply it automatically (Makefile); " +
		"to run manually, export IDENTUUM_IDP_TEST_DATABASE_URL yourself")
	return ""
}

// applyMigrations opens a stdlib DB, runs the OSS migration set, and
// closes the DB. Errors are redacted — the DB URL is NEVER part of any
// error message or test assertion.
func applyMigrations(t *testing.T, dbURL string) {
	t.Helper()
	db, err := postgres.OpenStdlibDB(dbURL)
	if err != nil {
		t.Fatalf("open stdlib db: error returned (URL redacted): %v", classifyOpenError(err))
	}
	defer func() { _ = db.Close() }()

	results, err := postgres.RunMigrations(context.Background(), db)
	if err != nil {
		t.Fatalf("run migrations: error returned (URL redacted): %v", classifyMigrationError(err))
	}
	applied := 0
	for _, r := range results {
		if r.Applied {
			applied++
		}
	}
	t.Logf("oss e2e: migrations: applied=%d of %d embedded", applied, len(results))
}

// classifyOpenError converts a postgres.OpenStdlibDB error into a
// structural category string. The original error may carry the DB URL
// verbatim; we deliberately discard the message.
func classifyOpenError(err error) string {
	if err == nil {
		return "<nil>"
	}
	return "open-stdlib-db-failed"
}

// classifyMigrationError is the same idea for migration failures.
func classifyMigrationError(err error) string {
	if err == nil {
		return "<nil>"
	}
	return "run-migrations-failed"
}

// TestE2E_OSS_HealthAndDiscovery validates the OSS smoke handler end-to-end:
//   - /healthz returns 200 + JSON status=ok
//   - /livez returns 200 + JSON status=alive
//   - /.well-known/openid-configuration advertises issuer + endpoints +
//     code-only response_types_supported + EdDSA/ES256 only (no RS256, no none)
//   - /.well-known/jwks.json returns {"keys":[]} (empty JWKS — fresh DB
//     has no signing keys yet) and NEVER contains "PRIVATE KEY" or
//     `"d":` (the RFC 7518 private exponent field name).
func TestE2E_OSS_HealthAndDiscovery(t *testing.T) {
	dbURL := testDBURL(t)
	applyMigrations(t, dbURL)

	// The smoke handler does not need the DB pool for any of these
	// endpoints (JWKS uses EmptyJWKSProvider). The DB-backed JWKS path
	// is exercised by a separate test below.
	const issuer = "http://localhost:7113"
	h := server.NewSmokeHandlerWithJWKS(
		server.OIDCDiscoveryConfig{Issuer: issuer},
		server.EmptyJWKSProvider{},
	)

	ts := httptest.NewServer(h)
	t.Cleanup(ts.Close)

	t.Run("healthz", func(t *testing.T) {
		body := mustGetJSON(t, ts.URL+"/healthz")
		if status, _ := body["status"].(string); status != "ok" {
			t.Fatalf("healthz: status: want=ok got=%q", status)
		}
	})

	t.Run("livez", func(t *testing.T) {
		body := mustGetJSON(t, ts.URL+"/livez")
		if status, _ := body["status"].(string); status != "alive" {
			t.Fatalf("livez: status: want=alive got=%q", status)
		}
	})

	t.Run("discovery", func(t *testing.T) {
		body := mustGetJSON(t, ts.URL+"/.well-known/openid-configuration")
		// Issuer is exactly what we configured (no trailing slash —
		// server.resolveDiscovery trims it).
		if iss, _ := body["issuer"].(string); iss != issuer {
			t.Fatalf("discovery: issuer: want=%q got=%q", issuer, iss)
		}
		// Endpoints must be derived from issuer.
		for _, ep := range []string{"authorization_endpoint", "token_endpoint", "jwks_uri"} {
			v, _ := body[ep].(string)
			if !strings.HasPrefix(v, issuer) {
				t.Fatalf("discovery: %s: must start with %q (got: <redacted-or-empty>)", ep, issuer)
			}
		}
		// response_types_supported MUST be ["code"] only.
		got := asStringSlice(body["response_types_supported"])
		if len(got) != 1 || got[0] != "code" {
			t.Fatalf("discovery: response_types_supported: want=[code] got=%v", got)
		}
		// id_token_signing_alg_values_supported MUST contain EdDSA +
		// ES256 and MUST NOT contain RS256 or none.
		algs := asStringSlice(body["id_token_signing_alg_values_supported"])
		ms := map[string]bool{}
		for _, a := range algs {
			ms[a] = true
		}
		if !ms["EdDSA"] || !ms["ES256"] {
			t.Fatalf("discovery: id_token_signing_alg_values_supported: want EdDSA+ES256 got=%v", algs)
		}
		if ms["RS256"] || ms["none"] {
			t.Fatalf("discovery: RS256 or none must NOT be advertised; got=%v", algs)
		}
		// subject_types_supported MUST contain "public".
		subj := asStringSlice(body["subject_types_supported"])
		hasPublic := false
		for _, s := range subj {
			if s == "public" {
				hasPublic = true
			}
		}
		if !hasPublic {
			t.Fatalf("discovery: subject_types_supported: must include public; got=%v", subj)
		}
	})

	t.Run("jwks_no_private_material", func(t *testing.T) {
		raw := mustGetRawBody(t, ts.URL+"/.well-known/jwks.json")
		// Structural: must parse as an object with a "keys" array.
		var body struct {
			Keys []map[string]any `json:"keys"`
		}
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Fatalf("jwks: parse failed: %v", err)
		}
		// EmptyJWKSProvider returns {"keys":[]} on a fresh deployment.
		if len(body.Keys) != 0 {
			t.Fatalf("jwks: empty provider must return 0 keys; got=%d", len(body.Keys))
		}
		// Privacy invariants. These checks scan the RAW body bytes for
		// substrings — defence in depth in case any future provider
		// ever accidentally encodes private material.
		// Substring "PRIVATE KEY" appears in any PEM private key block.
		if bytesContainCaseInsensitive(raw, []byte("PRIVATE KEY")) {
			t.Fatalf("jwks: response body must NOT contain a PEM private key block")
		}
		// RFC 7518 JWK private exponent field is "d". Forbid the
		// exact JSON occurrence `"d":` — note that EdDSA + EC public
		// keys use "x" / "y" / "crv" / "kty" only.
		if bytesContain(raw, []byte(`"d":`)) {
			t.Fatalf(`jwks: response body must NOT contain the JWK "d" private field`)
		}
	})
}

// TestE2E_OSS_MigrationsIdempotent applies migrations twice in a row
// against the same DB and asserts the second pass reports zero new
// applications. This validates the goose session lock works AND the
// migration set is self-consistent.
func TestE2E_OSS_MigrationsIdempotent(t *testing.T) {
	dbURL := testDBURL(t)
	// First pass — applies whatever is pending.
	applyMigrations(t, dbURL)
	// Second pass — must be a no-op.
	db, err := postgres.OpenStdlibDB(dbURL)
	if err != nil {
		t.Fatalf("open stdlib db: %v", classifyOpenError(err))
	}
	defer func() { _ = db.Close() }()
	results, err := postgres.RunMigrations(context.Background(), db)
	if err != nil {
		t.Fatalf("second migration pass: %v", classifyMigrationError(err))
	}
	applied := 0
	for _, r := range results {
		if r.Applied {
			applied++
		}
	}
	if applied != 0 {
		t.Fatalf("second migration pass must be no-op; got applied=%d of %d", applied, len(results))
	}
}

// TestE2E_OSS_PoolSentinel exercises the pgxpool factory against the
// dev DB and runs the same sentinel query as the --db-check CLI
// surface. Proves the OSS code path can talk to its own Postgres.
func TestE2E_OSS_PoolSentinel(t *testing.T) {
	dbURL := testDBURL(t)
	applyMigrations(t, dbURL)

	ctx := context.Background()
	pool, err := postgres.NewPool(ctx, dbURL, nil)
	if err != nil {
		t.Fatalf("open pool: %v", classifyOpenError(err))
	}
	defer pool.Close()

	repos := postgres.NewPgxRepositories(pool, e2eSigningKeyCipher())
	if repos == nil || repos.User == nil {
		t.Fatalf("repository factory returned nil")
	}

	var dbName string
	if err := pool.QueryRow(ctx, "SELECT current_database()").Scan(&dbName); err != nil {
		t.Fatalf("sentinel query failed: %v", err)
	}
	if dbName == "" {
		t.Fatalf("sentinel query returned empty database name")
	}
	// Sentinel db name is the DB selected by the URL — non-secret;
	// safe to log for operator visibility (same posture as --db-check).
	t.Logf("oss e2e: pool: ok (database=%q, repositories=%d)", dbName, postgresRepositoryFieldCount())
}

// --- helpers ---

// postgresRepositoryFieldCount mirrors the constant used by the CLI to
// surface the number of repositories on postgres.Repositories. Kept as
// a small package-local helper so the test never needs to import a
// CLI-internal value.
func postgresRepositoryFieldCount() int { return 19 }

func mustGetJSON(t *testing.T, url string) map[string]any {
	t.Helper()
	raw := mustGetRawBody(t, url)
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("GET %s: parse: %v", url, err)
	}
	return body
}

func mustGetRawBody(t *testing.T, url string) []byte {
	t.Helper()
	resp, err := http.Get(url) // #nosec G107 -- httptest.Server URL only
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: status: want=200 got=%d", url, resp.StatusCode)
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("GET %s: read body: %v", url, err)
	}
	return raw
}

func asStringSlice(v any) []string {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, e := range arr {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func bytesContain(haystack, needle []byte) bool {
	return indexOf(haystack, needle) >= 0
}

func bytesContainCaseInsensitive(haystack, needle []byte) bool {
	return indexOf(lower(haystack), lower(needle)) >= 0
}

func lower(b []byte) []byte {
	out := make([]byte, len(b))
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		out[i] = c
	}
	return out
}

func indexOf(haystack, needle []byte) int {
	if len(needle) == 0 {
		return 0
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		match := true
		for j := 0; j < len(needle); j++ {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}
