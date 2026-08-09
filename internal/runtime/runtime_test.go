package runtime

// Tests for the internal/runtime authority. These tests cover
// behaviour that is not directly testable through the public seam
// because it touches package-private state (the redactURL helper,
// the no-DB Config default substitution, the Done() / ServeErr()
// state machine).

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/identuum/identuum-idp-oss/internal/postgres"
)

// TestNew_DefaultsAppliedForNilStdoutStderrGetenv pins the Config
// substitution contract documented on New: nil Stdout / Stderr /
// Getenv become io.Discard / io.Discard / os.Getenv respectively.
// We verify by Start-ing and Shutdown-ing — no Stdout messages will
// reach the test framework, and resolveUIPublicBaseURLForWebAuthn
// will not panic.
func TestNew_DefaultsAppliedForNilStdoutStderrGetenv(t *testing.T) {
	rt, err := New(Config{Addr: "127.0.0.1:0"})
	require.NoError(t, err)
	require.NotNil(t, rt)
	require.Equal(t, "identuum-idp-oss (unknown version)", rt.cfg.Version)
	require.NotNil(t, rt.cfg.Stdout, "nil Stdout must become io.Discard")
	require.NotNil(t, rt.cfg.Stderr, "nil Stderr must become io.Discard")
	require.NotNil(t, rt.cfg.Getenv, "nil Getenv must become os.Getenv")
}

// TestRedactURL pins the URL-redaction contract for the no-DB path.
// Errors that embed the operator-supplied URL must surface with the
// URL replaced by a fixed sentinel. Errors that do not embed the
// URL must pass through unchanged.
func TestRedactURL(t *testing.T) {
	const url = "postgres://user:dev-user-not-a-secret@host:5432/db"

	t.Run("nil error returns nil", func(t *testing.T) {
		assert.NoError(t, redactURL(nil, url))
	})

	t.Run("empty url returns original error", func(t *testing.T) {
		err := errors.New("boom")
		assert.Equal(t, err, redactURL(err, ""))
	})

	t.Run("url substring is replaced", func(t *testing.T) {
		err := errors.New("failed to connect to " + url)
		got := redactURL(err, url)
		assert.NotContains(t, got.Error(), url)
		assert.Contains(t, got.Error(), "[redacted database url]")
	})

	t.Run("error without url passes through", func(t *testing.T) {
		err := errors.New("some other failure")
		got := redactURL(err, url)
		assert.Equal(t, err.Error(), got.Error())
	})
}

// TestStart_EmptyDBURL_ReturnsDatabaseRequiredError pins the new
// contract: there is no no-DB "scaffold" serve mode. Starting the
// runtime without a database URL is a clean pre-serve configuration
// error (a legitimate startup boundary — no panic, no degraded
// server). The error names the missing variable so an operator can fix
// it. The full service layer + full router is the only serve path.
func TestStart_EmptyDBURL_ReturnsDatabaseRequiredError(t *testing.T) {
	rt, err := New(Config{
		Addr:   "127.0.0.1:0",
		Stdout: io.Discard,
		Stderr: io.Discard,
	})
	require.NoError(t, err)

	err = rt.Start(context.Background())
	require.Error(t, err, "Start with no database URL must fail fast, not serve a scaffold")
	assert.Contains(t, err.Error(), "IDENTUUM_IDP_DATABASE_URL",
		"the error must name the missing variable so an operator can fix it; got %q", err.Error())

	// The engine was never wired (no serve path taken).
	assert.Nil(t, rt.Engine(), "no engine must be wired when the DB URL is missing")
}

// TestDone_BeforeStart pins the Done() pre-Start contract: the
// channel exists but is unbuffered and not closed. ServeErr is nil
// because the loop never ran.
func TestDone_BeforeStart(t *testing.T) {
	rt, err := New(Config{Addr: "127.0.0.1:0"})
	require.NoError(t, err)

	select {
	case <-rt.Done():
		t.Fatal("Done() must not be closed before Start")
	default:
	}
	assert.NoError(t, rt.ServeErr())
}

// TestShutdown_Idempotent pins the idempotency contract: subsequent
// Shutdown calls return the same (nil) error and do not double-close
// pools, channels, or context cancellers. We exercise the contract on a
// runtime whose Start failed at the configuration boundary (no DB URL):
// Shutdown must be a safe no-op even when no server/pool was ever wired,
// and remain safe when called repeatedly.
func TestShutdown_Idempotent(t *testing.T) {
	rt, err := New(Config{
		Addr:   "127.0.0.1:0",
		Stdout: io.Discard,
		Stderr: io.Discard,
	})
	require.NoError(t, err)

	// Start fails fast (no DB URL); srv/pool are never wired.
	require.Error(t, rt.Start(context.Background()))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	require.NoError(t, rt.Shutdown(ctx))
	// Subsequent Shutdowns are no-ops via sync.Once.
	require.NoError(t, rt.Shutdown(ctx))
	require.NoError(t, rt.Shutdown(ctx))
}

// TestStart_InvalidPort surfaces the listener-bind failure path: with a
// valid database URL the runtime wires the full service layer, then an
// obviously invalid listen address must fail at net.Listen — before the
// serve loop — and the returned error must carry the listener-failure
// context. This is an integration test: it requires a reachable
// Postgres (IDENTUUM_IDP_TEST_DATABASE_URL) because the no-DB scaffold
// mode no longer exists and the listener bind now happens after the
// (DB-backed) service layer is composed. It self-migrates the schema so
// the setup foundation initializes before the bind is attempted.
func TestStart_InvalidPort(t *testing.T) {
	dbURL := testDBURL(t)
	migrateTestSchema(t, dbURL)
	// Deterministic at-rest key so the MFA cipher wires cleanly (64 hex).
	t.Setenv("IDENTUUM_IDP_ENCRYPTION_KEY", "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
	// A-2a: this test starts a full runtime and is NOT asserting the
	// single-replica boundary. Opt out of the instance lease so it never
	// contends with other DB-backed runtime tests that share this Postgres
	// (P2-24: `make integration-test` now targets ./internal/runtime/... and
	// ./pkg/runtime/... alongside ./internal/e2e/..., so these tests DO run in
	// the gate, sharing one Postgres with e2e and each other — the lease
	// opt-out is REQUIRED, not merely defensive, or they would contend on the
	// migration-0023 single-replica instance lease).
	t.Setenv("IDENTUUM_IDP_ALLOW_MULTI_REPLICA", "true")

	rt, err := New(Config{
		Addr:      "127.0.0.1:999999", // out of range; fails fast at net.Listen
		Issuer:    "http://127.0.0.1:7113",
		JWKSDBURL: dbURL,
		DataDir:   t.TempDir(),
		Stdout:    io.Discard,
		Stderr:    io.Discard,
	})
	require.NoError(t, err)

	err = rt.Start(context.Background())
	require.Error(t, err)
	assert.True(t,
		strings.Contains(err.Error(), "listen failed") || strings.Contains(err.Error(), "invalid port"),
		"error %q must indicate listener failure", err.Error())
}

// TestStart_MetricsListener_ServesOnSeparatePort pins the core
// topological contract: /metrics is reachable on its OWN listener
// (Config.MetricsAddr), separate from the main API listener
// (Config.Addr), and the main API engine does NOT serve /metrics
// (covered independently by
// internal/api.TestNewOSSEngine_MetricsNotOnPublicRouter — this test
// proves the metrics port itself actually serves the endpoint
// end-to-end over a real TCP listener).
func TestStart_MetricsListener_ServesOnSeparatePort(t *testing.T) {
	dbURL := testDBURL(t)
	migrateTestSchema(t, dbURL)
	t.Setenv("IDENTUUM_IDP_ENCRYPTION_KEY", "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
	// A-2a: this test starts a full runtime and is NOT asserting the
	// single-replica boundary. Opt out of the instance lease so it never
	// contends with other DB-backed runtime tests that share this Postgres
	// (P2-24: `make integration-test` now targets ./internal/runtime/... and
	// ./pkg/runtime/... alongside ./internal/e2e/..., so these tests DO run in
	// the gate, sharing one Postgres with e2e and each other — the lease
	// opt-out is REQUIRED, not merely defensive, or they would contend on the
	// migration-0023 single-replica instance lease).
	t.Setenv("IDENTUUM_IDP_ALLOW_MULTI_REPLICA", "true")

	rt, err := New(Config{
		Addr:        "127.0.0.1:0",
		MetricsAddr: "127.0.0.1:0",
		Issuer:      "http://127.0.0.1:7113",
		JWKSDBURL:   dbURL,
		DataDir:     t.TempDir(),
		Stdout:      io.Discard,
		Stderr:      io.Discard,
	})
	require.NoError(t, err)

	require.NoError(t, rt.Start(context.Background()))
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = rt.Shutdown(ctx)
	}()

	require.NotEmpty(t, rt.MetricsAddr(), "metrics listener must have bound to a real address")
	require.NotEqual(t, rt.Addr(), rt.MetricsAddr(), "metrics listener must be a SEPARATE port from the main API listener")

	resp, err := http.Get("http://" + rt.MetricsAddr() + "/metrics")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	// The listener now serves REAL Prometheus exposition (audit F5 fix) —
	// never the retired placeholder string.
	assert.Contains(t, string(body), "# HELP",
		"metrics content must be real Prometheus exposition")
	assert.NotContains(t, string(body), "Prometheus exporter not yet wired",
		"the placeholder response must be gone")

	// The metrics port must NOT serve the public API surface (e.g.
	// /health) — it is a dedicated, single-purpose listener.
	resp2, err := http.Get("http://" + rt.MetricsAddr() + "/health")
	require.NoError(t, err)
	defer resp2.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp2.StatusCode, "the metrics listener must not also serve the public API surface")
}

// TestStart_MetricsListener_BindFailureDegradesGracefully pins the
// P-018 contract: if the metrics port is already in use, Start must
// NOT fail, panic, Fatal, or Exit — the main IdP must continue
// serving normally, only the metrics endpoint is unavailable.
func TestStart_MetricsListener_BindFailureDegradesGracefully(t *testing.T) {
	dbURL := testDBURL(t)
	migrateTestSchema(t, dbURL)
	t.Setenv("IDENTUUM_IDP_ENCRYPTION_KEY", "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
	// A-2a: this test starts a full runtime and is NOT asserting the
	// single-replica boundary. Opt out of the instance lease so it never
	// contends with other DB-backed runtime tests that share this Postgres
	// (P2-24: `make integration-test` now targets ./internal/runtime/... and
	// ./pkg/runtime/... alongside ./internal/e2e/..., so these tests DO run in
	// the gate, sharing one Postgres with e2e and each other — the lease
	// opt-out is REQUIRED, not merely defensive, or they would contend on the
	// migration-0023 single-replica instance lease).
	t.Setenv("IDENTUUM_IDP_ALLOW_MULTI_REPLICA", "true")

	// Occupy a port first so the runtime's metrics listener collides.
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer occupied.Close()

	var stderrBuf bytes.Buffer
	rt, err := New(Config{
		Addr:        "127.0.0.1:0",
		MetricsAddr: occupied.Addr().String(), // guaranteed collision
		Issuer:      "http://127.0.0.1:7113",
		JWKSDBURL:   dbURL,
		DataDir:     t.TempDir(),
		Stdout:      io.Discard,
		Stderr:      &stderrBuf,
	})
	require.NoError(t, err)

	// Start must succeed DESPITE the metrics-port collision — the
	// main IdP is unaffected.
	require.NoError(t, rt.Start(context.Background()))
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = rt.Shutdown(ctx)
	}()

	assert.Empty(t, rt.MetricsAddr(), "metrics listener must not be considered bound after a collision")
	assert.Contains(t, stderrBuf.String(), "metrics listener bind failed", "the bind failure must be logged")
	assert.Contains(t, stderrBuf.String(), "the IdP continues serving normally", "the log must reassure the operator the main IdP is unaffected")

	// The main API listener must still be fully functional.
	require.NotEmpty(t, rt.Addr())
	resp, err := http.Get("http://" + rt.Addr() + "/health")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode, "the main IdP must serve normally even though the metrics port collided")
}

// TestStart_MetricsAddrEmpty_NoListenerStarted pins that an empty
// Config.MetricsAddr (the zero value) disables the metrics listener
// entirely — no second port is opened. This keeps every existing
// Config{} caller/test that predates this feature behaviourally
// unchanged unless they opt in.
func TestStart_MetricsAddrEmpty_NoListenerStarted(t *testing.T) {
	dbURL := testDBURL(t)
	migrateTestSchema(t, dbURL)
	t.Setenv("IDENTUUM_IDP_ENCRYPTION_KEY", "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
	// A-2a: this test starts a full runtime and is NOT asserting the
	// single-replica boundary. Opt out of the instance lease so it never
	// contends with other DB-backed runtime tests that share this Postgres
	// (P2-24: `make integration-test` now targets ./internal/runtime/... and
	// ./pkg/runtime/... alongside ./internal/e2e/..., so these tests DO run in
	// the gate, sharing one Postgres with e2e and each other — the lease
	// opt-out is REQUIRED, not merely defensive, or they would contend on the
	// migration-0023 single-replica instance lease).
	t.Setenv("IDENTUUM_IDP_ALLOW_MULTI_REPLICA", "true")

	rt, err := New(Config{
		Addr:      "127.0.0.1:0",
		Issuer:    "http://127.0.0.1:7113",
		JWKSDBURL: dbURL,
		DataDir:   t.TempDir(),
		Stdout:    io.Discard,
		Stderr:    io.Discard,
		// MetricsAddr intentionally left empty.
	})
	require.NoError(t, err)

	require.NoError(t, rt.Start(context.Background()))
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = rt.Shutdown(ctx)
	}()

	assert.Empty(t, rt.MetricsAddr(), "no metrics listener must be started when Config.MetricsAddr is empty")
}

// migrateTestSchema applies the embedded OSS migrations against the test
// database so a DB-backed runtime can initialize. Idempotent.
func migrateTestSchema(t *testing.T, dbURL string) {
	t.Helper()
	db, err := postgres.OpenStdlibDB(dbURL)
	require.NoError(t, err)
	defer db.Close()
	_, err = postgres.RunMigrations(context.Background(), db)
	require.NoError(t, err)
}
