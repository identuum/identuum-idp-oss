package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/identuum/identuum-idp-oss/internal/lifecycle"
)

// dbwait.go — FUNC-M9: a database that does not answer at boot no longer
// ends the process. The binary waits for it, NOT-SERVING meanwhile (P-018):
// the listen address answers /livez 200, /health 503 not_serving with the
// fault, and every other route 503; once the database answers, the
// placeholder steps aside and the normal boot (migrate, serve) continues.
// Before, the bare binary exited 1 and stayed down after the database came
// back, and the compose install crash-looped.

// DatabaseWaitOptions parameterises WaitForDatabase. Zero values take the
// defaults.
type DatabaseWaitOptions struct {
	// Listen is the address the NOT-SERVING surface answers on while the
	// wait lasts; empty serves nothing.
	Listen string
	// Version is reported by /health.
	Version string
	// Stderr receives the operator-visible lines. The database URL never
	// reaches it.
	Stderr io.Writer
	// Ping checks the database; nil opens one pgx connection to the URL.
	Ping func(ctx context.Context) error
	// MaxInterval caps the retry interval (default 30s); it starts at 1s
	// and doubles.
	MaxInterval time.Duration
}

// WaitForDatabase is WaitForDatabase for this runtime's database, listen
// address and version. Call it before Start (and before migrating): New
// opens nothing.
func (r *Runtime) WaitForDatabase(ctx context.Context) error {
	if r.cfg.JWKSDBURL == "" {
		return nil // no database configured: nothing to wait for
	}
	return WaitForDatabase(ctx, r.cfg.JWKSDBURL, DatabaseWaitOptions{Listen: r.cfg.Addr, Version: r.cfg.Version, Stderr: r.cfg.Stderr})
}

const databaseFaultReason = "the database does not answer; the IdP keeps retrying and starts serving when it does"

// WaitForDatabase returns once the database answers, or with ctx's error when
// ctx ends first. While it waits it serves the NOT-SERVING surface on
// opts.Listen.
func WaitForDatabase(ctx context.Context, databaseURL string, opts DatabaseWaitOptions) error {
	ping := opts.Ping
	if ping == nil {
		ping = func(ctx context.Context) error { return pingDatabase(ctx, databaseURL) }
	}
	stderr := opts.Stderr
	if stderr == nil {
		stderr = io.Discard
	}
	maxInterval := opts.MaxInterval
	if maxInterval <= 0 {
		maxInterval = 30 * time.Second
	}
	if ping(ctx) == nil {
		return nil
	}
	fmt.Fprintf(stderr, "identuum-idp: NOT-SERVING — the database does not answer at boot; retrying (up to every %s) and serving /livez and /health meanwhile\n", maxInterval)
	stop := serveNotServing(opts.Listen, opts.Version, stderr)
	defer stop()
	interval := time.Second
	for attempt := 1; ; attempt++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(interval):
		}
		if ping(ctx) == nil {
			fmt.Fprintf(stderr, "identuum-idp: the database answers after %d retries; starting\n", attempt)
			return nil
		}
		if attempt%10 == 0 {
			fmt.Fprintf(stderr, "identuum-idp: NOT-SERVING — the database still does not answer (%d retries)\n", attempt)
		}
		interval = min(interval*2, maxInterval)
	}
}

// pingDatabase opens one connection and pings it. Its error never carries
// the URL to an output: callers print only that the database does not answer.
func pingDatabase(ctx context.Context, databaseURL string) error {
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	conn, err := pgx.Connect(cctx, databaseURL)
	if err != nil {
		return errors.New("database unreachable")
	}
	defer conn.Close(context.Background())
	if err := conn.Ping(cctx); err != nil {
		return errors.New("database unreachable")
	}
	return nil
}

// serveNotServing answers on listen until the returned stop is called. A
// listen address that cannot be bound is reported and nothing is served.
func serveNotServing(listen, version string, stderr io.Writer) (stop func()) {
	if listen == "" {
		return func() {}
	}
	l, err := net.Listen("tcp", listen)
	if err != nil {
		fmt.Fprintf(stderr, "identuum-idp: NOT-SERVING surface not started (listen %s): %v\n", listen, err)
		return func() {}
	}
	report := lifecycle.NewStartupReport()
	report.Fatal("database", databaseFaultReason)
	writeJSON := func(w http.ResponseWriter, status int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(v)
	}
	mux := http.NewServeMux()
	alive := func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"status": "alive"})
	}
	// Liveness answers as the real server's does; /readyz and every other
	// route fall to the 503 below, so the image's healthcheck reads unhealthy.
	mux.HandleFunc("/livez", alive)
	mux.HandleFunc("/healthz", alive)
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"status": "not_serving", "version": version, "mode": "oss", "tier": "starter", "faults": report.Faults(),
		})
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "not_serving", "reason": databaseFaultReason})
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(l) }()
	return func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}
}
