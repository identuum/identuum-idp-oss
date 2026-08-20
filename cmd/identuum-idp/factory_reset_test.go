package main

// Unit coverage for the factory-reset guard (OPERATOR-UX-1 /
// FACTORY-RESET-GUARD-1). Hermetic: every case here must terminate BEFORE
// any database is contacted, so no Postgres and no network are required —
// and that absence is itself the property under test.

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"
)

// RULE: FACTORY-RESET-GUARD-1
func TestFactoryReset_RefusesWithoutExplicitFlag(t *testing.T) {
	t.Setenv("IDENTUUM_IDP_DATABASE_URL", "")
	t.Setenv("IDENTUUM_IDP_OSS_DB", "")

	t.Run("no flag refuses BEFORE touching the database", func(t *testing.T) {
		// The positional points at a would-be-live URL. If the guard were
		// removed, dispatch would proceed to dial (a different error, a
		// different message, rc 1) — the assertions below then fail.
		var stdout, stderr bytes.Buffer
		start := time.Now()
		rc := dispatchFactoryReset(context.Background(),
			[]string{"postgres://user:dev-user-not-a-secret@127.0.0.1:1/nope?connect_timeout=1"},
			&stdout, &stderr)
		if rc != 2 {
			t.Fatalf("factory-reset without the flag exit = %d, want 2", rc)
		}
		if !strings.Contains(stderr.String(), "REFUSED") {
			t.Fatalf("refusal must say REFUSED; got %q", stderr.String())
		}
		if !strings.Contains(stderr.String(), "--i-understand-this-destroys-all-data") {
			t.Fatalf("refusal must NAME the exact confirmation flag; got %q", stderr.String())
		}
		if !strings.Contains(stderr.String(), "No database was contacted") {
			t.Fatalf("refusal must state that no database was contacted; got %q", stderr.String())
		}
		if strings.Contains(stderr.String(), "postgres://") || strings.Contains(stdout.String(), "postgres://") {
			t.Fatal("the database URL must never be printed")
		}
		if elapsed := time.Since(start); elapsed > 2*time.Second {
			t.Fatalf("refusal took %s — it must return without any dial", elapsed)
		}
	})

	t.Run("no flag and no URL still refuses on the flag, not the URL", func(t *testing.T) {
		// The guard runs FIRST: with neither flag nor DSN, the message is the
		// destruction refusal, not the missing-URL usage error.
		var stdout, stderr bytes.Buffer
		rc := dispatchFactoryReset(context.Background(), nil, &stdout, &stderr)
		if rc != 2 {
			t.Fatalf("exit = %d, want 2", rc)
		}
		if !strings.Contains(stderr.String(), "REFUSED") {
			t.Fatalf("the flag guard must fire before URL resolution; got %q", stderr.String())
		}
	})

	t.Run("flag present but no DSN anywhere is the usage refusal", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		rc := dispatchFactoryReset(context.Background(),
			[]string{"--i-understand-this-destroys-all-data"}, &stdout, &stderr)
		if rc != 2 {
			t.Fatalf("exit = %d, want 2", rc)
		}
		if !strings.Contains(stderr.String(), "IDENTUUM_IDP_DATABASE_URL") {
			t.Fatalf("usage refusal must name the env fallback; got %q", stderr.String())
		}
	})

	t.Run("extra positionals are rejected", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		rc := dispatchFactoryReset(context.Background(),
			[]string{"--i-understand-this-destroys-all-data", "postgres://x", "stray"}, &stdout, &stderr)
		if rc != 2 {
			t.Fatalf("exit = %d, want 2", rc)
		}
	})
}
