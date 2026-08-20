package main

import (
	"bytes"
	"strings"
	"testing"
)

// These tests pin the public-release CLI contract (see
// docs/audit/release-readiness/oss-cli-flag-audit.md and the
// oss-cli-simplification changelog):
//
//   - The default action (no subcommand) serves the full IdP; with no
//     database URL configured it exits non-zero naming the missing var.
//   - The operator one-shots are subcommands: migrate, bootstrap,
//     recover-site-admin, show-setup-code.
//   - The split-era flags (--gin-serve, --jwks-db, --serve, --db-check,
//     --print-license-info, --check-feature, --get-limit, --oss-smoke*)
//     are removed and now error as unknown.

// --version prints the build version and exits 0, via both the flag and
// the subcommand spellings.
func TestRun_Version(t *testing.T) {
	for _, args := range [][]string{{"--version"}, {"version"}} {
		var stdout, stderr bytes.Buffer
		code := run(args, &stdout, &stderr)
		if code != 0 {
			t.Fatalf("run(%v) exit = %d, want 0 (stderr=%q)", args, code, stderr.String())
		}
		if !strings.Contains(stdout.String(), "identuum-idp-oss") {
			t.Fatalf("run(%v) stdout = %q, want the version string", args, stdout.String())
		}
	}
}

// No subcommand + no database URL configured → clean non-zero exit that
// NAMES the missing variable (a legitimate pre-serve startup boundary,
// not a silent scaffold and not a panic).
func TestRun_NoDatabaseURL_CleanExitNamingVar(t *testing.T) {
	t.Setenv("IDENTUUM_IDP_DATABASE_URL", "")
	var stdout, stderr bytes.Buffer
	code := run(nil, &stdout, &stderr)
	if code == 0 {
		t.Fatalf("run() with no DB URL must exit non-zero; got 0 (stdout=%q)", stdout.String())
	}
	if !strings.Contains(stderr.String(), "IDENTUUM_IDP_DATABASE_URL") {
		t.Fatalf("missing-DB error must name IDENTUUM_IDP_DATABASE_URL; stderr=%q", stderr.String())
	}
}

// --issuer set but no database URL also exits non-zero naming the var.
func TestRun_EmptyDatabaseURLFlag_CleanExit(t *testing.T) {
	t.Setenv("IDENTUUM_IDP_DATABASE_URL", "")
	var stdout, stderr bytes.Buffer
	code := run([]string{"--issuer", "http://localhost:7113"}, &stdout, &stderr)
	if code == 0 {
		t.Fatalf("run(--issuer ...) with no DB URL must exit non-zero; got 0")
	}
	if !strings.Contains(stderr.String(), "IDENTUUM_IDP_DATABASE_URL") {
		t.Fatalf("error must name IDENTUUM_IDP_DATABASE_URL; stderr=%q", stderr.String())
	}
}

// Every removed split-era flag now errors as unknown (exit 2). This is
// the negative side of the simplification contract.
func TestRun_RemovedFlagsErrorAsUnknown(t *testing.T) {
	t.Setenv("IDENTUUM_IDP_DATABASE_URL", "")
	removed := [][]string{
		{"--gin-serve", "127.0.0.1:7113"},
		{"--jwks-db", "postgres://x"},
		{"--serve", "127.0.0.1:7113"},
		{"--db-check", "postgres://x"},
		{"--print-license-info"},
		{"--check-feature", "mfa"},
		{"--get-limit", "limit_users"},
		{"--oss-smoke", "http://x"},
		{"--oss-smoke-verbose"},
		{"--oss-smoke-deep"},
	}
	for _, args := range removed {
		var stdout, stderr bytes.Buffer
		code := run(args, &stdout, &stderr)
		if code != 2 {
			t.Errorf("run(%v) exit = %d, want 2 (removed flag must error as unknown); stderr=%q", args, code, stderr.String())
		}
	}
}

// An unknown subcommand exits 2 and prints usage.
func TestRun_UnknownSubcommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"frobnicate"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("unknown subcommand exit = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "unknown subcommand") {
		t.Fatalf("stderr should mention the unknown subcommand; got %q", stderr.String())
	}
}

// help prints the usage summary listing the subcommands and the default
// serve action.
func TestRun_HelpListsSubcommands(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"help"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("help exit = %d, want 0", code)
	}
	out := stdout.String()
	for _, want := range []string{"migrate", "bootstrap", "recover-site-admin", "show-setup-code", "serve the full OSS IdP"} {
		if !strings.Contains(out, want) {
			t.Errorf("usage must mention %q; got %q", want, out)
		}
	}
}

// The migrate subcommand requires exactly one <database-url> argument.
func TestRun_MigrateSubcommand_RequiresURL(t *testing.T) {
	var stdout, stderr bytes.Buffer
	// Isolate the env: the subcommands now fall back to these when no
	// positional is given, and this test is about the NOTHING-provided case.
	t.Setenv("IDENTUUM_IDP_DATABASE_URL", "")
	t.Setenv("IDENTUUM_IDP_OSS_DB", "")
	code := run([]string{"migrate"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("migrate with no URL exit = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "database-url") {
		t.Fatalf("stderr should explain the missing <database-url>; got %q", stderr.String())
	}
}

// The operator subcommands accept the database URL from the environment when
// no positional is given — the appliance's own precedence (DATABASE_URL, then
// OSS_DB). This is what lets `docker exec <container> identuum-idp bootstrap`
// work against the distroless runtime image, which has no shell to expand the
// container's env into an argument.
// RULE: DSN-DEFAULT-1
func TestRequirePositionalURL_EnvFallback(t *testing.T) {
	discard := &bytes.Buffer{}

	t.Run("positional wins over env", func(t *testing.T) {
		t.Setenv("IDENTUUM_IDP_DATABASE_URL", "postgres://env/should-lose")
		got, ok := requirePositionalURL("bootstrap", []string{"postgres://arg/wins"}, discard)
		if !ok || got != "postgres://arg/wins" {
			t.Fatalf("got %q ok=%v; the explicit argument must win", got, ok)
		}
	})
	t.Run("IDENTUUM_IDP_DATABASE_URL fills an absent positional", func(t *testing.T) {
		t.Setenv("IDENTUUM_IDP_DATABASE_URL", "postgres://env/primary")
		t.Setenv("IDENTUUM_IDP_OSS_DB", "postgres://env/secondary")
		got, ok := requirePositionalURL("bootstrap", nil, discard)
		if !ok || got != "postgres://env/primary" {
			t.Fatalf("got %q ok=%v; want the primary env var", got, ok)
		}
	})
	t.Run("IDENTUUM_IDP_OSS_DB is the second choice", func(t *testing.T) {
		t.Setenv("IDENTUUM_IDP_DATABASE_URL", "")
		t.Setenv("IDENTUUM_IDP_OSS_DB", "postgres://env/secondary")
		got, ok := requirePositionalURL("recover-site-admin", nil, discard)
		if !ok || got != "postgres://env/secondary" {
			t.Fatalf("got %q ok=%v; want the compose-shaped env var", got, ok)
		}
	})
	t.Run("nothing anywhere is still refused", func(t *testing.T) {
		t.Setenv("IDENTUUM_IDP_DATABASE_URL", "")
		t.Setenv("IDENTUUM_IDP_OSS_DB", "")
		var stderr bytes.Buffer
		if _, ok := requirePositionalURL("bootstrap", nil, &stderr); ok {
			t.Fatal("no positional and no env must refuse")
		}
		if !strings.Contains(stderr.String(), "IDENTUUM_IDP_DATABASE_URL") {
			t.Fatalf("the refusal must name the env fallback; got %q", stderr.String())
		}
	})
	t.Run("flags are still rejected", func(t *testing.T) {
		if _, ok := requirePositionalURL("bootstrap", []string{"--database-url=x"}, discard); ok {
			t.Fatal("flag-shaped arguments must still be refused")
		}
	})
}

// The migrate subcommand never prints the operator-supplied URL or its
// credentials, even on failure. Uses an unreachable host that fails
// fast so the test does not block.
func TestRun_MigrateSubcommand_RedactsURL(t *testing.T) {
	const url = "postgres://user:dev-user-not-a-secret@127.0.0.1:1/nope?sslmode=disable&connect_timeout=1"
	var stdout, stderr bytes.Buffer
	code := run([]string{"migrate", url}, &stdout, &stderr)
	if code == 0 {
		t.Fatalf("migrate against an unreachable DB must fail; got 0")
	}
	combined := stdout.String() + stderr.String()
	// PREMISE: a failing migrate must SAY SO. A silent failure has no output
	// to leak, so the sweep below would pass vacuously — and the operator
	// would get a non-zero exit with no explanation, a defect of its own (V4).
	if combined == "" {
		t.Fatalf("migrate failed with rc=%d and printed NOTHING — an empty transcript cannot leak, so the redaction sweep below would prove nothing", code)
	}
	for _, secret := range []string{url, "dev-user-not-a-secret", "user:dev-user-not-a-secret"} {
		if strings.Contains(combined, secret) {
			t.Fatalf("migrate output leaked %q; output=%q", secret, combined)
		}
	}
}

// bootstrap and recover-site-admin require a <database-url> argument and
// reject a missing one before touching any database or secret.
func TestRun_OperatorSubcommands_RequireURL(t *testing.T) {
	for _, sub := range []string{"bootstrap", "recover-site-admin"} {
		var stdout, stderr bytes.Buffer
		code := run([]string{sub}, &stdout, &stderr)
		if code != 2 {
			t.Errorf("%s with no URL exit = %d, want 2; stderr=%q", sub, code, stderr.String())
		}
	}
}

// show-setup-code requires a <data-dir> argument.
func TestRun_ShowSetupCode_RequiresDataDir(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"show-setup-code"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("show-setup-code with no data-dir exit = %d, want 2", code)
	}
}

// An unknown serve flag errors as unknown (exit 2).
func TestRun_UnknownFlag(t *testing.T) {
	t.Setenv("IDENTUUM_IDP_DATABASE_URL", "")
	var stdout, stderr bytes.Buffer
	code := run([]string{"--definitely-not-a-flag"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("unknown flag exit = %d, want 2", code)
	}
}
