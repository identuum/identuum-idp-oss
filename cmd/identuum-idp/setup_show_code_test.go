package main

// Unit tests for the appliance --show-setup-code support command after
// the 2026-06-13 hardening pass. The command is now DB-aware: the
// database is the authority for "is setup complete?", and a stale
// $DATA_DIR/setup-token.txt left behind after completion must NOT cause
// the plaintext to be revealed. The on-disk file is consulted only
// while the DB still reports status='setup_required'.

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// stubLoader returns a setupStateLoader that always returns the given
// state and error pair. Used in place of a real Postgres pool.
func stubLoader(state *domain.SetupState, err error) setupStateLoader {
	return func(ctx context.Context) (*domain.SetupState, error) {
		return state, err
	}
}

func stateRequired() *domain.SetupState {
	return &domain.SetupState{
		ID:        domain.SetupStateSingletonID,
		Status:    domain.SetupStatusRequired,
		UpdatedAt: time.Now().UTC(),
	}
}

func stateComplete() *domain.SetupState {
	now := time.Now().UTC()
	return &domain.SetupState{
		ID:          domain.SetupStateSingletonID,
		Status:      domain.SetupStatusComplete,
		CompletedAt: &now,
		UpdatedAt:   now,
	}
}

func seedTokenFile(t *testing.T, dir, plaintext string) {
	t.Helper()
	path := filepath.Join(dir, "setup-token.txt")
	if err := os.WriteFile(path, []byte(plaintext+"\n"), 0o600); err != nil {
		t.Fatalf("seed file: %v", err)
	}
}

func TestRunShowSetupCode_SetupRequiredWithValidFile_Prints(t *testing.T) {
	dir := t.TempDir()
	seedTokenFile(t, dir, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQRST")

	var stdout, stderr bytes.Buffer
	rc := runShowSetupCode(context.Background(), dir, stubLoader(stateRequired(), nil), &stdout, &stderr)
	if rc != 0 {
		t.Fatalf("rc = %d; want 0; stderr=%q", rc, stderr.String())
	}
	if got := strings.TrimRight(stdout.String(), "\n"); got != "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQRST" {
		t.Errorf("stdout = %q; want the plaintext setup code", got)
	}
	if stderr.Len() != 0 {
		t.Errorf("stderr should be empty on the happy path; got %q", stderr.String())
	}
}

// RULE: SETUP-CODE-1
func TestRunShowSetupCode_SetupCompleteRefusesEvenWithStaleFile(t *testing.T) {
	dir := t.TempDir()
	// Stale file left behind from a partial setup-completion run.
	seedTokenFile(t, dir, "STALE-PLAINTEXT-MUST-NOT-LEAK")

	var stdout, stderr bytes.Buffer
	rc := runShowSetupCode(context.Background(), dir, stubLoader(stateComplete(), nil), &stdout, &stderr)
	if rc == 0 {
		t.Fatalf("rc = 0; want non-zero refusal after setup completion")
	}
	if rc != 2 {
		t.Errorf("rc = %d; want 2", rc)
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout must NOT print the stale token; got %q", stdout.String())
	}
	if strings.Contains(stdout.String(), "STALE-PLAINTEXT-MUST-NOT-LEAK") || strings.Contains(stderr.String(), "STALE-PLAINTEXT-MUST-NOT-LEAK") {
		t.Errorf("stale plaintext leaked into output: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "setup is already complete") {
		t.Errorf("stderr missing 'setup is already complete' diagnostic; got %q", stderr.String())
	}
}

func TestRunShowSetupCode_SetupCompleteRefusesWithMissingFile(t *testing.T) {
	dir := t.TempDir()

	var stdout, stderr bytes.Buffer
	rc := runShowSetupCode(context.Background(), dir, stubLoader(stateComplete(), nil), &stdout, &stderr)
	if rc != 2 {
		t.Errorf("rc = %d; want 2", rc)
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout must be empty; got %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "setup is already complete") {
		t.Errorf("stderr missing 'setup is already complete' diagnostic; got %q", stderr.String())
	}
}

func TestRunShowSetupCode_SetupRequiredButFileMissing(t *testing.T) {
	dir := t.TempDir()

	var stdout, stderr bytes.Buffer
	rc := runShowSetupCode(context.Background(), dir, stubLoader(stateRequired(), nil), &stdout, &stderr)
	if rc != 2 {
		t.Errorf("rc = %d; want 2", rc)
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout must be empty; got %q", stdout.String())
	}
	// Must mention the missing file path and how to recover by re-running setup.
	msg := stderr.String()
	if !strings.Contains(msg, "setup-token.txt") {
		t.Errorf("stderr missing token-file path hint; got %q", msg)
	}
	if !strings.Contains(msg, "restart") {
		t.Errorf("stderr missing recovery hint (expected 'restart' guidance); got %q", msg)
	}
}

func TestRunShowSetupCode_NilLoaderIsConfigurationError(t *testing.T) {
	dir := t.TempDir()
	seedTokenFile(t, dir, "DOES-NOT-MATTER")

	var stdout, stderr bytes.Buffer
	rc := runShowSetupCode(context.Background(), dir, nil, &stdout, &stderr)
	if rc != 2 {
		t.Errorf("rc = %d; want 2", rc)
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout must be empty; got %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "database") {
		t.Errorf("stderr missing 'database' configuration hint; got %q", stderr.String())
	}
}

func TestRunShowSetupCode_LoaderErrorIsExit1(t *testing.T) {
	dir := t.TempDir()
	seedTokenFile(t, dir, "DOES-NOT-MATTER")

	loaderErr := errors.New("connect: connection refused")
	var stdout, stderr bytes.Buffer
	rc := runShowSetupCode(context.Background(), dir, stubLoader(nil, loaderErr), &stdout, &stderr)
	if rc != 1 {
		t.Errorf("rc = %d; want 1 on DB-side error", rc)
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout must be empty; got %q", stdout.String())
	}
}

// --- Preserved data-dir hygiene tests (zero-DB pre-checks) -------------

func TestRunShowSetupCode_EmptyDataDirArgIs2(t *testing.T) {
	var stdout, stderr bytes.Buffer
	rc := runShowSetupCode(context.Background(), "", stubLoader(stateRequired(), nil), &stdout, &stderr)
	if rc != 2 {
		t.Errorf("rc = %d; want 2", rc)
	}
}

func TestRunShowSetupCode_MissingDataDirExits2(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "does-not-exist")
	var stdout, stderr bytes.Buffer
	rc := runShowSetupCode(context.Background(), dir, stubLoader(stateRequired(), nil), &stdout, &stderr)
	if rc != 2 {
		t.Errorf("rc = %d; want 2", rc)
	}
	if !strings.Contains(stderr.String(), "data dir does not exist") {
		t.Errorf("stderr missing diagnostic message: %q", stderr.String())
	}
}

func TestRunShowSetupCode_FileAsDataDirIs2(t *testing.T) {
	parent := t.TempDir()
	path := filepath.Join(parent, "not-a-dir")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	var stdout, stderr bytes.Buffer
	rc := runShowSetupCode(context.Background(), path, stubLoader(stateRequired(), nil), &stdout, &stderr)
	if rc != 2 {
		t.Errorf("rc = %d; want 2", rc)
	}
	if !strings.Contains(stderr.String(), "not a directory") {
		t.Errorf("stderr missing 'not a directory': %q", stderr.String())
	}
}

// --- showSetupCodeCommand: env-var/flag → loader plumbing --------------

func TestShowSetupCodeCommand_MissingDatabaseURLConfigurationError(t *testing.T) {
	dir := t.TempDir()
	seedTokenFile(t, dir, "DOES-NOT-MATTER")
	getenv := func(string) string { return "" }

	var stdout, stderr bytes.Buffer
	rc := showSetupCodeCommand(context.Background(), dir, "", getenv, &stdout, &stderr)
	if rc != 2 {
		t.Errorf("rc = %d; want 2 on missing DB URL", rc)
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout must be empty; got %q", stdout.String())
	}
	msg := stderr.String()
	if !strings.Contains(msg, "IDENTUUM_IDP_DATABASE_URL") {
		t.Errorf("stderr should mention the IDENTUUM_IDP_DATABASE_URL env var; got %q", msg)
	}
	if !strings.Contains(msg, "--database-url") {
		t.Errorf("stderr should mention the --database-url flag; got %q", msg)
	}
}

func TestShowSetupCodeCommand_DatabaseURLNeverEchoedToStderr(t *testing.T) {
	// We use a malformed URL so the pool open fails fast; the redaction
	// guarantee is that the URL substring never appears in stderr.
	const secretURL = "postgres://shouldnotleak:dev-shouldnotleak-not-a-secret@127.0.0.1:1/idp"
	dir := t.TempDir()
	seedTokenFile(t, dir, "DOES-NOT-MATTER")
	getenv := func(k string) string {
		if k == "IDENTUUM_IDP_DATABASE_URL" {
			return secretURL
		}
		return ""
	}

	var stdout, stderr bytes.Buffer
	rc := showSetupCodeCommand(context.Background(), dir, "", getenv, &stdout, &stderr)
	// Either rc==1 (pool open failed) or rc==1 (state read failed); in
	// both cases we never want the URL in stderr or stdout.
	if rc == 0 {
		t.Fatalf("rc = 0; expected non-zero on unreachable DB; stderr=%q", stderr.String())
	}
	if strings.Contains(stdout.String(), "shouldnotleak") || strings.Contains(stderr.String(), "shouldnotleak") {
		t.Errorf("DB URL leaked: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	if strings.Contains(stdout.String(), "dev-shouldnotleak-not-a-secret") || strings.Contains(stderr.String(), "dev-shouldnotleak-not-a-secret") {
		t.Errorf("DB password leaked: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}
