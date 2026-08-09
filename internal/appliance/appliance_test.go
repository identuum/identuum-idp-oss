package appliance

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// mapEnv is a fake environment. The real one is process-global, and a test that
// mutates it races every other test in the package.
type mapEnv map[string]string

func (m mapEnv) Get(k string) string   { return m[k] }
func (m mapEnv) Set(k, v string) error { m[k] = v; return nil }

// recordingEnv remembers which keys were WRITTEN.
//
// The first version of the export test read the values back out of the map and
// asserted they were non-empty — which passed even with the export deleted,
// because baseEnv pre-sets IDENTUUM_IDP_DATA_DIR and the read found the INPUT,
// not the output. Caught by teeth-proving: removing the export from Export()
// produced no failure at all. Recording the writes tests the thing the name
// claims.
type recordingEnv struct {
	mapEnv
	wrote map[string]string
}

func newRecordingEnv(base mapEnv) *recordingEnv {
	return &recordingEnv{mapEnv: base, wrote: map[string]string{}}
}
func (r *recordingEnv) Set(k, v string) error {
	r.wrote[k] = v
	return r.mapEnv.Set(k, v)
}

func baseEnv(dir string) mapEnv {
	return mapEnv{
		"IDENTUUM_IDP_OSS_DB":     "postgres://u:dev-u-not-a-secret@db:5432/idp",
		"IDENTUUM_IDP_OSS_LISTEN": "0.0.0.0:7113",
		"IDENTUUM_IDP_OSS_ISSUER": "http://localhost:7113",
		"IDENTUUM_IDP_DATA_DIR":   dir,
	}
}

func TestResolveConfig_NamesEveryMissingVariableAtOnce(t *testing.T) {
	_, err := ResolveConfig(mapEnv{})
	var me *MissingEnvError
	if !errors.As(err, &me) {
		t.Fatalf("err = %v, want *MissingEnvError", err)
	}
	if len(me.Missing) != 3 {
		t.Errorf("named %d missing variable(s) (%v), want all 3 — the shell version aborted on "+
			"the first, so an operator fixed one, re-ran, and learned about the next",
			len(me.Missing), me.Missing)
	}
}

func TestResolveConfig_NewNameWinsOverApplianceName(t *testing.T) {
	env := baseEnv(t.TempDir())
	env["IDENTUUM_IDP_DATABASE_URL"] = "postgres://operator/chosen"
	cfg, err := ResolveConfig(env)
	if err != nil {
		t.Fatalf("ResolveConfig: %v", err)
	}
	if cfg.DatabaseURL != "postgres://operator/chosen" {
		t.Errorf("DatabaseURL = %q, want the operator-set IDENTUUM_IDP_DATABASE_URL to win, "+
			"matching the shell's ${NEW:-$OLD}", cfg.DatabaseURL)
	}
}

func TestPrepare_GeneratesPersistsAndReusesTheKey(t *testing.T) {
	dir := t.TempDir()
	env := baseEnv(dir)

	cfg, err := Prepare(context.Background(), env, io.Discard, 0, 0, false, nil)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if len(cfg.EncryptionKey) != EncryptionKeyBytes*2 {
		t.Fatalf("key length = %d, want %d hex chars", len(cfg.EncryptionKey), EncryptionKeyBytes*2)
	}
	if _, err := hex.DecodeString(cfg.EncryptionKey); err != nil {
		t.Errorf("key is not hex: %v", err)
	}

	keyFile := filepath.Join(dir, "encryption-key")
	info, err := os.Stat(keyFile)
	if err != nil {
		t.Fatalf("stat key file: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("key file mode = %#o, want 0600 — the shell pinned this and it must not drift", got)
	}

	// SECOND boot reuses it. A new key here would make every already-encrypted
	// MFA secret unreadable.
	env2 := baseEnv(dir)
	cfg2, err := Prepare(context.Background(), env2, io.Discard, 0, 0, false, nil)
	if err != nil {
		t.Fatalf("second Prepare: %v", err)
	}
	if cfg2.EncryptionKey != cfg.EncryptionKey {
		t.Errorf("the key changed across reboots — every MFA secret encrypted under the old one " +
			"is now unreadable")
	}
}

func TestResolveEncryptionKey_OperatorSuppliedWinsAndIsNotPersisted(t *testing.T) {
	dir := t.TempDir()
	env := baseEnv(dir)
	env["IDENTUUM_IDP_ENCRYPTION_KEY"] = "operator-managed-key-value"

	cfg, err := Prepare(context.Background(), env, io.Discard, 0, 0, false, nil)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if cfg.EncryptionKey != "operator-managed-key-value" {
		t.Errorf("key = %q, want the operator's value used AS-IS — normalising it here would "+
			"mask their mistake instead of letting the runtime gate fail closed", cfg.EncryptionKey)
	}
	if _, err := os.Stat(filepath.Join(dir, "encryption-key")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("an operator-supplied key was written to disk; it is externally managed and " +
			"must not be copied into the data volume")
	}
}

func TestResolveEncryptionKey_EmptyKeyFileRefusesRatherThanRegenerating(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "encryption-key"), []byte("   \n"), 0o600); err != nil {
		t.Fatalf("seed empty key file: %v", err)
	}
	_, err := Prepare(context.Background(), baseEnv(dir), io.Discard, 0, 0, false, nil)
	if err == nil {
		t.Fatalf("an empty key file was treated as a first boot; generating a replacement " +
			"silently orphans every MFA secret encrypted under the old key")
	}
	if !strings.Contains(err.Error(), "refusing to generate a replacement") {
		t.Errorf("error = %v, want it to say WHY it refused", err)
	}
}

func TestPrepare_ExportsEverythingTheServePathReads(t *testing.T) {
	dir := t.TempDir()
	env := newRecordingEnv(baseEnv(dir))
	if _, err := Prepare(context.Background(), env, io.Discard, 0, 0, false, nil); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	// IDENTUUM_IDP_DATA_DIR in particular: without it Config.DataDir falls back
	// to the working directory, first-run setup cannot write its token, and the
	// container crash-loops on a FRESH database only.
	for _, k := range []string{
		"IDENTUUM_IDP_DATA_DIR", "IDENTUUM_IDP_DATABASE_URL",
		"IDENTUUM_IDP_LISTEN", "IDENTUUM_IDP_ISSUER", "IDENTUUM_IDP_ENCRYPTION_KEY",
	} {
		if _, ok := env.wrote[k]; !ok {
			t.Errorf("%s was never EXPORTED — reading it back would have found the test's own "+
				"input and passed vacuously", k)
		}
	}
}

func TestPrepare_NeverPrintsASecret(t *testing.T) {
	dir := t.TempDir()
	env := baseEnv(dir)
	var out strings.Builder
	cfg, err := Prepare(context.Background(), env, &out, 0, 0, false, nil)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	logged := out.String()
	if strings.Contains(logged, cfg.EncryptionKey) {
		t.Errorf("the at-rest key was printed: %s", logged)
	}
	if strings.Contains(logged, cfg.DatabaseURL) {
		t.Errorf("the database URL was printed: %s", logged)
	}
	// CONTROL: the assertions above would pass on empty output too, so prove
	// the writer actually received something.
	if !strings.Contains(logged, "redacted") {
		t.Errorf("no log output at all — the two assertions above would pass vacuously; got %q", logged)
	}
}

func TestPrepareDataDir_ChownsOnlyWhenRoot(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	called := 0
	chown := func(string, int, int) error { called++; return nil }

	cfg := &Config{DataDir: dir}
	if err := PrepareDataDir(cfg, 10001, 10001, false, chown); err != nil {
		t.Fatalf("PrepareDataDir: %v", err)
	}
	if called != 0 {
		t.Errorf("chown ran while unprivileged (%d call(s)); it would fail and abort the boot", called)
	}
	if err := PrepareDataDir(cfg, 10001, 10001, true, chown); err != nil {
		t.Fatalf("PrepareDataDir as root: %v", err)
	}
	if called != 1 {
		t.Errorf("chown ran %d time(s) as root, want 1 — Docker mounts named volumes root-owned "+
			"and the server cannot write its setup token without this", called)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o700 {
		t.Errorf("data dir mode = %#o, want 0700", got)
	}
}

func TestDropPrivileges_RefusesToDropToRoot(t *testing.T) {
	if IsRoot() {
		t.Skip("this asserts the refusal path taken when NOT root; running as root changes it")
	}
	// Not root: the call is a documented no-op, which is what a container
	// already running as the unprivileged user relies on.
	if err := DropPrivileges(10001, 10001); err != nil {
		t.Errorf("DropPrivileges while unprivileged = %v, want nil (no-op)", err)
	}
}
