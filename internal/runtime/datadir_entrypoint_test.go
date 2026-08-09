package runtime_test

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/identuum/identuum-idp-oss/internal/appliance"
)

// THE GUARANTEE THIS FILE HAS ALWAYS BEEN ABOUT, at its new address.
//
// It used to read deployment/entrypoint.sh and assert the script said
// `export IDENTUUM_IDP_DATA_DIR`. That script is gone: P2-19c moved its work
// into the binary so P2-19b could put the runtime on distroless, which has no
// shell to run it. The guard was NOT deleted with the script, because what it
// protects did not change — only where the work happens.
//
// The failure it exists to prevent: if the data directory is resolved but not
// published, the server falls back to Config.DataDir "." — the root-owned
// working directory — and first-run setup dies with
//
//	setup: open token file: open setup-token.txt: permission denied
//
// crash-looping the container. It reproduces ONLY on a fresh database, because
// an already-set-up installation never writes the token, which is what made it
// expensive to find the first time.
//
// internal/appliance has its own unit coverage of Export; this is the
// end-to-end statement of the same requirement, kept in the package that owns
// the consequence.
func TestApplianceExportsDataDir(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	env := recordingEnv{values: map[string]string{
		"IDENTUUM_IDP_OSS_DB":     "postgres://u:dev-u-not-a-secret@db:5432/idp",
		"IDENTUUM_IDP_OSS_LISTEN": "0.0.0.0:7113",
		"IDENTUUM_IDP_OSS_ISSUER": "http://localhost:7113",
		"IDENTUUM_IDP_DATA_DIR":   dir,
	}, wrote: map[string]string{}}

	cfg, err := appliance.Prepare(context.Background(), env, io.Discard, 0, 0, false, nil)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}

	// CONTROL: the resolution this test is about must still happen. Without it
	// the export assertion could pass against a flow that no longer resolves a
	// data directory at all.
	if cfg.DataDir != dir {
		t.Fatalf("CONTROL FAILED: DataDir = %q, want %q — the appliance no longer resolves the "+
			"data directory the documented way, so this guard is asserting against a flow it "+
			"no longer understands", cfg.DataDir, dir)
	}

	got, ok := env.wrote["IDENTUUM_IDP_DATA_DIR"]
	if !ok {
		t.Fatal("the appliance resolves the data directory but never exports " +
			"IDENTUUM_IDP_DATA_DIR — the binary falls back to Config.DataDir \".\" (the " +
			"root-owned working directory) and first-run setup fails with 'open " +
			"setup-token.txt: permission denied', crash-looping the container on every " +
			"fresh database")
	}
	if got != dir {
		t.Errorf("exported IDENTUUM_IDP_DATA_DIR = %q, want %q", got, dir)
	}

	// And the directory it named is actually usable by the server that follows.
	if _, err := os.Stat(filepath.Join(dir)); err != nil {
		t.Errorf("the exported data directory does not exist: %v", err)
	}
}

// recordingEnv records writes; reading a value back would find this test's own
// input and prove nothing.
type recordingEnv struct {
	values map[string]string
	wrote  map[string]string
}

func (r recordingEnv) Get(k string) string { return r.values[k] }
func (r recordingEnv) Set(k, v string) error {
	r.wrote[k] = v
	r.values[k] = v
	return nil
}
