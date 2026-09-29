package runtime

import (
	"os"
	"path/filepath"
	"testing"
)

// OSS-POLISH item 3: with IDENTUUM_IDP_DATA_DIR unset the runtime wrote
// setup-token.txt into the current directory ("."), so a run from a checkout
// left the plaintext setup code inside the worktree. Unset now means the
// per-user data directory, an absolute path outside any working tree; an
// explicit value (the appliance always passes one) is used unchanged. New
// resolves the path only — it creates nothing.
func TestNew_DataDirDefaultsOutsideTheWorkingDirectory(t *testing.T) {
	rt, err := New(Config{Addr: "127.0.0.1:0", Getenv: func(string) string { return "" }})
	if err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(rt.cfg.DataDir) {
		t.Fatalf("default DataDir = %q, want an absolute per-user directory, not the working directory", rt.cfg.DataDir)
	}
	if base, err := os.UserConfigDir(); err == nil {
		if want := filepath.Join(base, "identuum-idp"); rt.cfg.DataDir != want {
			t.Fatalf("default DataDir = %q, want %q", rt.cfg.DataDir, want)
		}
	}

	env := map[string]string{"IDENTUUM_IDP_DATA_DIR": "/app/data"}
	rt, err = New(Config{Addr: "127.0.0.1:0", Getenv: func(k string) string { return env[k] }})
	if err != nil {
		t.Fatal(err)
	}
	if rt.cfg.DataDir != "/app/data" {
		t.Fatalf("explicit DataDir = %q, want /app/data (the appliance path is unchanged)", rt.cfg.DataDir)
	}
}
