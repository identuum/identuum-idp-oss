package appliance

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The at-rest encryption key is resolved by the documented precedence —
// operator env first, then the persisted 0600 key file, then a freshly
// generated 0600 file — and an empty key file is REFUSED rather than silently
// regenerated (which would orphan every already-encrypted secret). The
// resolved key is written only into Config, never emitted, and a generated
// key file is created 0600.
// RULE: ATREST-KEY-RESOLVE-1
func TestResolveEncryptionKey_PrecedenceAndRefusals(t *testing.T) {
	newCfg := func(dir string) *Config { return &Config{DataDir: dir} }
	noChown := func(string, int, int) error { return nil }

	// 1. Operator env wins, used AS-IS, and no key file is written.
	t.Run("operator_env_wins", func(t *testing.T) {
		dir := t.TempDir()
		cfg := newCfg(dir)
		env := mapEnv{"IDENTUUM_IDP_ENCRYPTION_KEY": "operator-supplied-value"}
		src, err := ResolveEncryptionKey(env, cfg, 0, 0, false, noChown)
		if err != nil || src != KeyFromOperator {
			t.Fatalf("src=%v err=%v, want KeyFromOperator", src, err)
		}
		if cfg.EncryptionKey != "operator-supplied-value" {
			t.Fatalf("operator key not used as-is: %q", cfg.EncryptionKey)
		}
		if _, statErr := os.Stat(filepath.Join(dir, "encryption-key")); statErr == nil {
			t.Fatalf("a key file was written even though the operator supplied one")
		}
	})

	// 2. First boot generates, persists 0600, and reuses on the next boot.
	t.Run("generate_then_persist_then_reuse", func(t *testing.T) {
		dir := t.TempDir()
		cfg := newCfg(dir)
		src, err := ResolveEncryptionKey(mapEnv{}, cfg, 0, 0, false, noChown)
		if err != nil || src != KeyGenerated {
			t.Fatalf("first boot src=%v err=%v, want KeyGenerated", src, err)
		}
		keyFile := filepath.Join(dir, "encryption-key")
		info, statErr := os.Stat(keyFile)
		if statErr != nil {
			t.Fatalf("generated key not persisted: %v", statErr)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Fatalf("generated key file mode = %o, want 0600", perm)
		}
		generated := cfg.EncryptionKey
		if generated == "" {
			t.Fatalf("generated key not placed in Config")
		}
		// Second boot reuses the persisted value.
		cfg2 := newCfg(dir)
		src2, err := ResolveEncryptionKey(mapEnv{}, cfg2, 0, 0, false, noChown)
		if err != nil || src2 != KeyFromPersisted {
			t.Fatalf("second boot src=%v err=%v, want KeyFromPersisted", src2, err)
		}
		if cfg2.EncryptionKey != generated {
			t.Fatalf("persisted key changed across boots: %q != %q", cfg2.EncryptionKey, generated)
		}
	})

	// 3. An empty key file is corruption: refuse, do NOT regenerate.
	t.Run("empty_file_refused", func(t *testing.T) {
		dir := t.TempDir()
		keyFile := filepath.Join(dir, "encryption-key")
		if err := os.WriteFile(keyFile, []byte("   \n"), 0o600); err != nil {
			t.Fatal(err)
		}
		cfg := newCfg(dir)
		_, err := ResolveEncryptionKey(mapEnv{}, cfg, 0, 0, false, noChown)
		if err == nil {
			t.Fatalf("an empty key file must be refused, not silently regenerated")
		}
		if !strings.Contains(err.Error(), "empty") {
			t.Fatalf("refusal error should name the empty-file cause, got: %v", err)
		}
		if cfg.EncryptionKey != "" {
			t.Fatalf("a key was resolved despite the empty-file refusal: %q", cfg.EncryptionKey)
		}
	})
}
