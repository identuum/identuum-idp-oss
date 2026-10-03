package appliance

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// The key file is read and created only as a regular file. A symbolic link in
// its place — dangling or not — is refused, and nothing is created at the
// link's target.
func TestResolveEncryptionKey_RefusesSymlinkKeyFile(t *testing.T) {
	t.Run("dangling", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(t.TempDir(), "elsewhere")
		if err := os.Symlink(target, filepath.Join(dir, "encryption-key")); err != nil {
			t.Fatal(err)
		}
		if _, err := Prepare(context.Background(), baseEnv(dir), io.Discard, 0, 0, false, nil); err == nil {
			t.Fatal("a dangling symlink key file must be refused")
		}
		if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("the link target was created: %v", err)
		}
	})
	t.Run("to a file", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(t.TempDir(), "other")
		if err := os.WriteFile(target, []byte("0011223344556677889900112233445566778899001122334455667788990011"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(dir, "encryption-key")); err != nil {
			t.Fatal(err)
		}
		if _, err := Prepare(context.Background(), baseEnv(dir), io.Discard, 0, 0, false, nil); err == nil {
			t.Fatal("a symlink key file must be refused, not read through")
		}
	})
}
