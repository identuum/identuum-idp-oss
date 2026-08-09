package setup

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestWriteTokenFile_CreatesWithMode0600(t *testing.T) {
	dir := t.TempDir()
	plaintext := "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQRST"

	path, err := WriteTokenFile(dir, plaintext)
	if err != nil {
		t.Fatalf("WriteTokenFile: %v", err)
	}
	if path != filepath.Join(dir, "setup-token.txt") {
		t.Errorf("path = %q; want %q", path, filepath.Join(dir, "setup-token.txt"))
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	// Windows does not honour POSIX 0600; skip the mode assertion there.
	if runtime.GOOS != "windows" {
		if got := info.Mode().Perm(); got != 0o600 {
			t.Errorf("perm = %#o; want 0600", got)
		}
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read file: %v", err)
	}
	if string(data) != plaintext+"\n" {
		t.Errorf("file contents = %q; want %q (trailing newline expected)", string(data), plaintext+"\n")
	}
}

func TestWriteTokenFile_OverwriteResetsPerms(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "setup-token.txt")

	if err := os.WriteFile(path, []byte("stale"), 0o644); err != nil {
		t.Fatalf("seed stale file: %v", err)
	}
	if _, err := WriteTokenFile(dir, "fresh-token-value"); err != nil {
		t.Fatalf("WriteTokenFile: %v", err)
	}

	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat: %v", err)
		}
		if got := info.Mode().Perm(); got != 0o600 {
			t.Errorf("perm after overwrite = %#o; want 0600", got)
		}
	}

	data, _ := os.ReadFile(path)
	if string(data) != "fresh-token-value\n" {
		t.Errorf("contents not refreshed: %q", string(data))
	}
}

func TestWriteTokenFile_RefuseWorldWritableDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX perm bits not applicable on Windows")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatalf("chmod 777: %v", err)
	}

	_, err := WriteTokenFile(dir, "x")
	if !errors.Is(err, ErrUnsafeDataDir) {
		t.Errorf("err = %v; want ErrUnsafeDataDir", err)
	}
}

func TestWriteTokenFile_RefuseMissingDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "does-not-exist")
	_, err := WriteTokenFile(dir, "x")
	if err == nil {
		t.Fatalf("WriteTokenFile expected error on missing dir")
	}
	if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("err = %v; want wrap of fs.ErrNotExist", err)
	}
}

func TestWriteTokenFile_RefuseFileDataDir(t *testing.T) {
	parent := t.TempDir()
	path := filepath.Join(parent, "actually-a-file")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	_, err := WriteTokenFile(path, "x")
	if err == nil {
		t.Fatalf("expected error when dataDir is a file")
	}
}

func TestReadTokenFile_HappyPath(t *testing.T) {
	dir := t.TempDir()
	plaintext := "HELLO-SETUP-CODE"
	if _, err := WriteTokenFile(dir, plaintext); err != nil {
		t.Fatalf("WriteTokenFile: %v", err)
	}
	got, err := ReadTokenFile(dir)
	if err != nil {
		t.Fatalf("ReadTokenFile: %v", err)
	}
	if got != plaintext {
		t.Errorf("got = %q; want %q (trailing newline must be stripped)", got, plaintext)
	}
}

func TestReadTokenFile_MissingFileWrapsErrNotExist(t *testing.T) {
	dir := t.TempDir()
	_, err := ReadTokenFile(dir)
	if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("err = %v; want wrap of fs.ErrNotExist", err)
	}
}

func TestDeleteTokenFile_RemovesAndNoOps(t *testing.T) {
	dir := t.TempDir()
	if _, err := WriteTokenFile(dir, "x"); err != nil {
		t.Fatalf("WriteTokenFile: %v", err)
	}
	if err := DeleteTokenFile(dir); err != nil {
		t.Fatalf("DeleteTokenFile first call: %v", err)
	}
	if _, err := os.Stat(TokenFilePath(dir)); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("file should be gone after delete, stat err = %v", err)
	}
	// Second call must succeed.
	if err := DeleteTokenFile(dir); err != nil {
		t.Errorf("DeleteTokenFile second call should be no-op, got %v", err)
	}
}

func TestTokenFilePath_StableLocation(t *testing.T) {
	dir := "/tmp/idp-data"
	got := TokenFilePath(dir)
	want := "/tmp/idp-data/setup-token.txt"
	if got != want {
		t.Errorf("TokenFilePath = %q; want %q", got, want)
	}
}
