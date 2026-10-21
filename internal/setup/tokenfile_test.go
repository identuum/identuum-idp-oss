package setup

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
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

func TestTokenFileRejectsLinksWithoutChangingTarget(t *testing.T) {
	for _, hardlink := range []bool{false, true} {
		t.Run(map[bool]string{false: "symlink", true: "hardlink"}[hardlink], func(t *testing.T) {
			dir := t.TempDir()
			target := filepath.Join(t.TempDir(), "sentinel")
			if err := os.WriteFile(target, []byte("sentinel"), 0o640); err != nil {
				t.Fatal(err)
			}
			link := os.Symlink
			if hardlink {
				link = os.Link
			}
			if err := link(target, TokenFilePath(dir)); err != nil {
				t.Fatal(err)
			}
			if !hardlink {
				if got, err := ReadTokenFile(dir); err == nil || got != "" {
					t.Fatal("symlink read was not refused")
				}
			}
			_, _ = WriteTokenFile(dir, "synthetic-setup-value")
			data, err := os.ReadFile(target)
			if err != nil {
				t.Fatal(err)
			}
			info, err := os.Stat(target)
			if err != nil {
				t.Fatal(err)
			}
			if string(data) != "sentinel" || info.Mode().Perm() != 0o640 {
				t.Fatal("linked target changed")
			}
		})
	}
}

func TestReadTokenFileRejectsInvalidInput(t *testing.T) {
	for _, input := range []string{strings.Repeat("a", 4097), "", "a\nb", "a\x00b"} {
		dir := t.TempDir()
		if err := os.WriteFile(TokenFilePath(dir), []byte(input), 0o600); err != nil {
			t.Fatal(err)
		}
		if got, err := ReadTokenFile(dir); err == nil || got != "" {
			t.Fatal("invalid input was not refused")
		}
	}
}

func TestTokenFileSharedGroup(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o770); err != nil {
		t.Fatal(err)
	}
	if _, err := WriteTokenFile(dir, "synthetic-setup-value"); err != nil {
		t.Fatal(err)
	}
	if got, err := ReadTokenFile(dir); err != nil || got != "synthetic-setup-value" {
		t.Fatal("shared-group round trip failed")
	}
}

func TestTokenFileSymlinkDataDir(t *testing.T) {
	for _, mode := range []os.FileMode{0o700, 0o770} {
		t.Run(mode.String(), func(t *testing.T) {
			target := t.TempDir()
			if err := os.Chmod(target, mode); err != nil {
				t.Fatal(err)
			}
			dir := filepath.Join(t.TempDir(), "data")
			if err := os.Symlink(target, dir); err != nil {
				t.Fatal(err)
			}
			path, err := WriteTokenFile(dir, "synthetic-setup-value")
			if err != nil {
				t.Fatal("write through data directory link failed")
			}
			if path != TokenFilePath(dir) {
				t.Fatal("returned path changed")
			}
			for _, dataDir := range []string{dir, target} {
				if got, err := ReadTokenFile(dataDir); err != nil || got != "synthetic-setup-value" {
					t.Fatal("data directory round trip failed")
				}
			}
			info, err := os.Stat(TokenFilePath(target))
			if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
				t.Fatal("target file is not regular with mode 0600")
			}
		})
	}
}

func TestTokenFileSymlinkDataDirRejectsUnsafeTarget(t *testing.T) {
	target := t.TempDir()
	if err := os.Chmod(target, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(TokenFilePath(target), []byte("sentinel"), 0o600); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "data")
	if err := os.Symlink(target, dir); err != nil {
		t.Fatal(err)
	}
	if got, err := ReadTokenFile(dir); !errors.Is(err, ErrUnsafeDataDir) || got != "" {
		t.Fatal("unsafe linked directory read was not refused")
	}
	if _, err := WriteTokenFile(dir, "synthetic-setup-value"); !errors.Is(err, ErrUnsafeDataDir) {
		t.Fatal("unsafe linked directory write was not refused")
	}
	data, err := os.ReadFile(TokenFilePath(target))
	if err != nil || string(data) != "sentinel" {
		t.Fatal("unsafe directory file changed")
	}
}

func TestTokenFileSymlinkDataDirRejectsFileLink(t *testing.T) {
	target := t.TempDir()
	dir := filepath.Join(t.TempDir(), "data")
	if err := os.Symlink(target, dir); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(t.TempDir(), "sentinel")
	if err := os.WriteFile(sentinel, []byte("sentinel"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(sentinel, TokenFilePath(target)); err != nil {
		t.Fatal(err)
	}
	if got, err := ReadTokenFile(dir); err == nil || got != "" {
		t.Fatal("file link read was not refused")
	}
	if _, err := WriteTokenFile(dir, "synthetic-setup-value"); err == nil {
		t.Fatal("file link write was not refused")
	}
	data, err := os.ReadFile(sentinel)
	if err != nil || string(data) != "sentinel" {
		t.Fatal("file link target changed")
	}
	info, err := os.Stat(sentinel)
	if err != nil || info.Mode().Perm() != 0o640 {
		t.Fatal("file link target permissions changed")
	}
}

func TestTokenFileRejectsFIFO(t *testing.T) {
	dir := t.TempDir()
	if err := unix.Mkfifo(TokenFilePath(dir), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := ReadTokenFile(dir); err == nil || got != "" {
		t.Fatal("FIFO read was not refused")
	}
	if _, err := WriteTokenFile(dir, "synthetic-setup-value"); err == nil {
		t.Fatal("FIFO write was not refused")
	}
}
