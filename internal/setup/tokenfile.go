package setup

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// tokenFileName is the filename inside $DATA_DIR that holds the setup
// token plaintext while setup status is setup_required. The file is
// always mode 0600 and is deleted on successful wizard completion.
const tokenFileName = "setup-token.txt"

// ErrUnsafeDataDir is returned when the data directory has permissions
// that would let other users read the setup-token file. Mounting
// $DATA_DIR onto a world-writable volume is a configuration error
// the binary refuses to paper over.
var ErrUnsafeDataDir = errors.New("setup: data directory is world-writable; refusing to persist setup token")

// TokenFilePath returns the absolute-or-relative path to the setup-token
// file inside the supplied data directory. Exported so /api/setup/status
// callers, the show-setup-code subcommand, and the boot banner all point
// at the same location.
func TokenFilePath(dataDir string) string {
	return filepath.Join(dataDir, tokenFileName)
}

// WriteTokenFile writes plaintext to $DATA_DIR/setup-token.txt with mode
// 0600 using an exclusive temporary file and atomic replacement. Refuses if the
// directory is world-writable. Returns the resolved path on success.
//
// A trailing newline is appended so `cat` of the file is shell-friendly;
// ReadTokenFile strips it on read.
func WriteTokenFile(dataDir, plaintext string) (string, error) {
	dir, err := openTokenDir(dataDir)
	if err != nil {
		return "", err
	}
	defer dir.Close()
	info, err := dir.Lstat(tokenFileName)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return "", fmt.Errorf("setup: inspect token file: %w", err)
	}
	if err == nil && !info.Mode().IsRegular() {
		return "", errors.New("setup: token file must be regular")
	}
	// Directory-relative operations pin the directory inode. The temporary
	// file never follows or truncates an existing entry, including hardlinks.
	name := ".setup-" + rand.Text()
	f, err := dir.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return "", fmt.Errorf("setup: open token file: %w", err)
	}
	defer dir.Remove(name)
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return "", fmt.Errorf("setup: chmod token file: %w", err)
	}
	if _, err := f.WriteString(plaintext + "\n"); err != nil {
		_ = f.Close()
		return "", fmt.Errorf("setup: write token file: %w", err)
	}
	if err := f.Close(); err != nil {
		return "", fmt.Errorf("setup: close token file: %w", err)
	}
	// Rename replaces an entry without following its target, even if another
	// directory writer replaced the destination after the inspection above.
	if err := dir.Rename(name, tokenFileName); err != nil {
		return "", fmt.Errorf("setup: replace token file: %w", err)
	}
	return TokenFilePath(dataDir), nil
}

// openTokenDir pins a local directory for all subsequent descriptor-relative IO.
// Shared-group directories remain supported; world-writable ones are refused.
func openTokenDir(dataDir string) (*os.Root, error) {
	// Follow the operator-selected directory path, including a final symlink.
	// Open pins its resolved target; Stat checks that same inode, and all file
	// operations below stay relative to it with their own no-follow checks.
	dir, err := os.OpenRoot(dataDir)
	if err != nil {
		return nil, fmt.Errorf("setup: open data dir: %w", err)
	}
	info, err := dir.Stat(".")
	if err != nil {
		_ = dir.Close()
		return nil, fmt.Errorf("setup: stat data dir: %w", err)
	}
	if info.Mode().Perm()&0o002 != 0 {
		_ = dir.Close()
		return nil, ErrUnsafeDataDir
	}
	return dir, nil
}

// ReadTokenFile reads the plaintext token, stripping any trailing newline
// the writer added. Returns a wrapped fs.ErrNotExist when the file does
// not exist so callers can distinguish "setup already complete or never
// initialized" from other I/O errors with errors.Is.
func ReadTokenFile(dataDir string) (string, error) {
	dir, err := openTokenDir(dataDir)
	if err != nil {
		return "", err
	}
	defer dir.Close()
	// NONBLOCK prevents a planted FIFO from hanging before Stat can reject it.
	f, err := dir.OpenFile(tokenFileName, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "", fmt.Errorf("setup: token file absent: %w", err)
		}
		return "", fmt.Errorf("setup: read token file: %w", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return "", fmt.Errorf("setup: stat token file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("setup: token file must be regular")
	}
	const maxBytes = 4096
	data, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return "", fmt.Errorf("setup: read token file: %w", err)
	}
	value := strings.TrimRight(string(data), "\r\n")
	if len(data) > maxBytes || value == "" {
		return "", errors.New("setup: invalid token file")
	}
	for _, c := range value {
		if c < '!' || c > '~' {
			return "", errors.New("setup: invalid token file")
		}
	}
	return value, nil
}

// DeleteTokenFile removes the plaintext token file. No-op when the file
// is already gone. Called once setup-complete succeeds so the plaintext
// never lingers on disk beyond its useful life.
func DeleteTokenFile(dataDir string) error {
	path := TokenFilePath(dataDir)
	if err := os.Remove(path); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("setup: delete token file: %w", err)
	}
	return nil
}
