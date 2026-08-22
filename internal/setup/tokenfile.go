package setup

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
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
// 0600 (umask is bypassed via os.OpenFile + os.Chmod). Refuses if the
// directory is world-writable. Returns the resolved path on success.
//
// A trailing newline is appended so `cat` of the file is shell-friendly;
// ReadTokenFile strips it on read.
func WriteTokenFile(dataDir, plaintext string) (string, error) {
	info, err := os.Stat(dataDir)
	if err != nil {
		return "", fmt.Errorf("setup: stat data dir: %w", err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("setup: data dir %q is not a directory", dataDir)
	}
	// Reject world-writable directories (perm bit 0o002 set). Group-writable
	// is permitted — operators commonly run the container as a non-root
	// uid with a shared gid for the data volume.
	if info.Mode().Perm()&0o002 != 0 {
		return "", fmt.Errorf("%w: %q (perm=%#o)", ErrUnsafeDataDir, dataDir, info.Mode().Perm())
	}

	path := TokenFilePath(dataDir)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return "", fmt.Errorf("setup: open token file: %w", err)
	}
	// Defensive chmod in case the file pre-existed with a different mode.
	if err := os.Chmod(path, 0o600); err != nil {
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
	return path, nil
}

// ReadTokenFile reads the plaintext token, stripping any trailing newline
// the writer added. Returns a wrapped fs.ErrNotExist when the file does
// not exist so callers can distinguish "setup already complete or never
// initialized" from other I/O errors with errors.Is.
func ReadTokenFile(dataDir string) (string, error) {
	path := TokenFilePath(dataDir)
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "", fmt.Errorf("setup: token file absent at %s: %w", path, err)
		}
		return "", fmt.Errorf("setup: read token file: %w", err)
	}
	return strings.TrimRight(string(data), "\r\n"), nil
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
