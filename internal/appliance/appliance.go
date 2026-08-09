// Package appliance is the container entrypoint, in Go.
//
// WHY THIS EXISTS (P2-19c, the prerequisite to P2-19b). The runtime image was
// debian:bookworm-slim because deployment/entrypoint.sh needed a shell and a
// pile of userland: sh, gosu, tini, chown, chmod, mkdir, head, od, tr. A
// distroless runtime has NONE of those, so "move to distroless" was not a base
// image swap — it was blocked until the shell script stopped being the
// entrypoint. Measured before this change: the script's work is env validation,
// data-directory ownership, at-rest key provisioning, migrations, env mapping,
// and a privilege drop. Every one of those is a thing the binary can do to
// itself, and doing it here is strictly better than doing it in shell:
//
//   - The key is generated with crypto/rand, not `head -c 32 /dev/urandom | od
//     -An -tx1 | tr -dc 'a-f0-9'`. That pipeline silently produces a SHORT key
//     if `tr` drops bytes, and nothing checks the length. This one cannot.
//   - The DB URL never becomes a process argument, so it cannot appear in a
//     `ps` listing on the host.
//   - There is no `exec` and no child process, so no init is needed to reap
//     zombies; Go's own signal handling reaches the graceful-shutdown path
//     directly as PID 1.
//
// WHAT IS DELIBERATELY UNCHANGED: the appliance env contract
// (IDENTUUM_IDP_OSS_DB / _LISTEN / _ISSUER), the key-resolution precedence
// (operator-supplied > persisted > generated), the file modes (0700 dir, 0600
// key), and the rule that no secret value is ever printed. An operator's
// existing compose file must keep working, so none of those may drift.
package appliance

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// EncryptionKeyBytes is the at-rest AES key length the runtime requires. The
// persisted form is hex, so the file holds twice this many characters.
const EncryptionKeyBytes = 32

// DefaultDataDir matches the directory the image creates.
const DefaultDataDir = "/app/data"

// Config is the resolved appliance configuration. Every field is derived from
// the environment; nothing here is a secret except EncryptionKey, which is
// never included in any String/log output because this type has no String
// method and is never formatted with %v by its callers.
type Config struct {
	DatabaseURL   string
	Listen        string
	Issuer        string
	DataDir       string
	EncryptionKey string
}

// Env abstracts the process environment so the whole flow is testable without
// mutating the real one — a test that sets and unsets globals races with any
// other test in the package.
type Env interface {
	Get(key string) string
	Set(key, value string) error
}

// OSEnv is the real environment.
type OSEnv struct{}

func (OSEnv) Get(k string) string   { return os.Getenv(k) }
func (OSEnv) Set(k, v string) error { return os.Setenv(k, v) }
func nonEmpty(env Env, k string) (string, bool) {
	v := strings.TrimSpace(env.Get(k))
	return v, v != ""
}

// MissingEnvError names every required variable that is absent, all at once.
//
// The shell version used `: "${VAR:?message}"`, which aborts on the FIRST
// missing variable — so an operator with three unset variables fixes one,
// re-runs, and learns about the next. This reports all of them.
type MissingEnvError struct{ Missing []string }

func (e *MissingEnvError) Error() string {
	return fmt.Sprintf("identuum-idp: missing required appliance environment: %s",
		strings.Join(e.Missing, ", "))
}

// ResolveConfig reads and validates the appliance contract.
func ResolveConfig(env Env) (*Config, error) {
	cfg := &Config{}
	var missing []string

	// The new-name variable wins when set (operator / externally managed),
	// exactly as the shell's ${NEW:-$OLD} mapping did.
	pick := func(newName, applianceName string) string {
		if v, ok := nonEmpty(env, newName); ok {
			return v
		}
		v, ok := nonEmpty(env, applianceName)
		if !ok {
			missing = append(missing, applianceName)
		}
		return v
	}
	cfg.DatabaseURL = pick("IDENTUUM_IDP_DATABASE_URL", "IDENTUUM_IDP_OSS_DB")
	cfg.Listen = pick("IDENTUUM_IDP_LISTEN", "IDENTUUM_IDP_OSS_LISTEN")
	cfg.Issuer = pick("IDENTUUM_IDP_ISSUER", "IDENTUUM_IDP_OSS_ISSUER")

	if len(missing) > 0 {
		return nil, &MissingEnvError{Missing: missing}
	}

	cfg.DataDir = DefaultDataDir
	if v, ok := nonEmpty(env, "IDENTUUM_IDP_DATA_DIR"); ok {
		cfg.DataDir = v
	}
	return cfg, nil
}

// PrepareDataDir creates the data directory and pins its mode.
//
// chownFn is injected so the privilege-sensitive part is testable and so the
// non-Linux build can supply a no-op. It is called ONLY when the process is
// running as root: Docker mounts a named volume at a root-owned mountpoint
// regardless of the image-side mkdir/chown, and without this the server (uid
// 10001) cannot write its first-run setup token —
//
//	setup: open token file: open setup-token.txt: permission denied
//
// — and the container crash-loops. Only a FRESH database hits it, which is why
// it survived so long unnoticed.
func PrepareDataDir(cfg *Config, uid, gid int, isRoot bool, chownFn func(string, int, int) error) error {
	if strings.TrimSpace(cfg.DataDir) == "" {
		return errors.New("appliance: empty data directory")
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return fmt.Errorf("appliance: create data directory: %w", err)
	}
	if isRoot && chownFn != nil {
		if err := chownFn(cfg.DataDir, uid, gid); err != nil {
			return fmt.Errorf("appliance: chown data directory: %w", err)
		}
	}
	if err := os.Chmod(cfg.DataDir, 0o700); err != nil {
		return fmt.Errorf("appliance: chmod data directory: %w", err)
	}
	return nil
}

// KeySource says where the at-rest key came from, so the caller can log WHICH
// path ran without ever touching the value.
type KeySource string

const (
	KeyFromOperator  KeySource = "operator-supplied"
	KeyFromPersisted KeySource = "persisted"
	KeyGenerated     KeySource = "generated"
)

// ResolveEncryptionKey implements the documented precedence:
//
//  1. operator-supplied via IDENTUUM_IDP_ENCRYPTION_KEY — used AS-IS. Its
//     format is validated by the runtime gate, so an invalid key still fails
//     closed; normalising it here would mask an operator's mistake.
//  2. persisted in the data volume — so the key survives reboots and
//     previously-encrypted MFA secrets stay readable.
//  3. first boot — generate, persist 0600, and use.
//
// The value is NEVER returned through the logger, only through Config.
func ResolveEncryptionKey(env Env, cfg *Config, uid, gid int, isRoot bool, chownFn func(string, int, int) error) (KeySource, error) {
	if v, ok := nonEmpty(env, "IDENTUUM_IDP_ENCRYPTION_KEY"); ok {
		cfg.EncryptionKey = v
		return KeyFromOperator, nil
	}

	keyFile := filepath.Join(cfg.DataDir, "encryption-key")
	switch raw, err := os.ReadFile(keyFile); {
	case err == nil:
		key := strings.TrimSpace(string(raw))
		if key == "" {
			// An empty key file is corruption, not a first boot. Generating a
			// new key here would silently orphan every MFA secret already
			// encrypted under the old one, so refuse and let an operator look.
			return "", fmt.Errorf("appliance: %s exists but is empty — refusing to "+
				"generate a replacement, because a new key makes every already-encrypted "+
				"MFA secret unreadable. Restore the file from backup, or delete it "+
				"deliberately to accept that loss", keyFile)
		}
		cfg.EncryptionKey = key
		return KeyFromPersisted, nil
	case !errors.Is(err, fs.ErrNotExist):
		return "", fmt.Errorf("appliance: read encryption key: %w", err)
	}

	buf := make([]byte, EncryptionKeyBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("appliance: generate encryption key: %w", err)
	}
	key := hex.EncodeToString(buf)

	// 0600 from the moment it exists — WriteFile's perm applies at creation, so
	// there is no window where the secret is group-readable.
	if err := os.WriteFile(keyFile, []byte(key), 0o600); err != nil {
		return "", fmt.Errorf("appliance: persist encryption key: %w", err)
	}
	if isRoot && chownFn != nil {
		if err := chownFn(keyFile, uid, gid); err != nil {
			return "", fmt.Errorf("appliance: chown encryption key: %w", err)
		}
	}
	if err := os.Chmod(keyFile, 0o600); err != nil {
		return "", fmt.Errorf("appliance: chmod encryption key: %w", err)
	}
	cfg.EncryptionKey = key
	return KeyGenerated, nil
}

// Export publishes the resolved configuration under the names the serve path
// reads. The shell did this with `export`; the effect must be identical or the
// server starts with the wrong data directory and first-run setup fails.
func Export(env Env, cfg *Config) error {
	for k, v := range map[string]string{
		"IDENTUUM_IDP_DATA_DIR":       cfg.DataDir,
		"IDENTUUM_IDP_DATABASE_URL":   cfg.DatabaseURL,
		"IDENTUUM_IDP_LISTEN":         cfg.Listen,
		"IDENTUUM_IDP_ISSUER":         cfg.Issuer,
		"IDENTUUM_IDP_ENCRYPTION_KEY": cfg.EncryptionKey,
	} {
		if err := env.Set(k, v); err != nil {
			return fmt.Errorf("appliance: export %s: %w", k, err)
		}
	}
	return nil
}

// Prepare runs the whole pre-serve sequence and reports what it did, without
// disclosing any secret. The caller then drops privileges and serves.
//
// Migrations are NOT run here: they are a separate one-shot the caller invokes,
// so this function stays free of database access and remains unit-testable
// against a temporary directory.
func Prepare(ctx context.Context, env Env, out io.Writer, uid, gid int, isRoot bool, chownFn func(string, int, int) error) (*Config, error) {
	cfg, err := ResolveConfig(env)
	if err != nil {
		return nil, err
	}
	if err := PrepareDataDir(cfg, uid, gid, isRoot, chownFn); err != nil {
		return nil, err
	}
	src, err := ResolveEncryptionKey(env, cfg, uid, gid, isRoot, chownFn)
	if err != nil {
		return nil, err
	}
	if err := Export(env, cfg); err != nil {
		return nil, err
	}
	// Says WHICH path ran and never the value — an operator needs to know
	// whether their key was used or a new one was minted.
	fmt.Fprintf(out, "identuum-idp-oss: at-rest encryption key %s (value redacted)\n", src)
	fmt.Fprintf(out, "identuum-idp-oss: data directory %s (0700)\n", cfg.DataDir)
	return cfg, nil
}
