package main

// Bootstrap subcommand for the OSS local-demo runtime.
//
// Why this exists:
//   On a fresh identuum-idp-oss database every meaningful HTTP route is
//   gated behind a site_admin bearer (see internal/handlers/keys.go and
//   internal/mw/site_admin.go) and the OAuth/OIDC flows require at least
//   one active signing key in the OSS KeyRepository. Both of those rows
//   are absent right after `identuum-idp migrate` lands the embedded migrations.
//   The full Identuum monolith resolves this with cli.RunSetup which is
//   not present in the OSS build. Without an OSS-local bootstrap path an
//   operator cannot reach an authenticated browser demo from a clean
//   `make oss-up`.
//
// What this is (and is not):
//   - This is an explicit, operator-run, idempotent CLI subcommand that
//     creates the System Organization's site_admin row (id pinned to
//     domain.SiteAdminID) and ensures at least one active EdDSA (or
//     ES256) signing key exists.
//   - It is NOT a public HTTP endpoint; there is no unauthenticated
//     bootstrap route exposed by the server. The chicken-and-egg is
//     resolved by the operator running this binary directly against the
//     OSS Postgres URL.
//   - It is NOT auto-fired from the container entrypoint. The entrypoint
//     stays single-purpose (migrate then serve). Auto-bootstrap
//     would leak the operator-supplied password into compose environment
//     surfaces; an explicit one-shot keeps secrets in the operator's hand.
//   - It is NOT a backdoor: the password and signing key material are
//     never printed. Logs only carry the user UUID and key KID.
//
// Strict no-secret-leak rules enforced below:
//   - The database URL is redacted from every error via redactURL().
//   - The bootstrap password is read from $IDENTUUM_IDP_BOOTSTRAP_PASSWORD
//     (never a CLI flag value) and is zeroed in the local buffer after
//     the hash is produced.
//   - Generated signing-key private material never leaves the
//     KeyService.Generate path; only the KID is logged.
//   - All log lines on every code path are safe to copy/paste into PRs.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/crypto"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/postgres"
	"github.com/identuum/identuum-idp-oss/internal/repository"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// At-rest key SOURCE names reported by resolveAtRestKey. These are the
// NAMED STATES the doctor subcommand prints (OPERATOR-UX-1) — key material
// itself is never returned to a caller that prints, and never printed.
const (
	atRestKeySourceEnv       = "env"        // IDENTUUM_IDP_ENCRYPTION_KEY
	atRestKeySourceEnvCompat = "env-compat" // AUTH_SERVICE_ENCRYPTION_KEY
	atRestKeySourceKeyFile   = "key-file"   // $IDENTUUM_IDP_DATA_DIR/encryption-key
	atRestKeySourceAbsent    = "absent"     // nothing anywhere
)

// resolveAtRestKey applies the at-rest AES key precedence and reports WHICH
// source supplied it: IDENTUUM_IDP_ENCRYPTION_KEY (preferred), then
// AUTH_SERVICE_ENCRYPTION_KEY (compat), then the key file the appliance
// persisted in the data volume — the SAME precedence
// appliance.ResolveEncryptionKey applies at serve time. The file fallback is
// what makes `docker exec <container> identuum-idp recover-site-admin` work
// against the distroless runtime image on an appliance whose key was generated
// at first boot and lives only in the file: there is no shell in that image to
// load it into the environment first, and recover is exactly the break-glass
// command that must work on a sick appliance.
//
// Injectable getenv/readFile keep the precedence unit-testable; production
// passes os.Getenv / os.ReadFile. The returned hexKey is a SECRET — callers
// must never print it.
func resolveAtRestKey(getenv func(string) string, readFile func(string) ([]byte, error)) (hexKey, source string) {
	if v := strings.TrimSpace(getenv("IDENTUUM_IDP_ENCRYPTION_KEY")); v != "" {
		return v, atRestKeySourceEnv
	}
	if v := strings.TrimSpace(getenv("AUTH_SERVICE_ENCRYPTION_KEY")); v != "" {
		return v, atRestKeySourceEnvCompat
	}
	dataDir := strings.TrimSpace(getenv("IDENTUUM_IDP_DATA_DIR"))
	if dataDir == "" {
		dataDir = "/app/data"
	}
	if raw, err := readFile(filepath.Join(dataDir, "encryption-key")); err == nil {
		if v := strings.TrimSpace(string(raw)); v != "" {
			return v, atRestKeySourceKeyFile
		}
	}
	return "", atRestKeySourceAbsent
}

// resolveSigningKeyCipher builds the at-rest CryptoService bootstrap uses to
// encrypt the signing key it creates (P3-5). The AES key precedence lives in
// resolveAtRestKey. FAIL-CLOSED: bootstrap MUST encrypt the private key it
// writes, so a missing or invalid key is a hard error rather than a plaintext
// fallback.
func resolveSigningKeyCipher() (postgres.PrivateKeyCipher, error) {
	hexKey, _ := resolveAtRestKey(os.Getenv, os.ReadFile)
	if hexKey == "" {
		return nil, fmt.Errorf("no at-rest encryption key: set IDENTUUM_IDP_ENCRYPTION_KEY, " +
			"or run where the appliance data volume is mounted ($IDENTUUM_IDP_DATA_DIR/encryption-key; " +
			"default /app/data). 32-byte hex, required to encrypt signing keys at rest")
	}
	cipher, err := crypto.NewCryptoService(hexKey)
	if err != nil {
		return nil, fmt.Errorf("at-rest encryption key invalid (must be 32-byte hex): %w", err)
	}
	return cipher, nil
}

// Environment variables consumed by the bootstrap subcommand. Names are
// stable wire-format: documented at
// identuum-idp/docs/open-core/IDP_OSS_BOOTSTRAP_SIGNING_KEY_ADMIN_READINESS.md
// and referenced by the make oss-bootstrap target. Changing them is a
// breaking change for operator scripts.
const (
	envBootstrapPassword  = "IDENTUUM_IDP_BOOTSTRAP_PASSWORD"
	envBootstrapEmail     = "IDENTUUM_IDP_BOOTSTRAP_EMAIL"
	envBootstrapAlgorithm = "IDENTUUM_IDP_BOOTSTRAP_ALGORITHM"
)

// bootstrapDefaults picks the safest values when the optional env vars
// are unset. EdDSA is the OSS default (matches KeyService.Generate
// dispatch + the operator no-RSA constraint).
var bootstrapDefaults = struct {
	Email     string
	Algorithm domain.KeyAlgorithm
}{
	Email:     domain.SiteAdminEmail,
	Algorithm: domain.KeyAlgorithmEdDSA,
}

// bootstrapOptions is the parsed env-driven configuration consumed by
// bootstrapCore. Keeping it separate from os.Getenv lets the unit tests
// exercise the full state machine without touching process env.
type bootstrapOptions struct {
	Email     string
	Password  string
	Algorithm domain.KeyAlgorithm
}

// loadBootstrapOptions reads + validates env vars. The password is
// required; the other two fall back to safe defaults. Returns a
// non-nil error only on a missing/empty password or an unsupported
// algorithm value. The password is never echoed back through the
// error message.
func loadBootstrapOptions(getenv func(string) string) (bootstrapOptions, error) {
	pw := getenv(envBootstrapPassword)
	if pw == "" {
		return bootstrapOptions{}, fmt.Errorf("%s is required (not set or empty)", envBootstrapPassword)
	}
	// bootstrap creates the FIRST site_admin row — control-plane
	// infrastructure per Decision D-004. STRICT password validation
	// is mandatory and DOES NOT consult any tenant org policy.
	// Wired by slice agent-a-20260715-idp-oss-password-complexity-
	// perorg-enforcement (Decision D-015 §9 EXCLUDED control-plane).
	// The password value is NOT included in the error message —
	// only the failed-policy category.
	if err := domain.ValidatePassword(pw, 12); err != nil {
		return bootstrapOptions{}, fmt.Errorf("%s failed strict policy: %w (password value redacted)", envBootstrapPassword, err)
	}

	email := getenv(envBootstrapEmail)
	if email == "" {
		email = bootstrapDefaults.Email
	}

	alg := bootstrapDefaults.Algorithm
	if raw := getenv(envBootstrapAlgorithm); raw != "" {
		switch domain.KeyAlgorithm(raw) {
		case domain.KeyAlgorithmEdDSA, domain.KeyAlgorithmES256:
			alg = domain.KeyAlgorithm(raw)
		default:
			return bootstrapOptions{}, fmt.Errorf("%s=%q is not supported (allowed: EdDSA, ES256)", envBootstrapAlgorithm, raw)
		}
	}

	return bootstrapOptions{
		Email:     email,
		Password:  pw,
		Algorithm: alg,
	}, nil
}

// bootstrapDeps abstracts the two repositories bootstrapCore needs.
// Production wires postgres.NewPgxRepositories; tests pass in-memory
// fakes. KeyService is constructed inside bootstrapCore because it is
// a thin wrapper around the KeyRepository — there is no behaviour to
// stub.
type bootstrapDeps struct {
	Keys  repository.KeyRepository
	Users repository.UserRepository
	// Setup marks the appliance setup-state row complete once the site_admin
	// + signing key exist (WIZARD-SPLIT-BRAIN-1). Optional: nil skips the step
	// (older tests), but a bootstrapped database that leaves state
	// setup_required while a site_admin exists is exactly the split-brain the
	// setup wizard then chokes on. PgxSetupStateRepository satisfies it.
	Setup setupCompleter
}

// setupCompleter is the narrow slice of the setup-state repository bootstrap
// needs: ensure the singleton row, then mark it complete.
type setupCompleter interface {
	EnsureRow(ctx context.Context) error
	MarkComplete(ctx context.Context, at time.Time) error
}

// finishBootstrap marks the setup-state row complete so a bootstrapped
// database is COHERENT — state setup_complete AND a site_admin present, never
// the disagreement that let the wizard silently discard credentials
// (WIZARD-SPLIT-BRAIN-1). Nil Setup (or a mark failure) never fails bootstrap:
// the privileged rows already exist, so the rc is unchanged; a failure is a
// loud warning the operator can resolve by re-running or via the wizard.
func finishBootstrap(ctx context.Context, deps bootstrapDeps, stdout, stderr io.Writer) int {
	if deps.Setup == nil {
		return 0
	}
	if err := deps.Setup.EnsureRow(ctx); err != nil {
		fmt.Fprintln(stderr, "identuum-idp: bootstrap: WARN could not ensure setup-state row:", err)
		return 0
	}
	if err := deps.Setup.MarkComplete(ctx, time.Now().UTC()); err != nil {
		fmt.Fprintln(stderr, "identuum-idp: bootstrap: WARN could not mark setup complete (site_admin exists but state stays setup_required — the wizard would then face an existing admin):", err)
		return 0
	}
	fmt.Fprintln(stdout, "identuum-idp: bootstrap: setup state marked complete (no split-brain)")
	return 0
}

// bootstrapCore is the pure state machine. It is idempotent on both
// halves: re-running after the first successful invocation is a no-op
// that prints the existing row IDs without mutating state. Returns
// the process exit code (0 on success, non-zero on failure). All
// logs go to stdout (success path) or stderr (failure path).
//
// The order of operations is intentional:
//
//  1. Signing key first. A site_admin row without a signing key is
//     useless (no bearer token can be issued). A signing key without
//     a site_admin row is still useful (the server can publish JWKS).
//     Doing keys first means a partial failure leaves the DB in a
//     state that's easier to reason about.
//
//  2. Site admin second. Uses the pinned SiteAdminID sentinel so the
//     row is locatable by ID without an email lookup, matching the
//     monolith's createSiteAdmin convention.
//
// On the site_admin path the plaintext password is passed to the
// repository's Create method, which detects non-PHC strings and
// argon2id-hashes them via internal/crypto. We never store the
// plaintext and we never log it. The local Password buffer is
// zeroed before bootstrapCore returns regardless of outcome.
func bootstrapCore(ctx context.Context, deps bootstrapDeps, opts bootstrapOptions, stdout, stderr io.Writer) (rc int) {
	// Best-effort password scrub. Go strings are immutable so we
	// rebind the field to the zero value; any copies held in lower
	// layers will be garbage-collected on the usual schedule. This
	// is defence-in-depth — the real protection is "never log the
	// value, never include it in error messages".
	defer func() {
		opts.Password = ""
	}()

	// Step 1: signing key. KeyService.ListActive surfaces the
	// active+rotating set used by the bearer-token verifier. We
	// only generate when zero keys exist; any pre-existing key
	// (including one rotated in by a prior bootstrap or via the
	// admin API) is honoured without a new write.
	keySvc := service.NewKeyService(deps.Keys)
	existingKeys, err := keySvc.ListActive(ctx)
	if err != nil {
		fmt.Fprintln(stderr, "identuum-idp: bootstrap: list active signing keys failed:", err)
		return 1
	}
	if len(existingKeys) > 0 {
		fmt.Fprintf(stdout, "identuum-idp: bootstrap: signing key already present (kid=%s, alg=%s) — skip generation\n", existingKeys[0].KID, existingKeys[0].Algorithm)
	} else {
		generated, genErr := keySvc.Generate(ctx, service.GenerateKeyOptions{
			Algorithm: string(opts.Algorithm),
			State:     domain.KeyStateActive,
		})
		if genErr != nil {
			fmt.Fprintln(stderr, "identuum-idp: bootstrap: generate signing key failed:", genErr)
			return 1
		}
		fmt.Fprintf(stdout, "identuum-idp: bootstrap: created signing key (kid=%s, alg=%s)\n", generated.KID, generated.Algorithm)
	}

	// Step 2: site_admin. GetByEmailAndOrgID short-circuits when
	// the row already exists, even if the row's ID is not the
	// SiteAdminID sentinel (e.g. legacy installs that pre-date
	// migration 0016). We do NOT rebind the sentinel after the
	// fact; that's a migration concern, not a bootstrap concern.
	systemOrgID, err := uuid.Parse(domain.SystemOrgID)
	if err != nil {
		fmt.Fprintln(stderr, "identuum-idp: bootstrap: failed to parse domain.SystemOrgID:", err)
		return 1
	}
	siteAdminID, err := uuid.Parse(domain.SiteAdminID)
	if err != nil {
		fmt.Fprintln(stderr, "identuum-idp: bootstrap: failed to parse domain.SiteAdminID:", err)
		return 1
	}

	existing, err := deps.Users.GetByEmailAndOrgID(ctx, systemOrgID, opts.Email)
	switch {
	case err == nil && existing != nil:
		fmt.Fprintf(stdout, "identuum-idp: bootstrap: site_admin already present (id=%s, email=%s) — skip create\n", existing.ID, existing.Email)
		return finishBootstrap(ctx, deps, stdout, stderr)
	case errors.Is(err, domain.ErrUserNotFound):
		// fall through to create
	case err != nil:
		fmt.Fprintln(stderr, "identuum-idp: bootstrap: lookup site_admin failed:", err)
		return 1
	}

	user := &domain.User{
		ID:             siteAdminID,
		OrganizationID: systemOrgID,
		Email:          opts.Email,
		PasswordHash:   opts.Password, // PgxUserRepository.Create argon2id-hashes non-PHC strings
		Role:           domain.RoleSiteAdmin,
		AuthSource:     domain.AuthSourceLocal,
		EmailVerified:  true,
	}
	created, err := deps.Users.Create(ctx, user)
	if err != nil {
		if errors.Is(err, domain.ErrUserAlreadyExists) {
			// "Already exists" was read as "a concurrent bootstrap created MY
			// row" and reported as success. It does not mean that. The insert
			// uses a FIXED sentinel ID, so it also fails when some OTHER row
			// already holds that ID — the ordinary shape of a stack first
			// bootstrapped under a different address via
			// IDENTUUM_IDP_BOOTSTRAP_EMAIL. Nothing was created, and the
			// operator was told otherwise; the next step then fails with
			// "site_admin@system.local does not exist — run 'identuum-idp
			// bootstrap' first", pointing back at the command that just
			// claimed success.
			//
			// So VERIFY the claim instead of assuming it: the row must be
			// there. Only then is a concurrent creator the real explanation.
			if confirmed, lookupErr := deps.Users.GetByEmailAndOrgID(ctx, systemOrgID, opts.Email); lookupErr == nil && confirmed != nil {
				fmt.Fprintf(stdout, "identuum-idp: bootstrap: site_admin row created concurrently (id=%s, email=%s) — treating as success\n", confirmed.ID, confirmed.Email)
				return finishBootstrap(ctx, deps, stdout, stderr)
			}
			fmt.Fprintf(stderr, "identuum-idp: bootstrap: cannot create site_admin %s — the sentinel id %s "+
				"is already held by a DIFFERENT row, and %s itself does not exist. This database was "+
				"bootstrapped under another address (IDENTUUM_IDP_BOOTSTRAP_EMAIL). Bootstrap will NOT "+
				"report success for a row it did not create: re-run with IDENTUUM_IDP_BOOTSTRAP_EMAIL set "+
				"to the existing site_admin, or use 'recover-site-admin' against that address.\n",
				opts.Email, siteAdminID, opts.Email)
			return 1
		}
		fmt.Fprintln(stderr, "identuum-idp: bootstrap: create site_admin failed:", err)
		return 1
	}
	fmt.Fprintf(stdout, "identuum-idp: bootstrap: created site_admin (id=%s, email=%s)\n", created.ID, created.Email)
	return finishBootstrap(ctx, deps, stdout, stderr)
}

// runBootstrap is the CLI entrypoint for the 'bootstrap' subcommand.
// It opens a pgxpool against the operator-supplied It opens a pgxpool against the operator-supplied
// URL, constructs the OSS repository factory, then delegates to
// bootstrapCore. The pool is closed on every exit path. The URL is
// redacted from every error.
func runBootstrap(ctx context.Context, databaseURL string, stdout, stderr io.Writer) int {
	opts, err := loadBootstrapOptions(os.Getenv)
	if err != nil {
		fmt.Fprintln(stderr, "identuum-idp: bootstrap: invalid configuration:", err)
		return 2
	}

	if strings.TrimSpace(databaseURL) == "" {
		fmt.Fprintln(stderr, "identuum-idp: bootstrap: database url is empty")
		return 2
	}

	pool, err := postgres.NewPool(ctx, databaseURL, nil)
	if err != nil {
		fmt.Fprintln(stderr, "identuum-idp: bootstrap: open pool failed:", redactURL(err, databaseURL))
		return 1
	}
	defer pool.Close()

	// P3-5: bootstrap creates a signing key, so it MUST supply a real cipher
	// to encrypt the private material at rest (fail-closed on a missing key).
	keyCipher, err := resolveSigningKeyCipher()
	if err != nil {
		fmt.Fprintln(stderr, "identuum-idp: bootstrap: signing-key encryption unavailable:", err)
		return 2
	}

	repos := postgres.NewPgxRepositories(pool, keyCipher)
	if repos == nil || repos.Key == nil || repos.User == nil {
		fmt.Fprintln(stderr, "identuum-idp: bootstrap: repository factory returned nil")
		return 1
	}

	return bootstrapCore(ctx, bootstrapDeps{
		Keys:  repos.Key,
		Users: repos.User,
		Setup: postgres.NewPgxSetupStateRepository(pool),
	}, opts, stdout, stderr)
}
