package main

// Recovery subcommand for the OSS local-demo runtime.
//
// Why this exists:
//   The bootstrap subcommand (cmd/identuum-idp/bootstrap.go) is idempotent
//   by design: if site_admin@system.local already exists, it skips the
//   create path and does NOT update the password. That is the correct
//   bootstrap posture (re-running bootstrap must not silently overwrite
//   the operator's password), but it leaves a recovery gap: when an
//   earlier bootstrap ran with a password the operator no longer knows,
//   re-running bootstrap is a no-op and the operator is locked out.
//
//   This subcommand is the explicit recovery path: it requires the
//   operator to declare intent by setting a different env var, locates
//   the existing site_admin row by sentinel ID/email, rewrites the
//   password hash, and resets MFA/TOTP enrollment so a fresh first-login
//   flow can proceed against the System Organization's mfa_policy.
//
// What this is (and is not):
//   - This is an explicit, operator-run, audit-friendly CLI subcommand.
//   - It is NOT a bootstrap behaviour change. Re-running bootstrap still
//     skips a pre-existing site_admin without touching the password.
//   - It is NOT an HTTP route. No unauthenticated recovery surface is
//     exposed by the server.
//   - It is NOT auto-fired from the container entrypoint.
//   - It is NOT a backdoor: the password and the resulting hash are
//     never printed. Logs only carry the sentinel user UUID and email.
//   - It refuses to operate on any row whose UUID, role, or organization
//     does not match the SiteAdminID / RoleSiteAdmin / SystemOrgID
//     sentinels. The operator cannot accidentally retarget the recovery
//     onto a tenant user.
//
// Strict no-secret-leak rules enforced below:
//   - The database URL is redacted from every error via redactURL().
//   - The recovery password is read from $IDENTUUM_IDP_RECOVER_SITE_ADMIN_PASSWORD
//     (never a CLI flag value) and is zeroed in the local buffer after
//     the update completes.
//   - The resulting argon2id hash is produced inside PgxUserRepository.Update
//     and never crosses the recover boundary.
//   - All log lines on every code path are safe to copy/paste into PRs.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/postgres"
	"github.com/identuum/identuum-idp-oss/internal/repository"
)

// envRecoverPassword names the only env-var the recovery path reads.
// Stable wire-format: documented in
// identuum-idp/docs/open-core/IDP_OSS_RECOVER_SITE_ADMIN_PASSWORD.md
// and referenced by the make oss-recover-site-admin target. Changing
// it is a breaking change for operator scripts.
const envRecoverPassword = "IDENTUUM_IDP_RECOVER_SITE_ADMIN_PASSWORD"

// recoverOptions is the parsed env-driven configuration consumed by
// recoverSiteAdminCore. Keeping it separate from os.Getenv lets the
// unit tests exercise the full state machine without touching process
// env.
type recoverOptions struct {
	Password string
}

// loadRecoverOptions reads + validates the env var. The password is
// required. Returns a non-nil error only on a missing/empty password.
// The password is never echoed back through the error message.
func loadRecoverOptions(getenv func(string) string) (recoverOptions, error) {
	pw := getenv(envRecoverPassword)
	if pw == "" {
		return recoverOptions{}, fmt.Errorf("%s is required (not set or empty)", envRecoverPassword)
	}
	// --recover-site-admin resets the SITE_ADMIN row — control-plane
	// infrastructure per Decision D-004. STRICT password validation
	// is mandatory; the SystemOrg has no per-org policy to consult.
	// Wired by slice agent-a-20260715-idp-oss-password-complexity-
	// perorg-enforcement (Decision D-015 §9 EXCLUDED control-plane).
	// The password value is NOT included in the error message.
	if err := domain.ValidatePassword(pw, 12); err != nil {
		return recoverOptions{}, fmt.Errorf("%s failed strict policy: %w (password value redacted)", envRecoverPassword, err)
	}
	return recoverOptions{Password: pw}, nil
}

// recoverSiteAdminCore is the pure state machine. It is idempotent in
// the sense that repeated runs target the same single sentinel row and
// always result in the SAME user existing with the latest password.
// Returns the process exit code (0 on success, non-zero on failure).
// Successful log lines go to stdout; failures go to stderr.
//
// Defensive sentinel checks: the function refuses to update unless the
// located row's ID, OrganizationID, and Role all match the
// SiteAdminID / SystemOrgID / RoleSiteAdmin sentinels. The site_admin
// email lookup is the only "soft" handle; the three sentinel checks
// then anchor the update so a mis-seeded row cannot be silently
// promoted via this command.
//
// Effects on the located row:
//   - password_hash rewritten (argon2id produced inside the repo layer
//     by PgxUserRepository.Update; the plaintext never persists)
//   - mfa_enabled = false
//   - mfa_secret = "" (cleared)
//   - mfa_recovery_codes = [] (cleared)
//   - requires_password_change = false
//
// Untouched: id, email, role, organization_id, auth_source,
// email_verified, banned, deleted_at, external_id, oidc_linked,
// oidc_issuer, activation_token_*, verification_token_hash, name.
func recoverSiteAdminCore(ctx context.Context, userRepo repository.UserRepository, opts recoverOptions, stdout, stderr io.Writer) (rc int) {
	defer func() {
		opts.Password = ""
	}()

	systemOrgID, err := uuid.Parse(domain.SystemOrgID)
	if err != nil {
		fmt.Fprintln(stderr, "identuum-idp: recover: failed to parse domain.SystemOrgID:", err)
		return 1
	}
	siteAdminID, err := uuid.Parse(domain.SiteAdminID)
	if err != nil {
		fmt.Fprintln(stderr, "identuum-idp: recover: failed to parse domain.SiteAdminID:", err)
		return 1
	}

	existing, err := userRepo.GetByEmailAndOrgID(ctx, systemOrgID, domain.SiteAdminEmail)
	switch {
	case errors.Is(err, domain.ErrUserNotFound):
		fmt.Fprintf(stderr, "identuum-idp: recover: %s does not exist — run 'identuum-idp bootstrap' first\n", domain.SiteAdminEmail)
		return 1
	case err != nil:
		fmt.Fprintln(stderr, "identuum-idp: recover: lookup site_admin failed:", err)
		return 1
	case existing == nil:
		fmt.Fprintf(stderr, "identuum-idp: recover: %s lookup returned nil without error\n", domain.SiteAdminEmail)
		return 1
	}

	if existing.ID != siteAdminID {
		fmt.Fprintf(stderr, "identuum-idp: recover: refusing to update — located row id=%s does not match domain.SiteAdminID sentinel %s\n", existing.ID, siteAdminID)
		return 1
	}
	if existing.OrganizationID != systemOrgID {
		fmt.Fprintf(stderr, "identuum-idp: recover: refusing to update — located row organization_id=%s does not match domain.SystemOrgID sentinel %s\n", existing.OrganizationID, systemOrgID)
		return 1
	}
	if existing.Role != domain.RoleSiteAdmin {
		fmt.Fprintf(stderr, "identuum-idp: recover: refusing to update — located row role=%q is not %q\n", existing.Role, domain.RoleSiteAdmin)
		return 1
	}

	pw := opts.Password
	mfaDisabled := false
	mfaSecretEmpty := ""
	requiresChangeFalse := false
	update := repository.UpdateUserOptions{
		Password:               &pw,
		MFAEnabled:             &mfaDisabled,
		MFASecret:              &mfaSecretEmpty,
		MFARecoveryCodes:       []string{}, // non-nil empty triggers SET to []
		RequiresPasswordChange: &requiresChangeFalse,
	}

	updated, err := userRepo.Update(ctx, existing.ID, existing.OrganizationID, update)
	if err != nil {
		fmt.Fprintln(stderr, "identuum-idp: recover: update site_admin failed:", err)
		return 1
	}
	if updated == nil {
		fmt.Fprintln(stderr, "identuum-idp: recover: update site_admin returned nil user")
		return 1
	}

	fmt.Fprintf(stdout, "identuum-idp: recover: site_admin password updated (id=%s, email=%s, mfa_reset=true, requires_password_change=false)\n", updated.ID, updated.Email)
	return 0
}

// runRecoverSiteAdmin is the CLI entrypoint wired into the
// --recover-site-admin flag in main.go's switch. It opens a pgxpool
// against the operator-supplied URL, constructs the OSS repository
// factory, then delegates to recoverSiteAdminCore. The pool is closed
// on every exit path. The URL is redacted from every error.
func runRecoverSiteAdmin(ctx context.Context, databaseURL string, stdout, stderr io.Writer) int {
	opts, err := loadRecoverOptions(os.Getenv)
	if err != nil {
		fmt.Fprintln(stderr, "identuum-idp: recover: invalid configuration:", err)
		return 2
	}

	if strings.TrimSpace(databaseURL) == "" {
		fmt.Fprintln(stderr, "identuum-idp: recover: database url is empty")
		return 2
	}

	pool, err := postgres.NewPool(ctx, databaseURL, nil)
	if err != nil {
		fmt.Fprintln(stderr, "identuum-idp: recover: open pool failed:", redactURL(err, databaseURL))
		return 1
	}
	defer pool.Close()

	// recover-site-admin never creates or reads signing keys, so it passes a
	// nil key cipher (the key repository is fail-closed: a nil cipher can
	// never write plaintext).
	repos := postgres.NewPgxRepositories(pool, nil)
	if repos == nil || repos.User == nil {
		fmt.Fprintln(stderr, "identuum-idp: recover: repository factory returned nil")
		return 1
	}

	return recoverSiteAdminCore(ctx, repos.User, opts, stdout, stderr)
}
