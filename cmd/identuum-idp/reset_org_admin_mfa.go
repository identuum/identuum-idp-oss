package main

// The reset-org-admin-mfa subcommand (owner ruling, v0.9.5) — a one-shot that
// gives an organization back its administrator after every factor is lost:
//
//	identuum-idp reset-org-admin-mfa --org <organization-id> --email <address> [database-url]
//
// It removes the org_admin's authenticator, recovery codes and passkeys,
// revokes its sessions and refresh tokens, and records org_admin_mfa_reset by
// the system actor. The administrator then signs in with the password and
// enrolls a new factor. A site_admin cannot do this over the API (D-025), so
// the path needs host access: in the distroless image,
//
//	docker exec identuum-idp-oss /app/identuum-idp reset-org-admin-mfa --org <id> --email <address>
//
// or a one-shot container with --entrypoint /app/identuum-idp and the
// database URL. It refuses the system organization (recover-site-admin is its
// command) and any user who is not exactly an org_admin. The database URL
// follows the shared one-shot precedence and is never printed.

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/postgres"
	"github.com/identuum/identuum-idp-oss/internal/repository"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// resetOrgAdminMFADeps is what the command acts through.
type resetOrgAdminMFADeps struct {
	Users    repository.UserRepository
	Passkeys service.PasskeyStore
	Sessions interface {
		RevokeByUserID(ctx context.Context, userID uuid.UUID, reason string) error
	}
	Refresh interface {
		RevokeAllBySubject(ctx context.Context, subject string, at time.Time) (int64, error)
	}
	Audit *service.OperatorAuditor
	Now   func() time.Time
}

// dispatchResetOrgAdminMFA parses the subcommand. --org and --email are
// checked before the database URL is resolved, so a malformed call never
// contacts a database.
func dispatchResetOrgAdminMFA(ctx context.Context, rest []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("identuum-idp reset-org-admin-mfa", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var orgArg, email string
	fs.StringVar(&orgArg, "org", "", "REQUIRED. The organization id.")
	fs.StringVar(&email, "email", "", "REQUIRED. The org_admin's email address.")
	if err := fs.Parse(rest); err != nil {
		return 2
	}
	orgID, err := uuid.Parse(strings.TrimSpace(orgArg))
	if err != nil || strings.TrimSpace(email) == "" {
		fmt.Fprintln(stderr, "identuum-idp: reset-org-admin-mfa requires --org <organization-id> and --email <address> (flags before the database URL)")
		return 2
	}
	if fs.NArg() > 1 {
		fmt.Fprintf(stderr, "identuum-idp: reset-org-admin-mfa: unexpected arguments after the database URL: %v\n", fs.Args()[1:])
		return 2
	}
	url, ok := requirePositionalURL("reset-org-admin-mfa", fs.Args(), stderr)
	if !ok {
		return 2
	}
	return runResetOrgAdminMFA(ctx, url, orgID, strings.TrimSpace(email), stdout, stderr)
}

// runResetOrgAdminMFA opens the database and delegates to the core. Errors are
// redacted so the URL never appears in output.
func runResetOrgAdminMFA(ctx context.Context, databaseURL string, orgID uuid.UUID, email string, stdout, stderr io.Writer) int {
	pool, err := postgres.NewPool(ctx, databaseURL, nil)
	if err != nil {
		fmt.Fprintln(stderr, "identuum-idp: reset-org-admin-mfa: open pool failed:", redactURL(err, databaseURL))
		return 1
	}
	defer pool.Close()
	// No signing key is read or written, so the key cipher is nil (the key
	// repository is fail-closed).
	repos := postgres.NewPgxRepositories(pool, nil)
	if repos == nil || repos.User == nil || repos.WebAuthnCredential == nil || repos.Session == nil || repos.RefreshToken == nil || repos.Audit == nil {
		fmt.Fprintln(stderr, "identuum-idp: reset-org-admin-mfa: repository factory returned nil")
		return 1
	}
	return resetOrgAdminMFACore(ctx, resetOrgAdminMFADeps{
		Users:    repos.User,
		Passkeys: repos.WebAuthnCredential,
		Sessions: repos.Session,
		Refresh:  repos.RefreshToken,
		Audit:    service.NewOperatorAuditor(repos.Audit),
		Now:      time.Now,
	}, orgID, email, stdout, stderr)
}

// resetOrgAdminMFACore finds the org_admin, clears every factor, revokes its
// sessions and refresh tokens, and records the reset.
func resetOrgAdminMFACore(ctx context.Context, deps resetOrgAdminMFADeps, orgID uuid.UUID, email string, stdout, stderr io.Writer) int {
	if orgID.String() == domain.SystemOrgID {
		fmt.Fprintln(stderr, "identuum-idp: reset-org-admin-mfa: refused — the system organization's administrator is the site_admin; use recover-site-admin")
		return 1
	}
	user, err := deps.Users.GetByEmailAndOrgID(ctx, orgID, email)
	switch {
	case errors.Is(err, domain.ErrUserNotFound), err == nil && user == nil:
		fmt.Fprintf(stderr, "identuum-idp: reset-org-admin-mfa: no user %s in organization %s\n", email, orgID)
		return 1
	case err != nil:
		fmt.Fprintln(stderr, "identuum-idp: reset-org-admin-mfa: lookup failed:", err)
		return 1
	}
	if user.Role != domain.RoleOrgAdmin {
		fmt.Fprintf(stderr, "identuum-idp: reset-org-admin-mfa: refused — %s is %q, not %q; its organization's org_admin resets it\n", email, user.Role, domain.RoleOrgAdmin)
		return 1
	}
	users := service.NewUserService(nil, deps.Users).WithPasskeyStore(deps.Passkeys)
	if _, err := users.ResetMFA(ctx, user.ID, orgID); err != nil {
		fmt.Fprintln(stderr, "identuum-idp: reset-org-admin-mfa: reset failed:", err)
		return 1
	}
	sessionsRevoked := deps.Sessions.RevokeByUserID(ctx, user.ID, "mfa_reset_by_operator") == nil
	refreshRevoked, refreshErr := deps.Refresh.RevokeAllBySubject(ctx, user.ID.String(), deps.Now().UTC())
	var revokedCount *int64
	if refreshErr == nil {
		revokedCount = &refreshRevoked
	}
	deps.Audit.OrgAdminMFAReset(ctx, user, sessionsRevoked, revokedCount)
	fmt.Fprintf(stdout, "identuum-idp: reset-org-admin-mfa: the second factor and passkeys of %s (organization %s) are removed; sessions revoked=%t, refresh tokens revoked=%t. Sign in with the password and enroll a new factor.\n",
		user.Email, orgID, sessionsRevoked, refreshErr == nil)
	if !sessionsRevoked || refreshErr != nil {
		return 1
	}
	return 0
}
