package main

// Unit tests for the recover-site-admin subcommand. These exercise the
// pure state-machine half (recoverSiteAdminCore + loadRecoverOptions)
// using the in-memory repository fakes shared with bootstrap_test.go.
// The pgxpool plumbing in runRecoverSiteAdmin is covered by the
// existing integration harness path; here we focus on:
//
//   1. Env-var validation.
//   2. The happy path: existing site_admin row gets its password hash
//      rewritten + MFA state cleared.
//   3. Sentinel-mismatch refusals (wrong ID, wrong org, wrong role).
//   4. Idempotency: repeated runs target the same single row and never
//      create a duplicate user.
//   5. No-leak invariants on stdout/stderr (password absence).
//   6. The "site_admin does not exist" path returns a non-zero rc.

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// seedBootstrappedSiteAdmin returns a memUserRepo containing exactly
// one row that mirrors what `--bootstrap` produces. Tests mutate the
// returned repo to exercise drift cases (wrong role, wrong org, etc.).
func seedBootstrappedSiteAdmin(t *testing.T) *memUserRepo {
	t.Helper()
	systemOrgID := uuid.MustParse(domain.SystemOrgID)
	siteAdminID := uuid.MustParse(domain.SiteAdminID)
	mfaSecret := "OLDSTALETOTPSECRET" // sentinel — never the real value
	return &memUserRepo{
		users: []*domain.User{{
			ID:               siteAdminID,
			OrganizationID:   systemOrgID,
			Email:            domain.SiteAdminEmail,
			PasswordHash:     "$argon2id$placeholder$old$hash$bytes",
			Role:             domain.RoleSiteAdmin,
			AuthSource:       domain.AuthSourceLocal,
			EmailVerified:    true,
			MFAEnabled:       true,
			MFASecret:        &mfaSecret,
			MFARecoveryCodes: []string{"code-a", "code-b"},
		}},
	}
}

// --- loadRecoverOptions tests ----------------------------------------------

func TestLoadRecoverOptions(t *testing.T) {
	t.Parallel()

	t.Run("password required", func(t *testing.T) {
		t.Parallel()
		_, err := loadRecoverOptions(func(string) string { return "" })
		if err == nil || !strings.Contains(err.Error(), envRecoverPassword) {
			t.Fatalf("expected error mentioning %s, got %v", envRecoverPassword, err)
		}
	})

	t.Run("password supplied", func(t *testing.T) {
		t.Parallel()
		got, err := loadRecoverOptions(func(k string) string {
			if k == envRecoverPassword {
				return "Demo-Only-Not-Printed-1!"
			}
			return ""
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.Password != "Demo-Only-Not-Printed-1!" {
			t.Fatal("password not threaded through")
		}
	})

	t.Run("weak password rejected by strict policy", func(t *testing.T) {
		// Forward-compat pin for the control-plane strict-validation
		// contract per Decision D-015 §9: the SystemOrg has no per-org
		// policy, so --recover-site-admin MUST use strict mode
		// unconditionally. A length-only password ("demo-only-not-printed",
		// 21 chars, no uppercase/digit/special) MUST be rejected.
		t.Parallel()
		_, err := loadRecoverOptions(func(k string) string {
			if k == envRecoverPassword {
				return "demo-only-not-printed"
			}
			return ""
		})
		if err == nil {
			t.Fatal("STRICT-CONTROL-PLANE INVARIANT VIOLATED: weak password must be rejected by recover-site-admin (Decision D-004 + D-015 §9 EXCLUDED control-plane)")
		}
	})
}

// --- recoverSiteAdminCore tests --------------------------------------------

func TestRecoverSiteAdminCore_HappyPath(t *testing.T) {
	t.Parallel()

	repo := seedBootstrappedSiteAdmin(t)
	opts := recoverOptions{Password: "new-demo-password-not-printed"}
	var stdout, stderr bytes.Buffer

	rc := recoverSiteAdminCore(context.Background(), repo, opts, &stdout, &stderr)
	if rc != 0 {
		t.Fatalf("expected rc=0, got %d (stderr=%s)", rc, stderr.String())
	}

	if !strings.Contains(stdout.String(), "site_admin password updated") {
		t.Fatalf("expected success log, got %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "mfa_reset=true") {
		t.Fatalf("expected mfa_reset=true marker in log, got %q", stdout.String())
	}

	if len(repo.users) != 1 {
		t.Fatalf("expected exactly 1 user after recovery, got %d", len(repo.users))
	}
	u := repo.users[0]

	// Sentinel fields preserved.
	if u.ID.String() != domain.SiteAdminID {
		t.Fatalf("expected SiteAdminID preserved, got %s", u.ID)
	}
	if u.OrganizationID.String() != domain.SystemOrgID {
		t.Fatalf("expected SystemOrgID preserved, got %s", u.OrganizationID)
	}
	if u.Role != domain.RoleSiteAdmin {
		t.Fatalf("expected RoleSiteAdmin preserved, got %q", u.Role)
	}
	if u.Email != domain.SiteAdminEmail {
		t.Fatalf("expected email preserved, got %q", u.Email)
	}
	if !u.EmailVerified {
		t.Fatal("expected EmailVerified preserved=true")
	}
	if u.AuthSource != domain.AuthSourceLocal {
		t.Fatalf("expected AuthSourceLocal preserved, got %q", u.AuthSource)
	}

	// Password rewritten.
	if u.PasswordHash == "$argon2id$placeholder$old$hash$bytes" {
		t.Fatal("password hash was NOT rewritten")
	}

	// MFA state reset.
	if u.MFAEnabled {
		t.Fatal("expected MFAEnabled=false after recovery")
	}
	if u.MFASecret == nil || *u.MFASecret != "" {
		t.Fatalf("expected MFASecret cleared to empty string, got %v", u.MFASecret)
	}
	if len(u.MFARecoveryCodes) != 0 {
		t.Fatalf("expected MFARecoveryCodes cleared, got %v", u.MFARecoveryCodes)
	}
	if u.RequiresPasswordChange {
		t.Fatal("expected RequiresPasswordChange=false after recovery")
	}
}

func TestRecoverSiteAdminCore_MissingSiteAdmin(t *testing.T) {
	t.Parallel()

	repo := &memUserRepo{}
	opts := recoverOptions{Password: "demo-only"}
	var stdout, stderr bytes.Buffer
	rc := recoverSiteAdminCore(context.Background(), repo, opts, &stdout, &stderr)
	if rc == 0 {
		t.Fatalf("expected non-zero rc when site_admin absent, got 0 (stdout=%s)", stdout.String())
	}
	if !strings.Contains(stderr.String(), "does not exist") {
		t.Fatalf("expected 'does not exist' guidance, got %q", stderr.String())
	}
	if !strings.Contains(stderr.String(), "'identuum-idp bootstrap' first") {
		t.Fatalf("expected pointer to bootstrap subcommand, got %q", stderr.String())
	}
}

func TestRecoverSiteAdminCore_RefusesWrongSentinelID(t *testing.T) {
	t.Parallel()

	repo := seedBootstrappedSiteAdmin(t)
	// Drift the ID — simulates a legacy install where the bootstrap row
	// is keyed by a non-sentinel UUIDv7. Recovery must refuse.
	repo.users[0].ID = uuid.MustParse("01900000-0000-7000-8000-000000abcdef")

	var stdout, stderr bytes.Buffer
	rc := recoverSiteAdminCore(context.Background(), repo, recoverOptions{Password: "demo-only"}, &stdout, &stderr)
	if rc == 0 {
		t.Fatal("expected non-zero rc on sentinel ID drift")
	}
	if !strings.Contains(stderr.String(), "does not match domain.SiteAdminID") {
		t.Fatalf("expected sentinel-mismatch error, got %q", stderr.String())
	}
}

func TestRecoverSiteAdminCore_RefusesWrongRole(t *testing.T) {
	t.Parallel()

	repo := seedBootstrappedSiteAdmin(t)
	repo.users[0].Role = domain.RoleOrgAdmin

	var stdout, stderr bytes.Buffer
	rc := recoverSiteAdminCore(context.Background(), repo, recoverOptions{Password: "demo-only"}, &stdout, &stderr)
	if rc == 0 {
		t.Fatal("expected non-zero rc on role drift")
	}
	if !strings.Contains(stderr.String(), `not "site_admin"`) {
		t.Fatalf("expected role-mismatch error, got %q", stderr.String())
	}
}

func TestRecoverSiteAdminCore_Idempotent(t *testing.T) {
	t.Parallel()

	repo := seedBootstrappedSiteAdmin(t)
	for i, pw := range []string{"first-pw", "second-pw", "third-pw"} {
		var stdout, stderr bytes.Buffer
		rc := recoverSiteAdminCore(context.Background(), repo, recoverOptions{Password: pw}, &stdout, &stderr)
		if rc != 0 {
			t.Fatalf("invocation %d: expected rc=0, got %d (stderr=%s)", i, rc, stderr.String())
		}
		if len(repo.users) != 1 {
			t.Fatalf("invocation %d: expected exactly 1 user, got %d", i, len(repo.users))
		}
		if repo.users[0].ID.String() != domain.SiteAdminID {
			t.Fatalf("invocation %d: sentinel ID drift", i)
		}
		if repo.users[0].PasswordHash != pw {
			t.Fatalf("invocation %d: password not updated", i)
		}
	}
}

func TestRecoverSiteAdminCore_NeverLeaksPassword(t *testing.T) {
	t.Parallel()

	const secret = "recover-marker-zzz-never-printed"
	repo := seedBootstrappedSiteAdmin(t)
	var stdout, stderr bytes.Buffer
	rc := recoverSiteAdminCore(context.Background(), repo, recoverOptions{Password: secret}, &stdout, &stderr)
	if rc != 0 {
		t.Fatalf("expected rc=0, got %d", rc)
	}
	// PREMISE: a successful recovery PRINTS its confirmation. An empty
	// transcript contains no password by definition, so without this the
	// sweep below proves nothing (V4).
	if stdout.Len() == 0 {
		t.Fatalf("recover printed nothing — an empty transcript cannot leak, so the sweep below would pass vacuously")
	}
	for name, buf := range map[string]*bytes.Buffer{"stdout": &stdout, "stderr": &stderr} {
		if strings.Contains(buf.String(), secret) {
			t.Fatalf("%s contained recovery password marker", name)
		}
	}
}
