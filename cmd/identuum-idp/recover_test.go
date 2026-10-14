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
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// recoverSessionSink records whose sessions recover-site-admin ended and can
// fail on demand (OSS-RECOVER-REVOKE).
type recoverSessionSink struct {
	users []uuid.UUID
	err   error
}

func (s *recoverSessionSink) RevokeByUserID(_ context.Context, userID uuid.UUID, _ string) error {
	if s.err != nil {
		return s.err
	}
	s.users = append(s.users, userID)
	return nil
}

// recoverRefreshSink records whose refresh tokens (and linked access JTIs)
// recover-site-admin ended and can fail on demand.
type recoverRefreshSink struct {
	users []uuid.UUID
	n     int64
	err   error
}

func (s *recoverRefreshSink) RevokeAllForUser(_ context.Context, userID uuid.UUID) (int64, error) {
	if s.err != nil {
		return 0, s.err
	}
	s.users = append(s.users, userID)
	return s.n, nil
}

// recoverDepsFor wires the fake user repository with sinks that never fail,
// for the tests that are about the user row and not the revocation.
func recoverDepsFor(repo *memUserRepo) recoverDeps {
	return recoverDeps{Users: repo, Sessions: &recoverSessionSink{}, Refresh: &recoverRefreshSink{},
		Audit: service.NewOperatorAuditor(&auditRows{})}
}

// failingAuditRows is an audit log whose every insert fails.
type failingAuditRows struct{}

func (failingAuditRows) Insert(context.Context, domain.AuditEvent) error {
	return errors.New("audit store down")
}

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

	rc := recoverSiteAdminCore(context.Background(), recoverDepsFor(repo), opts, &stdout, &stderr)
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
	rc := recoverSiteAdminCore(context.Background(), recoverDepsFor(repo), opts, &stdout, &stderr)
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

// RULE: RECOVER-1
func TestRecoverSiteAdminCore_RefusesWrongSentinelID(t *testing.T) {
	t.Parallel()

	repo := seedBootstrappedSiteAdmin(t)
	// Drift the ID — simulates a legacy install where the bootstrap row
	// is keyed by a non-sentinel UUIDv7. Recovery must refuse.
	repo.users[0].ID = uuid.MustParse("01900000-0000-7000-8000-000000abcdef")

	sessions := &recoverSessionSink{}
	refresh := &recoverRefreshSink{}
	rec := &auditRows{}
	var stdout, stderr bytes.Buffer
	rc := recoverSiteAdminCore(context.Background(), recoverDeps{Users: repo, Sessions: sessions, Refresh: refresh, Audit: service.NewOperatorAuditor(rec)},
		recoverOptions{Password: "demo-only"}, &stdout, &stderr)
	if rc == 0 {
		t.Fatal("expected non-zero rc on sentinel ID drift")
	}
	if !strings.Contains(stderr.String(), "does not match domain.SiteAdminID") {
		t.Fatalf("expected sentinel-mismatch error, got %q", stderr.String())
	}
	// A refusal ends nothing: the drifted row's sessions are not the
	// site_admin's to revoke.
	if len(sessions.users) != 0 || len(refresh.users) != 0 {
		t.Fatalf("a refusal revoked sessions %v / refresh tokens %v", sessions.users, refresh.users)
	}
	// And records nothing: no recovery happened.
	if len(rec.rows) != 0 {
		t.Fatalf("a refusal wrote %d audit rows", len(rec.rows))
	}
}

func TestRecoverSiteAdminCore_RefusesWrongRole(t *testing.T) {
	t.Parallel()

	repo := seedBootstrappedSiteAdmin(t)
	repo.users[0].Role = domain.RoleOrgAdmin

	var stdout, stderr bytes.Buffer
	rc := recoverSiteAdminCore(context.Background(), recoverDepsFor(repo), recoverOptions{Password: "demo-only"}, &stdout, &stderr)
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
		rc := recoverSiteAdminCore(context.Background(), recoverDepsFor(repo), recoverOptions{Password: pw}, &stdout, &stderr)
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
	rc := recoverSiteAdminCore(context.Background(), recoverDepsFor(repo), recoverOptions{Password: secret}, &stdout, &stderr)
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

// --- OSS-RECOVER-REVOKE: the recovery ends what the old credentials minted ---

// RULE: RECOVER-2
func TestRecoverSiteAdminCore_EndsTheSiteAdminsSessionsAndTokens(t *testing.T) {
	t.Parallel()

	repo := seedBootstrappedSiteAdmin(t)
	sessions := &recoverSessionSink{}
	refresh := &recoverRefreshSink{n: 3}
	var stdout, stderr bytes.Buffer
	rc := recoverSiteAdminCore(context.Background(), recoverDeps{Users: repo, Sessions: sessions, Refresh: refresh, Audit: service.NewOperatorAuditor(&auditRows{})},
		recoverOptions{Password: "new-demo-password-not-printed"}, &stdout, &stderr)
	if rc != 0 {
		t.Fatalf("expected rc=0, got %d (stderr=%s)", rc, stderr.String())
	}
	siteAdminID := uuid.MustParse(domain.SiteAdminID)
	// Exactly the site_admin's sessions and refresh tokens end — once each,
	// nobody else's.
	if len(sessions.users) != 1 || sessions.users[0] != siteAdminID {
		t.Errorf("sessions revoked for %v, want exactly the site_admin %s", sessions.users, siteAdminID)
	}
	if len(refresh.users) != 1 || refresh.users[0] != siteAdminID {
		t.Errorf("refresh tokens revoked for %v, want exactly the site_admin %s", refresh.users, siteAdminID)
	}
	for _, want := range []string{"site_admin password updated", "sessions_revoked=true", "refresh_tokens_revoked=3"} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("stdout lacks %q: %q", want, stdout.String())
		}
	}
}

// RULE: RECOVER-4
func TestRecoverSiteAdminCore_RevocationFailureExitsNonZero(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name     string
		sessions *recoverSessionSink
		refresh  *recoverRefreshSink
	}{
		{"sessions", &recoverSessionSink{err: errors.New("sessions store down")}, &recoverRefreshSink{}},
		{"refresh tokens", &recoverSessionSink{}, &recoverRefreshSink{err: errors.New("refresh store down")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			repo := seedBootstrappedSiteAdmin(t)
			rec := &auditRows{}
			var stdout, stderr bytes.Buffer
			rc := recoverSiteAdminCore(context.Background(), recoverDeps{Users: repo, Sessions: tc.sessions, Refresh: tc.refresh, Audit: service.NewOperatorAuditor(rec)},
				recoverOptions{Password: "new-demo-password-not-printed"}, &stdout, &stderr)
			if rc == 0 {
				t.Fatalf("rc = 0 although revoking the %s failed", tc.name)
			}
			// The credential still changed, so the recovery is recorded — as a
			// failure, without a refresh count.
			if len(rec.rows) != 1 || rec.rows[0].EventType != domain.AuditSiteAdminCredentialsReset || rec.rows[0].Outcome == nil ||
				*rec.rows[0].Outcome != "failure" || rec.rows[0].Metadata["refresh_tokens_revoked_count"] != nil {
				t.Errorf("audit rows = %+v, want one site_admin_credentials_reset with outcome failure and no refresh count", rec.rows)
			}
			// Never a success line over live sessions.
			if strings.Contains(stdout.String(), "site_admin password updated") {
				t.Errorf("success was reported with the %s still live: %q", tc.name, stdout.String())
			}
			for _, want := range []string{"revoking the site_admin's " + tc.name + " failed", "run recover-site-admin again"} {
				if !strings.Contains(stderr.String(), want) {
					t.Errorf("stderr lacks %q: %q", want, stderr.String())
				}
			}
		})
	}
}

// --- OSS-0914-RECOVER-AUDIT: the recovery leaves an audit record ---

// RULE: RECOVER-AUDIT-1
func TestRecoverSiteAdminCore_RecordsOneAuditEvent(t *testing.T) {
	t.Parallel()

	const secret = "recover-audit-marker-never-recorded"
	repo := seedBootstrappedSiteAdmin(t)
	rec := &auditRows{}
	var stdout, stderr bytes.Buffer
	rc := recoverSiteAdminCore(context.Background(), recoverDeps{Users: repo, Sessions: &recoverSessionSink{}, Refresh: &recoverRefreshSink{n: 2},
		Audit: service.NewOperatorAuditor(rec)}, recoverOptions{Password: secret}, &stdout, &stderr)
	if rc != 0 {
		t.Fatalf("rc = %d, stderr = %s", rc, stderr.String())
	}
	if len(rec.rows) != 1 {
		t.Fatalf("audit rows = %d, want exactly 1", len(rec.rows))
	}
	e := rec.rows[0]
	siteAdminID := uuid.MustParse(domain.SiteAdminID)
	if e.EventType != domain.AuditSiteAdminCredentialsReset || e.Outcome == nil || *e.Outcome != "success" || e.ActorType != "system" ||
		e.OrganizationID == nil || e.OrganizationID.String() != domain.SystemOrgID || e.SubjectID == nil || *e.SubjectID != siteAdminID {
		t.Errorf("audit row = %+v, want site_admin_credentials_reset, success, by the system actor, in the system organization, about the site_admin", e)
	}
	if e.Metadata["via"] != "cli" || e.Metadata["user_id"] != siteAdminID || e.Metadata["sessions_revoked"] != true ||
		e.Metadata["refresh_tokens_revoked_count"] != int64(2) {
		t.Errorf("audit metadata = %v, want via=cli, the site_admin's user_id, sessions_revoked=true, 2 refresh tokens", e.Metadata)
	}
	// Never the password, the resulting hash or the environment value's name.
	row := fmt.Sprintf("%+v %v", e, e.Metadata)
	for name, s := range map[string]string{"password": secret, "hash": repo.users[0].PasswordHash, "environment variable": envRecoverPassword} {
		if strings.Contains(row, s) {
			t.Errorf("the audit row carries the %s", name)
		}
	}
}

func TestRecoverSiteAdminCore_RefusedRecoveryRecordsNothing(t *testing.T) {
	t.Parallel()

	rec := &auditRows{}
	deps := recoverDepsFor(&memUserRepo{})
	deps.Audit = service.NewOperatorAuditor(rec)
	var stdout, stderr bytes.Buffer
	if rc := recoverSiteAdminCore(context.Background(), deps, recoverOptions{Password: "demo-only"}, &stdout, &stderr); rc == 0 {
		t.Fatal("rc = 0 with no site_admin row")
	}
	if len(rec.rows) != 0 {
		t.Fatalf("a refused recovery wrote %d audit rows", len(rec.rows))
	}
}

func TestRecoverSiteAdminCore_AuditWriteFailureExitsNonZero(t *testing.T) {
	t.Parallel()

	repo := seedBootstrappedSiteAdmin(t)
	deps := recoverDepsFor(repo)
	deps.Audit = service.NewOperatorAuditor(failingAuditRows{})
	var stdout, stderr bytes.Buffer
	if rc := recoverSiteAdminCore(context.Background(), deps, recoverOptions{Password: "new-demo-password-not-printed"}, &stdout, &stderr); rc == 0 {
		t.Fatal("rc = 0 although the audit event was not written")
	}
	if strings.Contains(stdout.String(), "site_admin password updated") {
		t.Errorf("success was reported without its audit record: %q", stdout.String())
	}
	for _, want := range []string{"writing the site_admin_credentials_reset audit event failed", "run recover-site-admin again"} {
		if !strings.Contains(stderr.String(), want) {
			t.Errorf("stderr lacks %q: %q", want, stderr.String())
		}
	}
}

func TestRecoverSiteAdminCore_RefusesWithoutAnAuditSink(t *testing.T) {
	t.Parallel()

	repo := seedBootstrappedSiteAdmin(t)
	deps := recoverDepsFor(repo)
	deps.Audit = nil
	var stdout, stderr bytes.Buffer
	if rc := recoverSiteAdminCore(context.Background(), deps, recoverOptions{Password: "new-demo-password-not-printed"}, &stdout, &stderr); rc == 0 {
		t.Fatal("rc = 0 with no audit sink")
	}
	if repo.users[0].PasswordHash != "$argon2id$placeholder$old$hash$bytes" {
		t.Error("the password changed although the recovery could not be recorded")
	}
}
