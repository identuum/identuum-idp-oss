//go:build integration

package main

// OSS-RECOVER-REVOKE (2026-10-09): against the live schema, recover-site-admin
// ends what the old credentials minted and nothing else. A site_admin session
// and a refresh token (with its linked access-token JTI) minted BEFORE the
// recovery are refused after it — the session by the liveness verdict the
// bearer gate uses, the refresh token by the grant's Consume, the JTI by the
// denylist — while another user's session and refresh token still work.
// FAIL-not-skip: a missing DSN fails like every other integration tooth.

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/postgres"
	"github.com/identuum/identuum-idp-oss/internal/repository"
	"github.com/identuum/identuum-idp-oss/internal/service"
	"github.com/identuum/identuum-idp-oss/internal/testsupport"
)

func recoverTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	var dsn string
	for _, env := range []string{"IDENTUUM_IDP_TEST_DATABASE_URL", "IDENTUUM_IDP_DATABASE_URL"} {
		if v := os.Getenv(env); v != "" {
			dsn = v
			break
		}
	}
	if dsn == "" {
		t.Fatal("IDENTUUM_IDP_TEST_DATABASE_URL (or IDENTUUM_IDP_DATABASE_URL) is not set; the recover-site-admin " +
			"revocation tooth was requested via -tags integration and requires a live Postgres DSN. " +
			"`make integration-test` supplies it automatically (Makefile)")
	}
	if err := testsupport.RequireTestDatabase(dsn); err != nil {
		t.Fatal(err)
	}
	stdlibDB, err := postgres.OpenStdlibDB(dsn)
	if err != nil {
		t.Fatalf("open stdlib db (URL redacted): %v", err)
	}
	if _, err := postgres.RunMigrations(context.Background(), stdlibDB); err != nil {
		t.Fatalf("run migrations (URL redacted): %v", err)
	}
	_ = stdlibDB.Close()
	pool, err := postgres.NewPool(context.Background(), dsn, nil)
	if err != nil {
		t.Fatalf("new pool (URL redacted): %v", err)
	}
	return pool
}

// ensureSiteAdminRow makes the sentinel site_admin row exist for the test and
// leaves the shared database as it found it: an existing row has its
// credential columns restored, a row this test inserted is deleted.
func ensureSiteAdminRow(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	siteAdminID := uuid.MustParse(domain.SiteAdminID)
	var exists bool
	if err := pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM users WHERE id = $1)`, siteAdminID).Scan(&exists); err != nil {
		t.Fatalf("site_admin lookup: %v", err)
	}
	if exists {
		var (
			passwordHash   string
			mfaEnabled     bool
			mfaSecret      *string
			recoveryCodes  *string
			requiresChange bool
		)
		if err := pool.QueryRow(ctx, `SELECT password_hash, mfa_enabled, mfa_secret, mfa_recovery_codes::text, requires_password_change
			FROM users WHERE id = $1`, siteAdminID).Scan(&passwordHash, &mfaEnabled, &mfaSecret, &recoveryCodes, &requiresChange); err != nil {
			t.Fatalf("site_admin snapshot: %v", err)
		}
		t.Cleanup(func() {
			_, _ = pool.Exec(context.Background(), `UPDATE users SET password_hash = $2, mfa_enabled = $3, mfa_secret = $4,
				mfa_recovery_codes = $5::jsonb, requires_password_change = $6 WHERE id = $1`,
				siteAdminID, passwordHash, mfaEnabled, mfaSecret, recoveryCodes, requiresChange)
		})
		return
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users (id, email, password_hash, organization_id, role, email_verified)
		VALUES ($1, $2, 'x', $3, 'site_admin', true)`, siteAdminID, domain.SiteAdminEmail, uuid.MustParse(domain.SystemOrgID)); err != nil {
		t.Fatalf("seed site_admin: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id = $1`, siteAdminID)
	})
}

func seedRecoverSession(t *testing.T, pool *pgxpool.Pool, userID uuid.UUID) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := pool.Exec(context.Background(), `
		INSERT INTO sessions (id, user_id, token_selector, token_validator_hash, remember_me, is_valid, expires_at)
		VALUES ($1, $2, $3, 'vhash', false, true, NOW() + interval '1 hour')`, id, userID, uuid.New()); err != nil {
		t.Fatalf("seed session: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM sessions WHERE id = $1`, id)
	})
	return id
}

// RULE: RECOVER-3
func TestRecoverSiteAdmin_EndsTheSiteAdminsSessionsAndTokensOnly(t *testing.T) {
	pool := recoverTestPool(t)
	defer pool.Close()
	ctx := context.Background()
	repos := postgres.NewPgxRepositories(pool, nil)

	siteAdminID := uuid.MustParse(domain.SiteAdminID)
	ensureSiteAdminRow(t, pool)

	// Another user in a scratch organization, whose session and refresh
	// token must survive the site_admin's recovery.
	orgID := uuid.New()
	slug := "rcv-" + uuid.NewString()[:8]
	if _, err := pool.Exec(ctx, `INSERT INTO organizations (id, name, domain, org_slug, active) VALUES ($1, $2, $3, $4, true)`,
		orgID, "Recover "+slug, slug+".example.test", slug); err != nil {
		t.Fatalf("seed org: %v", err)
	}
	otherID := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO users (id, email, password_hash, organization_id, role, email_verified) VALUES ($1, $2, 'x', $3, 'org_user', true)`,
		otherID, "u-"+slug+"@example.test", orgID); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM oauth_refresh_tokens WHERE subject = $1`, otherID.String())
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id = $1`, otherID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM organizations WHERE id = $1`, orgID)
	})

	adminSession := seedRecoverSession(t, pool, siteAdminID)
	otherSession := seedRecoverSession(t, pool, otherID)

	jtis := service.NewTokenRevocationService(nil, repos.TokenRevocation)
	refresh := service.NewRefreshTokenService(nil, repos.RefreshToken, service.RefreshTokenServiceOptions{}).
		WithTokenRevocationService(jtis)
	const clientID = "recover-revoke-test-client"
	adminJTI := "recover-" + uuid.NewString()
	adminToken, err := refresh.Issue(ctx, service.IssueRefreshTokenInput{ClientID: clientID, Subject: siteAdminID.String(), AccessJTI: adminJTI})
	if err != nil {
		t.Fatalf("issue site_admin refresh token: %v", err)
	}
	otherToken, err := refresh.Issue(ctx, service.IssueRefreshTokenInput{ClientID: clientID, Subject: otherID.String(), AccessJTI: "recover-" + uuid.NewString()})
	if err != nil {
		t.Fatalf("issue other user's refresh token: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM oauth_refresh_tokens WHERE id = $1`, adminToken.ID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM oauth_token_revocations WHERE jti = $1`, adminJTI)
	})

	// The verdict the bearer gate's liveness check reaches for a session.
	live := func(sid uuid.UUID) bool {
		t.Helper()
		info, err := repos.Session.GetSessionWithUserAndOrgStatus(ctx, sid)
		if err != nil {
			t.Fatalf("session %s lookup: %v", sid, err)
		}
		ok, _ := info.CanBeUsedForAuth(time.Now().UTC())
		return ok
	}
	if !live(adminSession) || !live(otherSession) {
		t.Fatal("precondition: both seeded sessions must be live before the recovery")
	}
	if revoked, err := jtis.IsRevoked(ctx, adminJTI); err != nil || revoked {
		t.Fatalf("precondition: the linked access JTI must not be denylisted before the recovery (revoked=%t err=%v)", revoked, err)
	}

	var stdout, stderr bytes.Buffer
	rc := recoverSiteAdminCore(ctx, recoverDeps{Users: repos.User, Sessions: repos.Session, Refresh: refresh},
		recoverOptions{Password: "Recover-Integration-Pw-1!"}, &stdout, &stderr)
	if rc != 0 {
		t.Fatalf("recover rc = %d, stderr = %s", rc, stderr.String())
	}

	// The site_admin's pre-recovery session, refresh token and access JTI
	// are refused.
	if live(adminSession) {
		t.Error("the site_admin session minted before the recovery is still live")
	}
	if _, err := refresh.Consume(ctx, service.ConsumeRefreshTokenInput{RawToken: adminToken.Token, ClientID: clientID}); !errors.Is(err, service.ErrRefreshTokenInvalidGrant) {
		t.Errorf("the site_admin refresh token minted before the recovery still rotates (err = %v)", err)
	}
	if revoked, err := jtis.IsRevoked(ctx, adminJTI); err != nil || !revoked {
		t.Errorf("the access JTI linked to the site_admin refresh token is not denylisted (revoked=%t err=%v)", revoked, err)
	}
	// Another user's session and refresh token are untouched.
	if !live(otherSession) {
		t.Error("another user's session was ended by the site_admin recovery")
	}
	if _, err := refresh.Consume(ctx, service.ConsumeRefreshTokenInput{RawToken: otherToken.Token, ClientID: clientID}); err != nil {
		t.Errorf("another user's refresh token was ended by the site_admin recovery: %v", err)
	}
}

// failingDenylist is the real denylist repository whose Insert fails: the
// sink that breaks AFTER the refresh rows' UPDATE has committed.
type failingDenylist struct {
	repository.TokenRevocationRepository
}

func (failingDenylist) Insert(context.Context, *domain.TokenRevocation) error {
	return errors.New("simulated denylist outage")
}

// claimsByToken is a verifier for the introspection proof: each raw token
// stands for a validly signed, SESSIONLESS access token (the kind the refresh
// grant mints), so only the denylist can make it inactive.
type claimsByToken map[string]*service.IntrospectionClaims

func (c claimsByToken) IntrospectToken(_ context.Context, raw string) (*service.IntrospectionClaims, error) {
	if claims, ok := c[raw]; ok {
		return claims, nil
	}
	return nil, errors.New("unknown token")
}

// F3 (OSS-PRE-RELEASE-REVIEW-2026-10-10, OSS-REVIEW-FIXES-1): the command's
// retry advice must be true. With a denylist that fails after the refresh
// rows' UPDATE, the first run exits non-zero and leaves the rows revoked but
// their linked access JTIs not denylisted; the retry with a healthy denylist
// must complete that work, so the sessionless access token linked to the
// recovered administrator's refresh token introspects inactive, while another
// user's stays active. Until this slice the retry skipped the already-revoked
// rows and reported success over a live access token.
func TestRecoverSiteAdmin_RetryCompletesTheLinkedAccessRevocationAfterAPartialFailure(t *testing.T) {
	pool := recoverTestPool(t)
	defer pool.Close()
	ctx := context.Background()
	repos := postgres.NewPgxRepositories(pool, nil)

	siteAdminID := uuid.MustParse(domain.SiteAdminID)
	ensureSiteAdminRow(t, pool)
	orgID := uuid.New()
	slug := "rcv-retry-" + uuid.NewString()[:8]
	if _, err := pool.Exec(ctx, `INSERT INTO organizations (id, name, domain, org_slug, active) VALUES ($1, $2, $3, $4, true)`,
		orgID, "Recover "+slug, slug+".example.test", slug); err != nil {
		t.Fatalf("seed org: %v", err)
	}
	otherID := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO users (id, email, password_hash, organization_id, role, email_verified) VALUES ($1, $2, 'x', $3, 'org_user', true)`,
		otherID, "u-"+slug+"@example.test", orgID); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM oauth_refresh_tokens WHERE subject = $1`, otherID.String())
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id = $1`, otherID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM organizations WHERE id = $1`, orgID)
	})

	jtis := service.NewTokenRevocationService(nil, repos.TokenRevocation)
	healthy := service.NewRefreshTokenService(nil, repos.RefreshToken, service.RefreshTokenServiceOptions{}).
		WithTokenRevocationService(jtis)
	broken := service.NewRefreshTokenService(nil, repos.RefreshToken, service.RefreshTokenServiceOptions{}).
		WithTokenRevocationService(service.NewTokenRevocationService(nil, failingDenylist{repos.TokenRevocation}))
	const clientID = "recover-retry-test-client"
	adminJTI, otherJTI := "recover-retry-"+uuid.NewString(), "recover-retry-"+uuid.NewString()
	adminToken, err := healthy.Issue(ctx, service.IssueRefreshTokenInput{ClientID: clientID, Subject: siteAdminID.String(), AccessJTI: adminJTI})
	if err != nil {
		t.Fatalf("issue site_admin refresh token: %v", err)
	}
	if _, err := healthy.Issue(ctx, service.IssueRefreshTokenInput{ClientID: clientID, Subject: otherID.String(), AccessJTI: otherJTI}); err != nil {
		t.Fatalf("issue other user's refresh token: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM oauth_refresh_tokens WHERE id = $1`, adminToken.ID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM oauth_token_revocations WHERE jti = ANY($1)`, []string{adminJTI, otherJTI})
	})

	// The verdict an introspecting resource reaches for each sessionless
	// access token: signature and claims stand (the verifier says so), so the
	// denylist decides.
	introspect := service.NewIntrospectionService(nil, claimsByToken{
		"admin-access": {Sub: siteAdminID.String(), UserID: siteAdminID, Jti: adminJTI, Exp: time.Now().Add(time.Hour).Unix()},
		"other-access": {Sub: otherID.String(), UserID: otherID, Jti: otherJTI, Exp: time.Now().Add(time.Hour).Unix()},
	}, nil).WithRevocationChecker(jtis)
	active := func(raw string) bool {
		t.Helper()
		resp, err := introspect.IntrospectVerdict(ctx, raw)
		if err != nil {
			t.Fatalf("introspect: %v", err)
		}
		return resp.Active
	}
	if !active("admin-access") || !active("other-access") {
		t.Fatal("precondition: both sessionless access tokens must introspect active before the recovery")
	}

	// First run: the denylist fails after the refresh UPDATE. Honest: non-zero
	// exit, the reset named, the retry advised; the refresh row is revoked but
	// its linked access token still introspects active.
	var stdout, stderr bytes.Buffer
	if rc := recoverSiteAdminCore(ctx, recoverDeps{Users: repos.User, Sessions: repos.Session, Refresh: broken},
		recoverOptions{Password: "Recover-Integration-Pw-1!"}, &stdout, &stderr); rc == 0 {
		t.Fatalf("first run rc = 0 with a failing denylist; stdout = %s", stdout.String())
	}
	if !strings.Contains(stderr.String(), "refresh tokens failed") || !strings.Contains(stderr.String(), "run recover-site-admin again") {
		t.Fatalf("first run stderr = %s; want the partial-reset message and the retry advice", stderr.String())
	}
	if _, err := healthy.Consume(ctx, service.ConsumeRefreshTokenInput{RawToken: adminToken.Token, ClientID: clientID}); !errors.Is(err, service.ErrRefreshTokenInvalidGrant) {
		t.Fatalf("precondition: the site_admin refresh row must be revoked by the first run (err = %v)", err)
	}
	if !active("admin-access") {
		t.Fatal("precondition: the linked access token must still introspect active after the failed first run (the partial state under test)")
	}

	// The retry the advice asks for, with the denylist back: it must finish
	// the linked access revocation the first run lost.
	stdout.Reset()
	stderr.Reset()
	if rc := recoverSiteAdminCore(ctx, recoverDeps{Users: repos.User, Sessions: repos.Session, Refresh: healthy},
		recoverOptions{Password: "Recover-Integration-Pw-1!"}, &stdout, &stderr); rc != 0 {
		t.Fatalf("retry rc = %d, stderr = %s", rc, stderr.String())
	}
	if revoked, err := jtis.IsRevoked(ctx, adminJTI); err != nil || !revoked {
		t.Errorf("after the retry the access JTI linked to the site_admin refresh token is not denylisted (revoked=%t err=%v)", revoked, err)
	}
	if active("admin-access") {
		t.Error("after the retry the sessionless access token linked to the recovered site_admin's refresh token still introspects active")
	}
	if !active("other-access") {
		t.Error("the retry made another user's access token inactive")
	}
	if revoked, err := jtis.IsRevoked(ctx, otherJTI); err != nil || revoked {
		t.Errorf("another user's linked access JTI was denylisted (revoked=%t err=%v)", revoked, err)
	}
}
