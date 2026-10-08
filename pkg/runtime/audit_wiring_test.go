package runtime_test

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/postgres"
	"github.com/identuum/identuum-idp-oss/pkg/runtime"
)

// TESTBOOK-FINDINGS-V7A V7A-03: the local-password policy refusal and the
// max-sessions eviction recorded no audit event in the running server: the
// runtime never gave either service its audit sink. Through the real
// runtime, both events reach audit_events.
func TestRuntime_PolicyDenialAndEvictionAreAudited(t *testing.T) {
	dsn, db := scratchDatabase(t, "identuum_idp_oss_test_secmfa_audit")
	if _, err := postgres.RunMigrations(context.Background(), db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	t.Setenv("IDENTUUM_IDP_ENCRYPTION_KEY", testEncryptionKey)
	t.Setenv("IDENTUUM_IDP_ALLOW_MULTI_REPLICA", "true")
	seedSigningKey(t, dsn)
	pool, err := postgres.NewPool(context.Background(), dsn, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	repos := postgres.NewPgxRepositories(pool, nil)
	ctx := context.Background()
	const password = "dev-auditwire-not-a-secret-1A!"
	hash, err := repos.User.HashPassword(ctx, password)
	if err != nil {
		t.Fatal(err)
	}
	user := func(slug, authPolicy string, cap int) string {
		now := time.Now().UTC()
		o, err := repos.Organization.Create(ctx, &domain.Organization{Name: slug, Domain: slug + ".test", OrgSlug: slug,
			Active: true, MaxSessionsPerUser: cap, MFAPolicy: "optional", AuthPolicy: authPolicy, CreatedAt: now, UpdatedAt: now})
		if err != nil {
			t.Fatalf("seed organization: %v", err)
		}
		email := "user@" + slug + ".test"
		if _, err := repos.User.Create(ctx, &domain.User{ID: uuid.New(), OrganizationID: o.ID, Email: email, PasswordHash: hash,
			Role: domain.RoleOrgUser, AuthSource: domain.AuthSourceLocal, EmailVerified: true}); err != nil {
			t.Fatalf("seed user: %v", err)
		}
		return email
	}
	idpOnly, capped := user("auditidp", domain.AuthPolicyIDPOnly, 10), user("auditcap", domain.AuthPolicyMixed, 1)

	ln := listen(t)
	rt, err := runtime.NewWithListener(runtime.Options{Issuer: "http://localhost:7113", DatabaseURL: dsn,
		DataDir: t.TempDir(), Stdout: io.Discard, Stderr: io.Discard}, ln)
	if err != nil {
		t.Fatal(err)
	}
	if err := rt.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = shutdown(t, rt) })
	login := func(email string) int {
		resp, err := (&http.Client{Timeout: 5 * time.Second}).Post("http://"+ln.Addr().String()+"/api/v1/auth/login",
			"application/json", strings.NewReader(`{"email":"`+email+`","password":"`+password+`"}`))
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	events := func(eventType domain.AuditEventType) int {
		var n int
		if err := db.QueryRow(`SELECT count(*) FROM audit_events WHERE event_type = $1`, string(eventType)).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	if code := login(idpOnly); code != http.StatusUnauthorized {
		t.Fatalf("a local password under idp_only answered %d; want 401", code)
	}
	if code1, code2 := login(capped), login(capped); code1 != http.StatusOK || code2 != http.StatusOK {
		t.Fatalf("two sign-ins answered %d and %d; want 200 and 200", code1, code2)
	}
	if n := events(domain.AuditLocalLoginBlockedByRole); n == 0 {
		t.Error("the idp_only refusal wrote no local_login_blocked_by_role audit event")
	}
	if n := events(domain.AuditSessionEvictedMaxSessions); n == 0 {
		t.Error("the eviction over a cap of 1 wrote no session_evicted_max_sessions audit event")
	}
}
