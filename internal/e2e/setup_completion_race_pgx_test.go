//go:build integration

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/identuum/identuum-idp-oss/internal/api"
	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/postgres"
	"github.com/identuum/identuum-idp-oss/internal/service"
	"github.com/identuum/identuum-idp-oss/internal/setup"
	"github.com/identuum/identuum-idp-oss/internal/testsupport"
)

// EXPECTED RED: G7, until whole-completion protection is implemented. This is
// an ordinary failing integration test, with no skip or expected-failure gate.
// On 1af3ae4 the overlapping loser returns 400 setup_complete_failed, not 410.
// RED execution belongs to the operator; source inspection is not a RED result.
func TestE2E_OSS_SetupConcurrentOrganizationCollision(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	observer, pools := g7SetupPools(t, ctx)
	dataDir := t.TempDir()
	events := &g7SetupAudit{counts: make(map[string]int)}
	var handlers [2]http.Handler
	var first *setup.Service
	for i, pool := range pools {
		repos := postgres.NewPgxRepositories(pool, e2eSigningKeyCipher())
		svc := setup.New(setup.Deps{
			Repo:       postgres.NewPgxSetupStateRepository(pool),
			OrgService: service.NewOrganizationService(nil, repos.Organization),
			KeyService: service.NewKeyService(repos.Key),
			OrgRepo:    repos.Organization, UserRepo: repos.User,
			Issuer: "http://setup.example",
		})
		if i == 0 {
			first = svc
		}
		router := gin.New()
		api.RegisterSetupRoutes(router, api.SetupRoutesDeps{Service: svc, DataDir: dataDir, Audit: events})
		handlers[i] = router
	}
	// Use the real setup initializer; never log the banner or request payload.
	banner, err := first.Initialize(ctx, dataDir)
	if err != nil || banner == nil {
		t.Fatal("initialize fresh setup failed (details suppressed)")
	}
	password := uuid.NewString() + "aA1!"
	payload, err := json.Marshal(map[string]string{
		"setup_token":       banner.SetupToken,
		"organization_name": "G7 Collision", "organization_domain": "g7.example",
		"admin_email": "owner@g7.example", "admin_password": password,
	})
	if err != nil {
		t.Fatal("encode setup request failed")
	}

	blocker, err := observer.Begin(ctx)
	if err != nil {
		t.Fatal("begin organization blocker failed")
	}
	var workers sync.WaitGroup
	defer func() {
		cancel()
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		_ = blocker.Rollback(cleanup)
		joined := make(chan struct{})
		go func() { workers.Wait(); close(joined) }()
		select {
		case <-joined:
		case <-cleanup.Done():
			t.Error("setup request goroutines did not finish after cancellation")
		}
	}()
	// SHARE permits List's reads but prevents either organization INSERT.
	if _, err := blocker.Exec(ctx, `LOCK TABLE organizations IN SHARE MODE`); err != nil {
		t.Fatal("hold organizations failed")
	}
	type result struct {
		status                                  int
		alreadyComplete, genericFailure, leaked bool
	}
	results := make(chan result, 2)
	start := func(i int) {
		workers.Add(1)
		go func() {
			defer workers.Done()
			req := httptest.NewRequest(http.MethodPost, "/api/setup/complete", bytes.NewReader(payload)).WithContext(ctx)
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			handlers[i].ServeHTTP(rec, req)
			body := rec.Body.Bytes()
			var answer map[string]json.RawMessage
			exact := json.Unmarshal(body, &answer) == nil && len(answer) == 1 &&
				string(answer["error"]) == `"setup_already_complete"`
			results <- result{rec.Code, exact, string(answer["error"]) == `"setup_complete_failed"`,
				bytes.Contains(body, []byte(banner.SetupToken)) || bytes.Contains(body, []byte(password))}
		}()
	}
	start(0)
	g7AwaitSetupWait(t, ctx, observer, "g7-setup-a", true)
	start(1)
	// On the broken tree B waits to INSERT. With the fix it may instead wait
	// for completion protection. Never demand that B cross the future guard.
	g7AwaitSetupWait(t, ctx, observer, "g7-setup-b", false)
	if err := blocker.Rollback(ctx); err != nil {
		t.Fatal("release organizations failed")
	}
	successes, refusals := 0, 0
	for range 2 {
		select {
		case got := <-results:
			if got.leaked {
				t.Error("setup response contains sensitive request material")
			}
			switch {
			case got.status == http.StatusOK:
				successes++
			case got.status == http.StatusGone && got.alreadyComplete:
				refusals++
			default:
				t.Errorf("G7: completion status %d, setup_complete_failed=%t; want 200 or exact 410 setup_already_complete (body suppressed)", got.status, got.genericFailure)
			}
		case <-ctx.Done():
			t.Fatal("setup completions did not finish")
		}
	}
	if successes != 1 || refusals != 1 {
		t.Errorf("G7: successes=%d already-complete refusals=%d; want 1 each", successes, refusals)
	}
	// Check persistence even when the response assertion is RED.
	var organizations, primaryDomains, admins, totalKeys, activeKeys int
	var completed, cleared bool
	err = observer.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM organizations WHERE id <> $1::uuid),
		(SELECT count(*) FROM organization_domains d JOIN organizations o ON o.id=d.organization_id
		 WHERE o.id <> $1::uuid AND d.is_primary AND d.domain=o.domain AND d.domain='g7.example'),
		(SELECT count(*) FROM users WHERE id=$2::uuid AND organization_id=$1::uuid AND email=$3 AND role='site_admin'),
		(SELECT count(*) FROM signing_keys),
		(SELECT count(*) FROM signing_keys WHERE state='active' AND algorithm='EdDSA'),
		(SELECT status='setup_complete' FROM system_setup_state),
		(SELECT setup_token_hash IS NULL FROM system_setup_state)`,
		domain.SystemOrgID, domain.SiteAdminID, domain.SiteAdminEmail).
		Scan(&organizations, &primaryDomains, &admins, &totalKeys, &activeKeys, &completed, &cleared)
	if err != nil {
		t.Fatal("read completion invariants failed (details suppressed)")
	}
	if organizations != 1 || primaryDomains != 1 || admins != 1 || totalKeys != 1 || activeKeys != 1 || !completed || !cleared {
		t.Error("setup persistence must contain one organization/domain, canonical administrator, active key and completed state with cleared hash")
	}
	events.mu.Lock()
	defer events.mu.Unlock()
	if events.counts["setup.completed"] != 1 || events.counts[string(domain.AuditUserCreated)] != 1 || len(events.counts) != 2 {
		t.Error("setup must emit exactly one completion and one first-administrator creation audit event")
	}
}

type g7SetupAudit struct {
	mu     sync.Mutex
	counts map[string]int
}

func (a *g7SetupAudit) Record(_ context.Context, event audit.Event) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.counts[event.Action]++
	return nil
}

func g7AwaitSetupWait(t *testing.T, parent context.Context, pool *pgxpool.Pool, application string, insert bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		var waiting bool
		err := pool.QueryRow(ctx, `SELECT EXISTS (
		 SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND application_name=$1
		 AND wait_event_type='Lock' AND cardinality(pg_blocking_pids(pid)) > 0
		 AND (NOT $2::boolean OR query ~* '^[[:space:]]*INSERT[[:space:]]+INTO[[:space:]]+organizations'))`, application, insert).Scan(&waiting)
		if err != nil {
			t.Fatal("observe request-attributed database wait failed (details suppressed)")
		}
		if waiting {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal("request did not reach its required database lock wait")
		case <-tick.C:
		}
	}
}

// Create a unique database, never reset or adopt an existing fixture database.
// This helper runs only when the operator explicitly runs the integration test.
func g7SetupPools(t *testing.T, ctx context.Context) (*pgxpool.Pool, [2]*pgxpool.Pool) {
	t.Helper()
	dsn := os.Getenv("IDENTUUM_IDP_TEST_DATABASE_URL")
	if dsn == "" || testsupport.RequireTestDatabase(dsn) != nil {
		t.Fatal("G7 requires an explicitly selected scratch test database")
	}
	u, err := url.Parse(dsn)
	if err != nil || u.Port() == "5513" {
		t.Fatal("G7 refuses an invalid or protected database address")
	}
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal("open scratch database administrator failed (URL suppressed)")
	}
	t.Cleanup(admin.Close)
	name := "g7_setup_" + strings.ReplaceAll(uuid.NewString(), "-", "") + "_test"
	quoted := pgx.Identifier{name}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+quoted); err != nil {
		t.Fatal("create unique G7 database failed (details suppressed)")
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := admin.Exec(cleanup, "DROP DATABASE "+quoted+" WITH (FORCE)"); err != nil {
			t.Error("drop owned G7 database failed (details suppressed)")
		}
	})
	u.Path = "/" + name
	applyMigrations(t, u.String())
	open := func(application string) *pgxpool.Pool {
		cfg, err := pgxpool.ParseConfig(u.String())
		if err != nil {
			t.Fatal("configure G7 pool failed (details suppressed)")
		}
		cfg.ConnConfig.RuntimeParams["application_name"] = application
		pool, err := pgxpool.NewWithConfig(ctx, cfg)
		if err != nil {
			t.Fatal("open G7 pool failed (details suppressed)")
		}
		t.Cleanup(pool.Close)
		return pool
	}
	return open("g7-setup-observer"), [2]*pgxpool.Pool{open("g7-setup-a"), open("g7-setup-b")}
}
