//go:build integration

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/identuum/identuum-idp-oss/internal/api"
	"github.com/identuum/identuum-idp-oss/internal/crypto"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/postgres"
	"github.com/identuum/identuum-idp-oss/internal/repository"
	"github.com/identuum/identuum-idp-oss/internal/service"
	"github.com/identuum/identuum-idp-oss/internal/setup"
)

// G7 remaining proofs for SETUP-COMPLETE-ONCE-1: a later completion with
// different input never overwrites the winner, and a failed winner leaves
// setup retryable from another instance without duplicates.

// TestE2E_OSS_SetupLoserCannotOverwriteWinner pauses A after its organization
// and administrator writes, at its first signing-key insert, then starts B on
// the other instance with a different organization, contact address and
// password. B must wait in the database and then get the exact 410; the
// organization and administrator must still be A's.
func TestE2E_OSS_SetupLoserCannotOverwriteWinner(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	observer, pools := g7SetupPools(t, ctx)
	dataDir := t.TempDir()
	events := &g7SetupAudit{counts: make(map[string]int)}
	handlers, first := g7SetupHandlers(pools, dataDir, events, nil)
	banner, err := first.Initialize(ctx, dataDir)
	if err != nil || banner == nil {
		t.Fatal("initialize fresh setup failed (details suppressed)")
	}
	winnerPassword, loserPassword := uuid.NewString()+"aA1!", uuid.NewString()+"bB2?"
	winner := g7SetupPayload(t, banner.SetupToken, "G7 Winner", "winner.g7.example", "owner@winner.g7.example", winnerPassword)
	loser := g7SetupPayload(t, banner.SetupToken, "G7 Loser", "loser.g7.example", "owner@loser.g7.example", loserPassword)

	blocker, err := observer.Begin(ctx)
	if err != nil {
		t.Fatal("begin signing-key blocker failed")
	}
	var workers sync.WaitGroup
	defer g7JoinSetupWorkers(t, cancel, blocker.Rollback, &workers)
	// SHARE lets every read through and holds the first key INSERT, which
	// A reaches only after its organization and administrator writes.
	if _, err := blocker.Exec(ctx, `LOCK TABLE signing_keys IN SHARE MODE`); err != nil {
		t.Fatal("hold signing_keys failed")
	}
	resultA := g7StartSetup(ctx, &workers, handlers[0], winner, banner.SetupToken, winnerPassword, loserPassword)
	g7AwaitSetupQuery(t, ctx, observer, "g7-setup-a", `^[[:space:]]*INSERT[[:space:]]+INTO[[:space:]]+signing_keys`)
	var admins int
	if err := observer.QueryRow(ctx, `SELECT count(*) FROM users WHERE id=$1::uuid`, domain.SiteAdminID).Scan(&admins); err != nil || admins != 1 {
		t.Fatal("A must have written the administrator before it waits at the key insert")
	}
	resultB := g7StartSetup(ctx, &workers, handlers[1], loser, banner.SetupToken, winnerPassword, loserPassword)
	// B waits on an advisory lock: the completion lock on this tree. Never
	// demand that B pass it.
	g7AwaitSetupAdvisoryWait(t, ctx, observer, "g7-setup-b")
	if err := blocker.Rollback(ctx); err != nil {
		t.Fatal("release signing_keys failed")
	}
	got := [2]g7SetupResult{g7AwaitSetupResult(t, ctx, resultA), g7AwaitSetupResult(t, ctx, resultB)}
	if got[0].status != http.StatusOK || got[1].status != http.StatusGone || !got[1].alreadyComplete {
		t.Errorf("G7: want A 200 then B exact 410 setup_already_complete; got A %d, B %d (bodies suppressed)", got[0].status, got[1].status)
	}

	var orgs, winnerOrgs, loserOrgs, winnerContact, keys int
	var hash string
	err = observer.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM organizations WHERE id <> $1::uuid),
		(SELECT count(*) FROM organizations WHERE id <> $1::uuid AND name='G7 Winner' AND domain='winner.g7.example'),
		(SELECT count(*) FROM organizations WHERE domain='loser.g7.example' OR name='G7 Loser'),
		(SELECT count(*) FROM users WHERE id=$2::uuid AND email=$3 AND contact_email='owner@winner.g7.example'),
		(SELECT count(*) FROM signing_keys WHERE state='active'),
		(SELECT password_hash FROM users WHERE id=$2::uuid)`,
		domain.SystemOrgID, domain.SiteAdminID, domain.SiteAdminEmail).
		Scan(&orgs, &winnerOrgs, &loserOrgs, &winnerContact, &keys, &hash)
	if err != nil {
		t.Fatal("read winner-owned state failed (details suppressed)")
	}
	if orgs != 1 || winnerOrgs != 1 || loserOrgs != 0 || winnerContact != 1 || keys != 1 {
		t.Errorf("G7: the winner's organization, contact address and one key must stand; orgs=%d winner=%d loser=%d contact=%d keys=%d",
			orgs, winnerOrgs, loserOrgs, winnerContact, keys)
	}
	if crypto.CompareHashAndPasswordContext(ctx, []byte(hash), []byte(winnerPassword)) != nil {
		t.Error("G7: the winner's password no longer signs in")
	}
	if crypto.CompareHashAndPasswordContext(ctx, []byte(hash), []byte(loserPassword)) == nil {
		t.Error("G7: the refused completion overwrote the administrator password")
	}
	g7AssertOneCompletion(t, events)
}

// TestE2E_OSS_SetupFailedWinnerCanRetry fails A's first signing-key read,
// after its organization and administrator writes and before MarkComplete.
// Setup must stay required with the code still valid, and the same request
// on the other instance must then finish with no duplicate resources.
func TestE2E_OSS_SetupFailedWinnerCanRetry(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	observer, pools := g7SetupPools(t, ctx)
	dataDir := t.TempDir()
	events := &g7SetupAudit{counts: make(map[string]int)}
	failing := &g7FailOnceKeys{}
	handlers, first := g7SetupHandlers(pools, dataDir, events, failing)
	banner, err := first.Initialize(ctx, dataDir)
	if err != nil || banner == nil {
		t.Fatal("initialize fresh setup failed (details suppressed)")
	}
	password := uuid.NewString() + "aA1!"
	payload := g7SetupPayload(t, banner.SetupToken, "G7 Retry", "retry.g7.example", "owner@retry.g7.example", password)

	attempt := func(i int) g7SetupResult {
		var workers sync.WaitGroup
		// Bounded: a guard left held by the failed attempt makes the retry
		// wait until this deadline.
		attemptCtx, stop := context.WithTimeout(ctx, 10*time.Second)
		defer stop()
		return g7AwaitSetupResult(t, attemptCtx, g7StartSetup(attemptCtx, &workers, handlers[i], payload, banner.SetupToken, password, ""))
	}
	if got := attempt(0); got.status != http.StatusBadRequest || !got.genericFailure || got.leaked {
		t.Fatalf("G7: the injected failure must answer 400 setup_complete_failed; got %d", got.status)
	}
	if !failing.failed() {
		t.Fatal("the failure was not injected")
	}
	var required, armed bool
	var admins int
	if err := observer.QueryRow(ctx, `SELECT status='setup_required', setup_token_hash IS NOT NULL,
		(SELECT count(*) FROM users WHERE id=$1::uuid) FROM system_setup_state`, domain.SiteAdminID).
		Scan(&required, &armed, &admins); err != nil {
		t.Fatal("read state after the failed attempt failed (details suppressed)")
	}
	if !required || !armed || admins != 1 {
		t.Fatalf("G7: a failed attempt after its administrator write must leave setup required and its code valid; required=%t armed=%t admins=%d", required, armed, admins)
	}
	if got := attempt(1); got.status != http.StatusOK || got.leaked {
		t.Fatalf("G7: the retry on the other instance must succeed; got %d (body suppressed)", got.status)
	}

	var orgs, admin, keys int
	var completed, cleared bool
	if err := observer.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM organizations WHERE id <> $1::uuid),
		(SELECT count(*) FROM users WHERE organization_id=$1::uuid AND role='site_admin'),
		(SELECT count(*) FROM signing_keys),
		(SELECT status='setup_complete' FROM system_setup_state),
		(SELECT setup_token_hash IS NULL FROM system_setup_state)`, domain.SystemOrgID).
		Scan(&orgs, &admin, &keys, &completed, &cleared); err != nil {
		t.Fatal("read state after the retry failed (details suppressed)")
	}
	if orgs != 1 || admin != 1 || keys != 1 || !completed || !cleared {
		t.Errorf("G7: the retry must resume without duplicates; orgs=%d admins=%d keys=%d completed=%t cleared=%t", orgs, admin, keys, completed, cleared)
	}
	g7AssertOneCompletion(t, events)
}

type g7SetupResult struct {
	status                                  int
	alreadyComplete, genericFailure, leaked bool
}

// g7FailOnceKeys fails the first active-key read on the instance it wraps.
type g7FailOnceKeys struct {
	mu   sync.Mutex
	done bool
}

func (f *g7FailOnceKeys) failed() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.done
}

type g7KeyStore interface {
	repository.KeyRepository
	repository.SigningKeyEnsurer
}

type g7FailingKeyRepo struct {
	g7KeyStore
	once *g7FailOnceKeys
}

func (r g7FailingKeyRepo) GetActiveSigningKeys(ctx context.Context) ([]domain.SigningKey, error) {
	r.once.mu.Lock()
	fail := !r.once.done
	r.once.done = true
	r.once.mu.Unlock()
	if fail {
		return nil, errors.New("g7: injected key-store failure")
	}
	return r.g7KeyStore.GetActiveSigningKeys(ctx)
}

// g7SetupHandlers builds one setup Service and route per pool. A non-nil
// failing wraps the first instance's key store.
func g7SetupHandlers(pools [2]*pgxpool.Pool, dataDir string, events *g7SetupAudit, failing *g7FailOnceKeys) ([2]http.Handler, *setup.Service) {
	var handlers [2]http.Handler
	var first *setup.Service
	for i, pool := range pools {
		repos := postgres.NewPgxRepositories(pool, e2eSigningKeyCipher())
		keys := repos.Key
		if i == 0 && failing != nil {
			keys = g7FailingKeyRepo{g7KeyStore: repos.Key.(g7KeyStore), once: failing}
		}
		svc := setup.New(setup.Deps{
			Repo:       postgres.NewPgxSetupStateRepository(pool),
			OrgService: service.NewOrganizationService(nil, repos.Organization),
			KeyService: service.NewKeyService(keys),
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
	return handlers, first
}

func g7SetupPayload(t *testing.T, code, org, orgDomain, email, password string) []byte {
	t.Helper()
	payload, err := json.Marshal(map[string]string{
		"setup_token": code, "organization_name": org, "organization_domain": orgDomain,
		"admin_email": email, "admin_password": password,
	})
	if err != nil {
		t.Fatal("encode setup request failed")
	}
	return payload
}

// g7StartSetup posts payload in a goroutine and sends a body-free result.
// leaked reports whether the body holds the code or either password.
func g7StartSetup(ctx context.Context, workers *sync.WaitGroup, h http.Handler, payload []byte, code, password, other string) <-chan g7SetupResult {
	results := make(chan g7SetupResult, 1)
	workers.Add(1)
	go func() {
		defer workers.Done()
		req := httptest.NewRequest(http.MethodPost, "/api/setup/complete", bytes.NewReader(payload)).WithContext(ctx)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		body := rec.Body.Bytes()
		var answer map[string]json.RawMessage
		exact := json.Unmarshal(body, &answer) == nil && len(answer) == 1 &&
			string(answer["error"]) == `"setup_already_complete"`
		leaked := bytes.Contains(body, []byte(code)) || bytes.Contains(body, []byte(password)) ||
			(other != "" && bytes.Contains(body, []byte(other)))
		results <- g7SetupResult{rec.Code, exact, string(answer["error"]) == `"setup_complete_failed"`, leaked}
	}()
	return results
}

// g7AwaitSetupResult returns one request's result, failing at ctx's end.
func g7AwaitSetupResult(t *testing.T, ctx context.Context, result <-chan g7SetupResult) g7SetupResult {
	t.Helper()
	select {
	case got := <-result:
		if got.leaked {
			t.Error("setup response contains sensitive request material")
		}
		return got
	case <-ctx.Done():
		t.Fatal("setup completion did not finish")
	}
	return g7SetupResult{}
}

func g7JoinSetupWorkers(t *testing.T, cancel context.CancelFunc, release func(context.Context) error, workers *sync.WaitGroup) {
	cancel()
	cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	_ = release(cleanup)
	joined := make(chan struct{})
	go func() { workers.Wait(); close(joined) }()
	select {
	case <-joined:
	case <-cleanup.Done():
		t.Error("setup request goroutines did not finish after cancellation")
	}
}

func g7AssertOneCompletion(t *testing.T, events *g7SetupAudit) {
	t.Helper()
	events.mu.Lock()
	defer events.mu.Unlock()
	if events.counts["setup.completed"] != 1 || events.counts[string(domain.AuditUserCreated)] != 1 || len(events.counts) != 2 {
		t.Error("setup must emit exactly one completion and one first-administrator creation audit event")
	}
}

// g7AwaitSetupQuery waits until application waits on a lock while running a
// statement that matches pattern.
func g7AwaitSetupQuery(t *testing.T, parent context.Context, pool *pgxpool.Pool, application, pattern string) {
	t.Helper()
	g7AwaitSetupCondition(t, parent, pool, `SELECT EXISTS (
	 SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND application_name=$1
	 AND wait_event_type='Lock' AND cardinality(pg_blocking_pids(pid)) > 0 AND query ~* $2)`, application, pattern)
}

// g7AwaitSetupAdvisoryWait waits until application waits for an advisory lock.
func g7AwaitSetupAdvisoryWait(t *testing.T, parent context.Context, pool *pgxpool.Pool, application string) {
	t.Helper()
	g7AwaitSetupCondition(t, parent, pool, `SELECT EXISTS (
	 SELECT 1 FROM pg_locks l JOIN pg_stat_activity a ON a.pid=l.pid
	 WHERE a.datname=current_database() AND a.application_name=$1
	 AND l.locktype='advisory' AND NOT l.granted)`, application)
}

func g7AwaitSetupCondition(t *testing.T, parent context.Context, pool *pgxpool.Pool, query string, args ...any) {
	t.Helper()
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	for {
		var waiting bool
		if err := pool.QueryRow(ctx, query, args...).Scan(&waiting); err != nil {
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
