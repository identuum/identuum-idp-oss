//go:build integration

package e2e

import (
	"context"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/postgres"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// C1 client update lock (OSS v0.9.12), prepared before the fix and RED on
// 16e01c5. These tests call production service/repository
// code inside two externally owned READ COMMITTED transactions. They prove the
// locked-read behavior, not the service's ownership of Begin/Commit or HTTP/MFA.
// Begin intercepts nested transactions too, so a transactional repository seam
// using DBTX.Begin retains the barrier. No production SQL is replaced here.
type f2ReadGate struct {
	entered chan struct{}
	scanned chan struct{}
	release chan struct{}
	once    sync.Once
}

func newF2ReadGate() *f2ReadGate {
	return &f2ReadGate{entered: make(chan struct{}), scanned: make(chan struct{}), release: make(chan struct{})}
}

type f2LockTx struct {
	pgx.Tx
	gate *f2ReadGate
}

func (tx *f2LockTx) Begin(ctx context.Context) (pgx.Tx, error) {
	nested, err := tx.Tx.Begin(ctx)
	if err != nil {
		return nil, err
	}
	return &f2LockTx{Tx: nested, gate: tx.gate}, nil
}

func (tx *f2LockTx) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	selected := false
	q := strings.ToLower(sql)
	if strings.Contains(q, "select") && strings.Contains(q, "from oauth_clients") {
		tx.gate.once.Do(func() { selected = true; close(tx.gate.entered) })
	}
	row := tx.Tx.QueryRow(ctx, sql, args...)
	if !selected {
		return row
	}
	return &f2GatedRow{row: row, ctx: ctx, gate: tx.gate}
}

type f2GatedRow struct {
	row  pgx.Row
	ctx  context.Context
	gate *f2ReadGate
}

func (r *f2GatedRow) Scan(dest ...any) error {
	if err := r.row.Scan(dest...); err != nil {
		return err
	}
	close(r.gate.scanned)
	select {
	case <-r.gate.release:
		return nil
	case <-r.ctx.Done():
		return r.ctx.Err()
	}
}

func f2ScratchPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	// Reject the owner's endpoint BEFORE migration or connection. testDBURL
	// applies the repository's test-database policy (testsupport, the same as
	// the Makefile's test-db-endpoint); the checks below repeat its core. No
	// compose-project check: CI and make verify-integration set none.
	port, err := strconv.Atoi(os.Getenv("DEV_PG_HOST_PORT"))
	if err != nil || port < 1024 || port > 65535 || port == 5513 {
		t.Fatal("set DEV_PG_HOST_PORT to a disposable scratch port, never 5513")
	}
	dbURL := testDBURL(t) // Existing database-name guard; never print its value.
	cfg, err := pgxpool.ParseConfig(dbURL)
	if err != nil {
		t.Fatal("scratch connection configuration rejected")
	}
	if cfg.ConnConfig.Host != "127.0.0.1" || int(cfg.ConnConfig.Port) != port ||
		!strings.HasSuffix(cfg.ConnConfig.Database, "_test") {
		t.Fatal("test connection must use loopback, the selected scratch port and an _test database")
	}
	applyMigrations(t, dbURL)
	cfg.MaxConns = 4 // A, B, observer and independent final read.
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal("open scratch pool failed")
	}
	t.Cleanup(pool.Close)
	return pool
}

func f2SeedClient(t *testing.T, pool *pgxpool.Pool, required, dynamic bool) uuid.UUID {
	t.Helper()
	orgID, id := uuid.New(), uuid.New()
	ctx := context.Background()
	_, err := pool.Exec(ctx, `INSERT INTO organizations (id, name, domain, org_slug, active)
		VALUES ($1, 'F2 scratch', $2, $3, true)`, orgID, orgID.String()+".example.invalid", "f2-"+orgID.String())
	if err != nil {
		t.Fatal("seed scratch organization failed")
	}
	repo := postgres.NewPgxClientRepository(pool)
	client := &domain.Client{
		ID: id, ClientID: "f2-" + id.String(), Name: "old", OrganizationID: &orgID,
		IsPublic: true, PKCEOptOut: !required, DynamicallyRegistered: dynamic,
		Scope: "openid", TokenEndpointAuthMethod: "none",
		RedirectURIs: []string{"https://f2.example.invalid/cb"},
	}
	if err := repo.RegisterClient(ctx, client); err != nil {
		t.Fatal("seed public scratch client failed")
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = pool.Exec(cleanup, `DELETE FROM oauth_clients WHERE id = $1`, id)
		_, _ = pool.Exec(cleanup, `DELETE FROM organizations WHERE id = $1`, orgID)
	})
	return id
}

func f2Begin(t *testing.T, ctx context.Context, pool *pgxpool.Pool) pgx.Tx {
	t.Helper()
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		t.Fatal("begin scratch transaction failed")
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = tx.Rollback(cleanup)
	})
	return tx
}

func f2Await(t *testing.T, ctx context.Context, event <-chan struct{}) {
	t.Helper()
	select {
	case <-event:
	case <-ctx.Done():
		t.Fatal("F2 harness stalled before the required read event")
	}
}

// Returns only on a completed ordinary read OR positively observed contention.
// A deadline fails the harness; it is never taken as evidence of serialization.
func f2ObserveReadOrLock(t *testing.T, ctx context.Context, pool *pgxpool.Pool, a, b uint32, scanned <-chan struct{}) bool {
	t.Helper()
	for {
		select {
		case <-scanned:
			return false
		default:
		}
		var blocked bool
		if err := pool.QueryRow(ctx, `SELECT $1::int = ANY(pg_blocking_pids($2::int))`, int64(a), int64(b)).Scan(&blocked); err != nil {
			t.Fatal("F2 lock observer failed; no behavioral verdict")
		}
		if blocked {
			return true
		}
		if ctx.Err() != nil {
			t.Fatal("F2 read/lock observation stalled; no behavioral verdict")
		}
		runtime.Gosched()
	}
}

type f2UpdateResult struct {
	prior  domain.Client
	client *domain.Client
	err    error
}

func f2Result(t *testing.T, ctx context.Context, result <-chan f2UpdateResult) f2UpdateResult {
	t.Helper()
	select {
	case r := <-result:
		if r.err != nil || r.client == nil {
			t.Fatal("scratch client update refused unexpectedly")
		}
		return r
	case <-ctx.Done():
		t.Fatal("F2 update stalled; no behavioral verdict")
	}
	return f2UpdateResult{}
}

// RULE: CLIENT-UPDATE-LOCK-1
func TestClientUpdateLock_Pgx(t *testing.T) {
	pool := f2ScratchPool(t)
	for _, scenario := range []string{"disjoint_admin_edits", "opposite_pkce_prior", "dcr_disjoint_metadata", "same_field_control"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			dynamic := scenario == "dcr_disjoint_metadata"
			id := f2SeedClient(t, pool, dynamic, dynamic)
			a, b := f2Begin(t, ctx, pool), f2Begin(t, ctx, pool)
			ga, gb := newF2ReadGate(), newF2ReadGate()
			pidA, pidB := a.Conn().PgConn().PID(), b.Conn().PgConn().PID()
			var workers sync.WaitGroup
			defer func() { cancel(); workers.Wait() }()
			sa := service.NewClientService(nil, postgres.NewPgxClientRepository(&f2LockTx{Tx: a, gate: ga}))
			sb := service.NewClientService(nil, postgres.NewPgxClientRepository(&f2LockTx{Tx: b, gate: gb}))
			on, off, newName, aName, newScope := true, false, "new", "A", "openid profile"
			oa := service.UpdateClientOptions{PKCERequired: &on}
			ob := service.UpdateClientOptions{Name: &newName}
			switch scenario {
			case "opposite_pkce_prior":
				ob = service.UpdateClientOptions{PKCERequired: &off}
			case "dcr_disjoint_metadata":
				oa = service.UpdateClientOptions{Scope: &newScope}
			case "same_field_control":
				oa = service.UpdateClientOptions{Name: &aName}
			}
			ra, rb := make(chan f2UpdateResult, 1), make(chan f2UpdateResult, 1)
			workers.Add(1)
			go func() {
				defer workers.Done()
				prior, c, err := sa.UpdateClientReportingPrior(ctx, id, oa)
				ra <- f2UpdateResult{prior, c, err}
			}()
			f2Await(t, ctx, ga.scanned)
			workers.Add(1)
			go func() {
				defer workers.Done()
				if dynamic {
					c, err := sb.UpdateClient(ctx, id, ob)
					rb <- f2UpdateResult{client: c, err: err}
					return
				}
				prior, c, err := sb.UpdateClientReportingPrior(ctx, id, ob)
				rb <- f2UpdateResult{prior, c, err}
			}()
			f2Await(t, ctx, gb.entered)
			blocked := f2ObserveReadOrLock(t, ctx, pool, pidA, pidB, gb.scanned)
			close(ga.release)
			ar := f2Result(t, ctx, ra)
			if err := a.Commit(ctx); err != nil {
				t.Fatal("scratch A commit failed")
			}
			close(gb.release) // Also safe if B's locked Scan has not returned yet.
			br := f2Result(t, ctx, rb)
			if err := b.Commit(ctx); err != nil {
				t.Fatal("scratch B commit failed")
			}
			got, err := postgres.NewPgxClientRepository(pool).GetClientByID(ctx, id)
			if err != nil || got == nil {
				t.Fatal("final scratch client read failed")
			}
			switch scenario {
			case "disjoint_admin_edits":
				if got.Name != newName || got.PKCEOptOut {
					t.Error("B lost A's PKCE edit while changing only name")
				}
			case "opposite_pkce_prior":
				if ar.prior.PKCEOptOut != true || ar.client.PKCEOptOut || br.prior.PKCEOptOut || !br.client.PKCEOptOut || !got.PKCEOptOut {
					t.Error("PKCE prior/result chain must be false -> true -> false in commit order")
				}
			case "dcr_disjoint_metadata":
				if got.Name != newName || got.Scope != newScope || !got.DynamicallyRegistered || got.PKCEOptOut {
					t.Error("DCR shared-service rename lost A's scope or DCR/PKCE restrictions")
				}
			case "same_field_control":
				if got.Name != newName {
					t.Error("the later explicit name must win")
				}
			}
			// Report only a Boolean; never dump row aggregates or backend IDs.
			t.Logf("observed B waiting on A's database lock: %t", blocked)
		})
	}
}

// Red on the baseline's discarded tag.
// RULE: CLIENT-UPDATE-AFFECTED-ROW-1
func TestClientUpdateLock_ZeroRowsRefused(t *testing.T) {
	pool := f2ScratchPool(t)
	for _, tombstone := range []bool{false, true} {
		name := "hard_deleted"
		if tombstone {
			name = "tombstoned"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			id := f2SeedClient(t, pool, true, false)
			repo := postgres.NewPgxClientRepository(pool)
			stale, err := repo.GetClientByID(ctx, id)
			if err != nil || stale == nil {
				t.Fatal("fixture read failed")
			}
			tx := f2Begin(t, ctx, pool)
			query := `DELETE FROM oauth_clients WHERE id = $1`
			if tombstone {
				query = `UPDATE oauth_clients SET deleted_at = now() WHERE id = $1`
			}
			tag, err := tx.Exec(ctx, query, id)
			if err != nil || tag.RowsAffected() != 1 {
				t.Fatal("fixture delete/tombstone did not affect one row")
			}
			if err := tx.Commit(ctx); err != nil {
				t.Fatal("fixture delete/tombstone commit failed")
			}
			stale.Name = "must not succeed"
			if err := repo.Update(ctx, stale); err == nil {
				t.Error("zero-row client UPDATE returned success")
			}
			var total, live int
			if err := pool.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE deleted_at IS NULL) FROM oauth_clients WHERE id=$1`, id).Scan(&total, &live); err != nil {
				t.Fatal("deleted-state verification failed")
			}
			wantTotal := 0
			if tombstone {
				wantTotal = 1
			}
			if total != wantTotal || live != 0 {
				t.Error("update resurrected or removed the deleted fixture")
			}
		})
	}
}
