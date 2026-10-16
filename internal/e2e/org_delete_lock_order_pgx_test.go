//go:build integration

package e2e

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/identuum/identuum-idp-oss/internal/postgres"
)

// G5 (OSS-G5-ORG-DELETE-LOCK-ORDER): an agent communication authorization
// create share-locks its two participant accounts in id order (ACA-CREATE-
// LOCK-1). The organization delete tombstoned every account of the
// organization in one UPDATE, in scan order. With accounts A < B, a create
// holding A and a delete whose scan reached B first wait for each other, and
// Postgres aborts one side (40P01). The delete must lock the accounts in the
// create's order before it writes any of them. Same harness as
// agent_communication_create_lock_pgx_test.go; no test prints a row, a key,
// an SQL argument or a database error.
func TestOrgDeleteAccountLockOrder(t *testing.T) {
	t.Run("delete_beside_a_create_holding_the_lower_account", func(t *testing.T) {
		odlDeleteBesideCreate(t, false, true)
	})
	t.Run("delete_beside_a_create_holding_the_lower_account_roles_reversed", func(t *testing.T) {
		odlDeleteBesideCreate(t, true, true)
	})
	t.Run("control: unmodified delete, accounts inserted higher id first", func(t *testing.T) {
		odlDeleteBesideCreate(t, false, false)
	})
}

// odlSeed is aclSeed with ordered accounts: A < B in id bytes, B inserted
// first, so the physical order is the reverse of the create's lock order.
// reversed gives B the initiator role, which must not change the order.
func odlSeed(t *testing.T, pool *pgxpool.Pool, reversed bool) (w *aclWorld, lower, higher uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	w = &aclWorld{orgID: uuid.New(), owner: uuid.New(), other: uuid.New()}
	lower, higher = uuid.New(), uuid.New()
	if bytes.Compare(lower[:], higher[:]) > 0 {
		lower, higher = higher, lower
	}
	if _, err := pool.Exec(ctx, `INSERT INTO organizations (id, name, domain, org_slug, active)
		VALUES ($1, 'ODL scratch', $2, $3, true)`, w.orgID, w.orgID.String()+".example.invalid", "odl-"+w.orgID.String()); err != nil {
		t.Fatal("seed scratch organization failed")
	}
	for _, u := range []uuid.UUID{w.owner, w.other} {
		if _, err := pool.Exec(ctx, `INSERT INTO users (id, email, password_hash, organization_id, role)
			VALUES ($1, $2, 'x', $3, 'org_admin')`, u, u.String()+"@odl.example.invalid", w.orgID); err != nil {
			t.Fatal("seed scratch user failed")
		}
	}
	w.sa = [2]uuid.UUID{lower, higher}
	if reversed {
		w.sa = [2]uuid.UUID{higher, lower}
	}
	for _, sa := range []uuid.UUID{higher, lower} {
		i := 0
		if w.sa[1] == sa {
			i = 1
		}
		w.client[i] = uuid.New()
		w.clientID[i] = "odl-" + w.client[i].String()
		if _, err := pool.Exec(ctx, `INSERT INTO service_accounts (id, organization_id, name, description, owner_user_id)
			VALUES ($1, $2, $3, '', $4)`, sa, w.orgID, "ODL scratch "+sa.String(), w.owner); err != nil {
			t.Fatal("seed scratch service account failed")
		}
		if _, err := pool.Exec(ctx, `INSERT INTO oauth_clients (id, client_id, client_secret_hash, name, redirect_uris, scope,
			service_account_id, organization_id, token_endpoint_auth_method, jwks)
			VALUES ($1, $2, '', 'odl client', '{}', 'openid', $3, $4, 'private_key_jwt', '{"keys":[{"kty":"OKP"}]}')`,
			w.client[i], w.clientID[i], sa, w.orgID); err != nil {
			t.Fatal("seed scratch client failed")
		}
	}
	t.Cleanup(func() {
		cleanup, cc := context.WithTimeout(context.Background(), 5*time.Second)
		defer cc()
		_, _ = pool.Exec(cleanup, `DELETE FROM agent_communication_authorizations WHERE organization_id = $1`, w.orgID)
		_, _ = pool.Exec(cleanup, `DELETE FROM oauth_clients WHERE organization_id = $1`, w.orgID)
		_, _ = pool.Exec(cleanup, `DELETE FROM service_accounts WHERE organization_id = $1`, w.orgID)
		_, _ = pool.Exec(cleanup, `DELETE FROM users WHERE organization_id = $1`, w.orgID)
		_, _ = pool.Exec(cleanup, `DELETE FROM organizations WHERE id = $1`, w.orgID)
	})
	return w, lower, higher
}

// odlSecondAccountGate wraps the scratch transaction the create writes
// through. It holds the create before its SECOND account lock read: the
// first account (the lower id) is share-locked, the second is not yet asked.
type odlSecondAccountGate struct {
	pgx.Tx
	gate     *c1fixAccountGate
	accounts *int
	nested   bool
}

func (tx *odlSecondAccountGate) Begin(ctx context.Context) (pgx.Tx, error) {
	inner, err := tx.Tx.Begin(ctx)
	if err != nil {
		return nil, err
	}
	return &odlSecondAccountGate{Tx: inner, gate: tx.gate, accounts: tx.accounts, nested: true}, nil
}

func (tx *odlSecondAccountGate) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	if tx.nested && strings.Contains(sql, "FROM service_accounts") && strings.Contains(sql, "FOR SHARE") {
		*tx.accounts++
		if *tx.accounts == 2 {
			tx.gate.once.Do(func() { close(tx.gate.entered) })
			select {
			case <-tx.gate.release:
			case <-ctx.Done():
			}
		}
	}
	return tx.Tx.QueryRow(ctx, sql, args...)
}

// odlScanOrderDB models the adverse scan order without depending on the
// planner: immediately before the delete's bulk account UPDATE it takes
// NO KEY UPDATE on the higher account, the row such a scan reaches first.
// A delete that locked the accounts in id order before that UPDATE waits at
// the lower account and cannot reach this step while the create holds it.
type odlScanOrderDB struct {
	*pgxpool.Pool
	first uuid.UUID
}

func (d *odlScanOrderDB) Begin(ctx context.Context) (pgx.Tx, error) {
	tx, err := d.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	return &odlScanOrderTx{Tx: tx, first: d.first}, nil
}

type odlScanOrderTx struct {
	pgx.Tx
	first uuid.UUID
}

func (tx *odlScanOrderTx) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	if strings.HasPrefix(strings.TrimSpace(sql), "UPDATE service_accounts") {
		if _, err := tx.Tx.Exec(ctx, `SELECT 1 FROM service_accounts WHERE id = $1 FOR NO KEY UPDATE`, tx.first); err != nil {
			return pgconn.CommandTag{}, err
		}
	}
	return tx.Tx.Exec(ctx, sql, args...)
}

func odlDeadlock(err error) bool {
	var pg *pgconn.PgError
	return errors.As(err, &pg) && pg.Code == "40P01"
}

// The create holds the lower account and has not asked for the higher one.
// The organization delete starts and waits for the create. The create then
// asks for the higher account. Both complete, neither is a deadlock victim,
// and the organization is tombstoned at one instant. Before the fix the
// delete held the higher account while it waited, and Postgres aborted one
// side with 40P01. scanOrder false is the control: the delete runs unwrapped.
func odlDeleteBesideCreate(t *testing.T, reversed, scanOrder bool) {
	pool := f2ScratchPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	w, _, higher := odlSeed(t, pool, reversed)
	a := f2Begin(t, ctx, pool)
	gate := &c1fixAccountGate{entered: make(chan struct{}), release: make(chan struct{})}
	var workers sync.WaitGroup
	defer func() { cancel(); workers.Wait() }()
	released := false
	defer func() {
		if !released {
			close(gate.release)
		}
	}()
	accounts := 0
	ra := aclStart(ctx, &workers, aclService(&odlSecondAccountGate{Tx: a, gate: gate, accounts: &accounts}, pool), w.input())
	f2Await(t, ctx, gate.entered)

	var db postgres.DBTX = pool
	if scanOrder {
		db = &odlScanOrderDB{Pool: pool, first: higher}
	}
	deleted := make(chan error, 1)
	workers.Add(1)
	go func() {
		defer workers.Done()
		deleted <- postgres.NewPgxOrganizationRepository(db).Delete(ctx, w.orgID)
	}()
	waited := c1fixObserveWait(t, ctx, pool, a.Conn().PgConn().PID(), deleted)
	close(gate.release)
	released = true
	r := aclAwait(t, ctx, ra)
	if r.err == nil {
		if err := a.Commit(ctx); err != nil {
			t.Fatal("scratch A commit failed")
		}
	} else {
		_ = a.Rollback(ctx)
	}
	var derr error
	select {
	case derr = <-deleted:
	case <-ctx.Done():
		t.Fatal("organization delete stalled; no behavioral verdict")
	}
	if !waited {
		t.Error("the organization delete did not wait for the create holding the lower account")
	}
	if r.err != nil || r.a == nil {
		t.Error("the create failed beside the organization delete (deadlock victim or store failure)")
	}
	switch {
	case odlDeadlock(derr):
		t.Error("the organization delete was a deadlock victim (40P01)")
	case derr != nil:
		t.Error("the organization delete failed beside an authorization create")
	}
	if derr != nil {
		return
	}
	var stamps, live int
	if err := pool.QueryRow(ctx, `SELECT count(DISTINCT deleted_at), count(*) FILTER (WHERE deleted_at IS NULL) FROM (
		SELECT deleted_at FROM users WHERE organization_id = $1
		UNION ALL SELECT deleted_at FROM service_accounts WHERE organization_id = $1
		UNION ALL SELECT deleted_at FROM oauth_clients WHERE organization_id = $1
		UNION ALL SELECT deleted_at FROM organizations WHERE id = $1) s`, w.orgID).Scan(&stamps, &live); err != nil {
		t.Fatal("final scratch tombstone read failed")
	}
	if live != 0 {
		t.Errorf("%d user, account, client or organization row(s) left live; want 0", live)
	}
	if stamps != 1 {
		t.Errorf("%d distinct deletion timestamps; want the one instant of the delete", stamps)
	}
}
