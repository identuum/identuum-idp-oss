//go:build integration

package e2e

import (
	"context"
	"errors"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/postgres"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// C1 (OSS v0.9.12): the rest of the client update lock's writer coverage, on
// the same scratch database and harness as client_update_lock_pgx_test.go.
// Fixtures carry identifiers and Booleans only; no test prints a client row,
// a secret hash, an SQL argument or a database error.

// c1SeedConfidential seeds a confidential client that has a secret on file,
// so the secret can be regenerated.
func c1SeedConfidential(t *testing.T, pool *pgxpool.Pool) uuid.UUID {
	t.Helper()
	orgID, id := uuid.New(), uuid.New()
	ctx := context.Background()
	_, err := pool.Exec(ctx, `INSERT INTO organizations (id, name, domain, org_slug, active)
		VALUES ($1, 'C1 scratch', $2, $3, true)`, orgID, orgID.String()+".example.invalid", "c1-"+orgID.String())
	if err != nil {
		t.Fatal("seed scratch organization failed")
	}
	client := &domain.Client{
		ID: id, ClientID: "c1-" + id.String(), Name: "old", OrganizationID: &orgID,
		ClientSecretHash: "c1-seed-hash", Scope: "openid", TokenEndpointAuthMethod: "client_secret_basic",
		RedirectURIs: []string{"https://c1.example.invalid/cb"},
	}
	if err := postgres.NewPgxClientRepository(pool).RegisterClient(ctx, client); err != nil {
		t.Fatal("seed confidential scratch client failed")
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = pool.Exec(cleanup, `DELETE FROM oauth_clients WHERE id = $1`, id)
		_, _ = pool.Exec(cleanup, `DELETE FROM organizations WHERE id = $1`, orgID)
	})
	return id
}

// RULE: CLIENT-UPDATE-LOCK-SCOPE-1
func TestClientUpdateLock_Scope(t *testing.T) {
	t.Run("regenerate_vs_update", c1RegenerateVsUpdate)
	t.Run("different_clients_do_not_block", c1DifferentClientsDoNotBlock)
	t.Run("referencing_insert_not_blocked", c1ReferencingInsertNotBlocked)
	t.Run("binding_holds_the_service_account", c1BindingHoldsTheServiceAccount)
	t.Run("account_soft_deleted_before_the_lock", func(t *testing.T) { c1fixAccountChangedBeforeTheLock(t, c1fixSoftDelete) })
	t.Run("account_deactivated_before_the_lock", func(t *testing.T) { c1fixAccountChangedBeforeTheLock(t, c1fixDeactivate) })
	t.Run("soft_delete_waits_for_a_binding_save", func(t *testing.T) { c1fixAccountChangeWaits(t, c1fixSoftDelete) })
	t.Run("deactivate_waits_for_a_binding_save", func(t *testing.T) { c1fixAccountChangeWaits(t, c1fixDeactivate) })
	t.Run("org_delete_during_a_binding_save", c1fixOrgDeleteDuringBindingSave)
}

// Writer coverage: a competing secret rotation. A rename that read the row
// before the rotation committed must not write the old secret hash back.
func c1RegenerateVsUpdate(t *testing.T) {
	pool := f2ScratchPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	id := c1SeedConfidential(t, pool)
	a, b := f2Begin(t, ctx, pool), f2Begin(t, ctx, pool)
	ga, gb := newF2ReadGate(), newF2ReadGate()
	pidA, pidB := a.Conn().PgConn().PID(), b.Conn().PgConn().PID()
	var workers sync.WaitGroup
	defer func() { cancel(); workers.Wait() }()
	sa := service.NewClientService(nil, postgres.NewPgxClientRepository(&f2LockTx{Tx: a, gate: ga}))
	sb := service.NewClientService(nil, postgres.NewPgxClientRepository(&f2LockTx{Tx: b, gate: gb}))
	newName := "renamed"

	ra, rb := make(chan f2UpdateResult, 1), make(chan f2UpdateResult, 1)
	workers.Add(1)
	go func() {
		defer workers.Done()
		c, _, err := sa.RegenerateClientSecret(ctx, id)
		ra <- f2UpdateResult{client: c, err: err}
	}()
	f2Await(t, ctx, ga.scanned)
	workers.Add(1)
	go func() {
		defer workers.Done()
		c, err := sb.UpdateClient(ctx, id, service.UpdateClientOptions{Name: &newName})
		rb <- f2UpdateResult{client: c, err: err}
	}()
	f2Await(t, ctx, gb.entered)
	blocked := f2ObserveReadOrLock(t, ctx, pool, pidA, pidB, gb.scanned)
	close(ga.release)
	ar := f2Result(t, ctx, ra)
	if err := a.Commit(ctx); err != nil {
		t.Fatal("scratch A commit failed")
	}
	close(gb.release)
	f2Result(t, ctx, rb)
	if err := b.Commit(ctx); err != nil {
		t.Fatal("scratch B commit failed")
	}
	got, err := postgres.NewPgxClientRepository(pool).GetClientByID(ctx, id)
	if err != nil || got == nil {
		t.Fatal("final scratch client read failed")
	}
	if got.Name != newName {
		t.Error("the rename was lost")
	}
	if got.ClientSecretHash != ar.client.ClientSecretHash || got.ClientSecretHash == "c1-seed-hash" {
		t.Error("the rename wrote the old secret back over the rotated one")
	}
	t.Logf("observed B waiting on A's database lock: %t", blocked)
}

// One client row per save. A save of one client never waits on a save of
// another.
func c1DifferentClientsDoNotBlock(t *testing.T) {
	pool := f2ScratchPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	first, second := c1SeedConfidential(t, pool), c1SeedConfidential(t, pool)
	a := f2Begin(t, ctx, pool)
	ga := newF2ReadGate()
	var workers sync.WaitGroup
	defer func() { cancel(); workers.Wait() }()
	sa := service.NewClientService(nil, postgres.NewPgxClientRepository(&f2LockTx{Tx: a, gate: ga}))
	nameA, nameB := "first", "second"
	ra := make(chan f2UpdateResult, 1)
	workers.Add(1)
	go func() {
		defer workers.Done()
		c, err := sa.UpdateClient(ctx, first, service.UpdateClientOptions{Name: &nameA})
		ra <- f2UpdateResult{client: c, err: err}
	}()
	f2Await(t, ctx, ga.scanned)

	// A holds its client between its read and its write. The other client's
	// save runs to completion meanwhile.
	bctx, bcancel := context.WithTimeout(ctx, 5*time.Second)
	defer bcancel()
	sb := service.NewClientService(nil, postgres.NewPgxClientRepository(pool))
	if c, err := sb.UpdateClient(bctx, second, service.UpdateClientOptions{Name: &nameB}); err != nil || c == nil {
		t.Error("a save of another client waited on, or failed beside, a held save")
	}
	close(ga.release)
	f2Result(t, ctx, ra)
	if err := a.Commit(ctx); err != nil {
		t.Fatal("scratch A commit failed")
	}
}

// Lock mode, owner answer Q-C1-3. While a save holds its client row, rows that
// reference the client can still be written: the save does not block token,
// code, consent or registration-limit inserts for that client.
func c1ReferencingInsertNotBlocked(t *testing.T) {
	pool := f2ScratchPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	id := c1SeedConfidential(t, pool)
	a := f2Begin(t, ctx, pool)
	ga := newF2ReadGate()
	var workers sync.WaitGroup
	defer func() { cancel(); workers.Wait() }()
	sa := service.NewClientService(nil, postgres.NewPgxClientRepository(&f2LockTx{Tx: a, gate: ga}))
	name := "held"
	ra := make(chan f2UpdateResult, 1)
	workers.Add(1)
	go func() {
		defer workers.Done()
		c, err := sa.UpdateClient(ctx, id, service.UpdateClientOptions{Name: &name})
		ra <- f2UpdateResult{client: c, err: err}
	}()
	f2Await(t, ctx, ga.scanned)

	ictx, icancel := context.WithTimeout(ctx, 3*time.Second)
	defer icancel()
	if _, err := pool.Exec(ictx, `INSERT INTO dcr_client_registration_limits (client_id) VALUES ($1)`, id); err != nil {
		t.Error("an insert that references the client waited on, or failed beside, a held save")
	}
	close(ga.release)
	f2Result(t, ctx, ra)
	if err := a.Commit(ctx); err != nil {
		t.Fatal("scratch A commit failed")
	}
	t.Cleanup(func() {
		cleanup, cc := context.WithTimeout(context.Background(), 5*time.Second)
		defer cc()
		_, _ = pool.Exec(cleanup, `DELETE FROM dcr_client_registration_limits WHERE client_id = $1`, id)
	})
}

// c1LockedReadTx gates only the save's LOCKED read of the client (the one
// that carries the row lock), not a plain read taken before it.
type c1LockedReadTx struct {
	pgx.Tx
	gate *f2ReadGate
}

func (tx *c1LockedReadTx) Begin(ctx context.Context) (pgx.Tx, error) {
	nested, err := tx.Tx.Begin(ctx)
	if err != nil {
		return nil, err
	}
	return &c1LockedReadTx{Tx: nested, gate: tx.gate}, nil
}

func (tx *c1LockedReadTx) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	row := tx.Tx.QueryRow(ctx, sql, args...)
	if !strings.Contains(strings.ToLower(sql), "for no key update") {
		return row
	}
	selected := false
	tx.gate.once.Do(func() { selected = true; close(tx.gate.entered) })
	if !selected {
		return row
	}
	return &f2GatedRow{row: row, ctx: ctx, gate: tx.gate}
}

// Lock order. A save that binds a service account holds that account before
// it locks the client: while the save runs, a hard DELETE of the account
// waits (account then client, the order the organization delete uses). OSS
// itself deletes and deactivates accounts by UPDATE; the account_* subtests
// below cover those.
func c1BindingHoldsTheServiceAccount(t *testing.T) {
	pool := f2ScratchPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	id := c1SeedConfidential(t, pool)
	got, err := postgres.NewPgxClientRepository(pool).GetClientByID(ctx, id)
	if err != nil || got == nil || got.OrganizationID == nil {
		t.Fatal("fixture read failed")
	}
	saID := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO service_accounts (id, organization_id, name) VALUES ($1, $2, 'C1 scratch')`, saID, *got.OrganizationID); err != nil {
		t.Fatal("seed scratch service account failed")
	}
	t.Cleanup(func() {
		cleanup, cc := context.WithTimeout(context.Background(), 5*time.Second)
		defer cc()
		_, _ = pool.Exec(cleanup, `UPDATE oauth_clients SET service_account_id = NULL WHERE id = $1`, id)
		_, _ = pool.Exec(cleanup, `DELETE FROM service_accounts WHERE id = $1`, saID)
	})

	a := f2Begin(t, ctx, pool)
	ga := newF2ReadGate()
	var workers sync.WaitGroup
	defer func() { cancel(); workers.Wait() }()
	sa := service.NewClientService(nil, postgres.NewPgxClientRepository(&c1LockedReadTx{Tx: a, gate: ga}))
	ra := make(chan f2UpdateResult, 1)
	workers.Add(1)
	go func() {
		defer workers.Done()
		c, err := sa.UpdateClient(ctx, id, service.UpdateClientOptions{ServiceAccountID: &saID})
		ra <- f2UpdateResult{client: c, err: err}
	}()
	f2Await(t, ctx, ga.scanned)

	dctx, dcancel := context.WithTimeout(ctx, 2*time.Second)
	defer dcancel()
	if _, err := pool.Exec(dctx, `DELETE FROM service_accounts WHERE id = $1`, saID); err == nil {
		t.Error("the service account was deleted while a save binding it held the client")
	}
	close(ga.release)
	r := f2Result(t, ctx, ra)
	if err := a.Commit(ctx); err != nil {
		t.Fatal("scratch A commit failed")
	}
	if r.client.ServiceAccountID == nil || *r.client.ServiceAccountID != saID {
		t.Error("the save did not bind the service account")
	}
}

// RULE: CLIENT-MUTATION-COMMIT-1
func TestClientMutation_StoreFailureIs503(t *testing.T) {
	t.Run("lock_wait_cancelled", c1LockWaitCancelledIs503)
	t.Run("write_or_commit_failure", c1WriteOrCommitFailureIsStoreUnavailable)
}

// A save whose wait for the client's lock is cancelled answers "store
// unavailable" (503 at the API) and changes nothing.
func c1LockWaitCancelledIs503(t *testing.T) {
	pool := f2ScratchPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	id := c1SeedConfidential(t, pool)
	holder := f2Begin(t, ctx, pool)
	if _, err := holder.Exec(ctx, `SELECT 1 FROM oauth_clients WHERE id = $1 FOR UPDATE`, id); err != nil {
		t.Fatal("hold scratch client row failed")
	}
	holderPID := holder.Conn().PgConn().PID()

	bctx, bcancel := context.WithCancel(ctx)
	defer bcancel()
	svc := service.NewClientService(nil, postgres.NewPgxClientRepository(pool))
	name := "must not land"
	done := make(chan error, 1)
	go func() {
		_, err := svc.UpdateClient(bctx, id, service.UpdateClientOptions{Name: &name})
		done <- err
	}()
	for {
		var waiting bool
		if err := pool.QueryRow(ctx, `SELECT count(*) > 0 FROM pg_stat_activity WHERE $1::int = ANY(pg_blocking_pids(pid))`, int64(holderPID)).Scan(&waiting); err != nil {
			t.Fatal("lock observer failed; no behavioral verdict")
		}
		if waiting {
			break
		}
		select {
		case err := <-done:
			if err == nil {
				t.Fatal("the save completed while another transaction held the client row")
			}
			t.Fatal("the save failed before it waited on the held row; no behavioral verdict")
		case <-ctx.Done():
			t.Fatal("the save never waited on the held row; no behavioral verdict")
		default:
		}
	}
	bcancel()
	var err error
	select {
	case err = <-done:
	case <-ctx.Done():
		t.Fatal("the cancelled save did not return")
	}
	if !domain.IsAuthStoreUnavailable(err) {
		t.Error("a cancelled lock wait must answer store unavailable")
	}
	if err := holder.Rollback(ctx); err != nil {
		t.Fatal("release scratch client row failed")
	}
	got, gerr := postgres.NewPgxClientRepository(pool).GetClientByID(ctx, id)
	if gerr != nil || got == nil || got.Name != "old" {
		t.Error("a cancelled save changed the client")
	}
}

// c1FaultDB is the scratch pool with one injected fault: the client UPDATE
// fails, or the transaction's COMMIT fails after rolling back. No SQL is
// replaced; every other statement reaches the database.
type c1FaultDB struct {
	postgres.DBTX
	failWrite, failCommit bool
}

var errC1Injected = errors.New("c1 injected store failure")

func c1IsClientUpdate(sql string) bool {
	return strings.Contains(strings.ToLower(sql), "update oauth_clients")
}

func (d *c1FaultDB) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	if d.failWrite && c1IsClientUpdate(sql) {
		return pgconn.CommandTag{}, errC1Injected
	}
	return d.DBTX.Exec(ctx, sql, args...)
}

func (d *c1FaultDB) Begin(ctx context.Context) (pgx.Tx, error) {
	tx, err := d.DBTX.Begin(ctx)
	if err != nil {
		return nil, err
	}
	return &c1FaultTx{Tx: tx, db: d}, nil
}

type c1FaultTx struct {
	pgx.Tx
	db *c1FaultDB
}

func (tx *c1FaultTx) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	if tx.db.failWrite && c1IsClientUpdate(sql) {
		return pgconn.CommandTag{}, errC1Injected
	}
	return tx.Tx.Exec(ctx, sql, args...)
}

func (tx *c1FaultTx) Begin(ctx context.Context) (pgx.Tx, error) {
	nested, err := tx.Tx.Begin(ctx)
	if err != nil {
		return nil, err
	}
	return &c1FaultTx{Tx: nested, db: tx.db}, nil
}

func (tx *c1FaultTx) Commit(ctx context.Context) error {
	if tx.db.failCommit {
		_ = tx.Tx.Rollback(ctx)
		return errC1Injected
	}
	return tx.Tx.Commit(ctx)
}

// A save or a secret rotation whose write or commit fails answers "store
// unavailable" (503 at the API, never a 400 or a success) and leaves the
// client as it was.
func c1WriteOrCommitFailureIsStoreUnavailable(t *testing.T) {
	pool := f2ScratchPool(t)
	for _, tc := range []struct {
		name                  string
		regenerate            bool
		failWrite, failCommit bool
	}{
		{"update_write", false, true, false},
		{"update_commit", false, false, true},
		{"regenerate_write", true, true, false},
		{"regenerate_commit", true, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			id := c1SeedConfidential(t, pool)
			svc := service.NewClientService(nil, postgres.NewPgxClientRepository(&c1FaultDB{DBTX: pool, failWrite: tc.failWrite, failCommit: tc.failCommit}))
			var err error
			if tc.regenerate {
				_, _, err = svc.RegenerateClientSecret(ctx, id)
			} else {
				name := "must not land"
				_, err = svc.UpdateClient(ctx, id, service.UpdateClientOptions{Name: &name})
			}
			if err == nil {
				t.Fatal("a failed write or commit reported success")
			}
			if !domain.IsAuthStoreUnavailable(err) {
				t.Error("a failed write or commit must answer store unavailable")
			}
			got, gerr := postgres.NewPgxClientRepository(pool).GetClientByID(ctx, id)
			if gerr != nil || got == nil || got.Name != "old" || got.ClientSecretHash != "c1-seed-hash" {
				t.Error("a failed write or commit changed the client")
			}
		})
	}
}

// OSS-0912-C1-FIX (owner answer Q1 (b)). OSS deletes and deactivates a service
// account by UPDATE, never by DELETE, so a key-share lock did not hold either
// off. A binding save share-locks the account and re-checks it under the lock.

// c1fixChange is a production change of a service account: soft delete or
// deactivation.
type c1fixChange func(ctx context.Context, pool *pgxpool.Pool, saID, orgID uuid.UUID) error

func c1fixSoftDelete(ctx context.Context, pool *pgxpool.Pool, saID, orgID uuid.UUID) error {
	return postgres.NewPgxServiceAccountRepository(pool).Delete(ctx, saID, orgID)
}

func c1fixDeactivate(ctx context.Context, pool *pgxpool.Pool, saID, orgID uuid.UUID) error {
	return postgres.NewPgxServiceAccountRepository(pool).UpdateActive(ctx, saID, orgID, false)
}

// c1fixSeedAccount seeds a live service account in the client's organization.
func c1fixSeedAccount(t *testing.T, pool *pgxpool.Pool, clientID uuid.UUID) (saID, orgID uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	got, err := postgres.NewPgxClientRepository(pool).GetClientByID(ctx, clientID)
	if err != nil || got == nil || got.OrganizationID == nil {
		t.Fatal("fixture read failed")
	}
	saID, orgID = uuid.New(), *got.OrganizationID
	// A description, as the production create writes one: the account read
	// that validates a binding refuses a NULL there.
	if _, err := pool.Exec(ctx, `INSERT INTO service_accounts (id, organization_id, name, description) VALUES ($1, $2, 'C1 fix scratch', '')`, saID, orgID); err != nil {
		t.Fatal("seed scratch service account failed")
	}
	t.Cleanup(func() {
		cleanup, cc := context.WithTimeout(context.Background(), 5*time.Second)
		defer cc()
		_, _ = pool.Exec(cleanup, `UPDATE oauth_clients SET service_account_id = NULL WHERE id = $1`, clientID)
		_, _ = pool.Exec(cleanup, `DELETE FROM service_accounts WHERE id = $1`, saID)
	})
	return saID, orgID
}

// c1fixBindingService is the client service as production wires it: a binding
// is validated against the live account before the save.
func c1fixBindingService(db postgres.DBTX, pool *pgxpool.Pool) *service.ClientService {
	return service.NewClientService(nil, postgres.NewPgxClientRepository(db)).
		WithServiceAccountBindingValidator(service.NewServiceAccountService(nil, postgres.NewPgxServiceAccountRepository(pool)))
}

// c1fixAccountGateTx holds the save just before its first statement on the
// service account, after the binding was validated: the window the re-check
// under the lock closes.
type c1fixAccountGate struct {
	entered, release chan struct{}
	once             sync.Once
}

type c1fixAccountGateTx struct {
	pgx.Tx
	gate *c1fixAccountGate
}

func (tx *c1fixAccountGateTx) Begin(ctx context.Context) (pgx.Tx, error) {
	nested, err := tx.Tx.Begin(ctx)
	if err != nil {
		return nil, err
	}
	return &c1fixAccountGateTx{Tx: nested, gate: tx.gate}, nil
}

func (tx *c1fixAccountGateTx) hold(ctx context.Context, sql string) {
	if !strings.Contains(strings.ToLower(sql), "from service_accounts") {
		return
	}
	first := false
	tx.gate.once.Do(func() { first = true; close(tx.gate.entered) })
	if !first {
		return
	}
	select {
	case <-tx.gate.release:
	case <-ctx.Done():
	}
}

func (tx *c1fixAccountGateTx) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	tx.hold(ctx, sql)
	return tx.Tx.Exec(ctx, sql, args...)
}

func (tx *c1fixAccountGateTx) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	tx.hold(ctx, sql)
	return tx.Tx.QueryRow(ctx, sql, args...)
}

// c1fixObserveWait reports true once a backend is seen waiting on backend a's
// locks, false if done delivered first (its value is put back). A deadline
// fails the harness; it is never taken as evidence.
func c1fixObserveWait(t *testing.T, ctx context.Context, pool *pgxpool.Pool, a uint32, done chan error) bool {
	t.Helper()
	for {
		select {
		case err := <-done:
			done <- err
			return false
		default:
		}
		var blocked bool
		if err := pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE $1::int = ANY(pg_blocking_pids(pid)))`, int64(a)).Scan(&blocked); err != nil {
			t.Fatal("lock observer failed; no behavioral verdict")
		}
		if blocked {
			return true
		}
		if ctx.Err() != nil {
			t.Fatal("lock observation stalled; no behavioral verdict")
		}
		runtime.Gosched()
	}
}

// The account is soft-deleted or deactivated after the save validated it and
// before the save locks it. The save refuses with a plain reason and the client
// stays unbound. Before the fix the client was bound to the changed account.
func c1fixAccountChangedBeforeTheLock(t *testing.T, change c1fixChange) {
	pool := f2ScratchPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	id := c1SeedConfidential(t, pool)
	saID, orgID := c1fixSeedAccount(t, pool, id)
	a := f2Begin(t, ctx, pool)
	gate := &c1fixAccountGate{entered: make(chan struct{}), release: make(chan struct{})}
	var workers sync.WaitGroup
	defer func() { cancel(); workers.Wait() }()
	svc := c1fixBindingService(&c1fixAccountGateTx{Tx: a, gate: gate}, pool)
	ra := make(chan f2UpdateResult, 1)
	workers.Add(1)
	go func() {
		defer workers.Done()
		c, err := svc.UpdateClient(ctx, id, service.UpdateClientOptions{ServiceAccountID: &saID})
		ra <- f2UpdateResult{client: c, err: err}
	}()
	f2Await(t, ctx, gate.entered)
	cctx, ccancel := context.WithTimeout(ctx, 3*time.Second)
	defer ccancel()
	if err := change(cctx, pool, saID, orgID); err != nil {
		t.Fatal("the account change failed while no save held the account")
	}
	close(gate.release)
	var r f2UpdateResult
	select {
	case r = <-ra:
	case <-ctx.Done():
		t.Fatal("binding save stalled; no behavioral verdict")
	}
	if err := a.Commit(ctx); err != nil {
		t.Fatal("scratch A commit failed")
	}
	if r.err == nil {
		t.Error("the save bound the client to a service account that changed before the save locked it")
	} else if domain.IsAuthStoreUnavailable(r.err) || !strings.Contains(r.err.Error(), "nothing was saved") {
		t.Error("the refusal must be a plain reason, not a store failure")
	}
	got, err := postgres.NewPgxClientRepository(pool).GetClientByID(ctx, id)
	if err != nil || got == nil {
		t.Fatal("final scratch client read failed")
	}
	if got.ServiceAccountID != nil {
		t.Error("the client is bound to the changed service account")
	}
}

// While a binding save holds the account, its soft delete or deactivation
// waits until the save commits: the save binds a live account and the change
// lands after it. Before the fix the change did not wait (FOR KEY SHARE does
// not conflict with an UPDATE that changes no key).
func c1fixAccountChangeWaits(t *testing.T, change c1fixChange) {
	pool := f2ScratchPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	id := c1SeedConfidential(t, pool)
	saID, orgID := c1fixSeedAccount(t, pool, id)
	a := f2Begin(t, ctx, pool)
	ga := newF2ReadGate()
	var workers sync.WaitGroup
	defer func() { cancel(); workers.Wait() }()
	svc := c1fixBindingService(&c1LockedReadTx{Tx: a, gate: ga}, pool)
	ra := make(chan f2UpdateResult, 1)
	workers.Add(1)
	go func() {
		defer workers.Done()
		c, err := svc.UpdateClient(ctx, id, service.UpdateClientOptions{ServiceAccountID: &saID})
		ra <- f2UpdateResult{client: c, err: err}
	}()
	f2Await(t, ctx, ga.scanned)

	changed := make(chan error, 1)
	workers.Add(1)
	go func() {
		defer workers.Done()
		changed <- change(ctx, pool, saID, orgID)
	}()
	waited := c1fixObserveWait(t, ctx, pool, a.Conn().PgConn().PID(), changed)
	close(ga.release)
	r := f2Result(t, ctx, ra)
	if err := a.Commit(ctx); err != nil {
		t.Fatal("scratch A commit failed")
	}
	var cerr error
	select {
	case cerr = <-changed:
	case <-ctx.Done():
		t.Fatal("account change stalled; no behavioral verdict")
	}
	if !waited {
		t.Error("the account change did not wait for the save that binds the account")
	}
	if cerr != nil {
		t.Error("the account change failed after the save committed")
	}
	if r.client.ServiceAccountID == nil || *r.client.ServiceAccountID != saID {
		t.Error("the save did not bind the service account")
	}
}

// Lock order. The organization delete takes accounts, then clients: the order
// a binding save takes. Deleting the organization while such a save is held
// waits, then completes with no deadlock, and the client ends tombstoned.
func c1fixOrgDeleteDuringBindingSave(t *testing.T) {
	pool := f2ScratchPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	id := c1SeedConfidential(t, pool)
	saID, orgID := c1fixSeedAccount(t, pool, id)
	a := f2Begin(t, ctx, pool)
	ga := newF2ReadGate()
	var workers sync.WaitGroup
	defer func() { cancel(); workers.Wait() }()
	svc := c1fixBindingService(&c1LockedReadTx{Tx: a, gate: ga}, pool)
	ra := make(chan f2UpdateResult, 1)
	workers.Add(1)
	go func() {
		defer workers.Done()
		c, err := svc.UpdateClient(ctx, id, service.UpdateClientOptions{ServiceAccountID: &saID})
		ra <- f2UpdateResult{client: c, err: err}
	}()
	f2Await(t, ctx, ga.scanned)

	deleted := make(chan error, 1)
	workers.Add(1)
	go func() {
		defer workers.Done()
		deleted <- postgres.NewPgxOrganizationRepository(pool).Delete(ctx, orgID)
	}()
	waited := c1fixObserveWait(t, ctx, pool, a.Conn().PgConn().PID(), deleted)
	close(ga.release)
	r := f2Result(t, ctx, ra)
	if err := a.Commit(ctx); err != nil {
		t.Fatal("scratch A commit failed")
	}
	var derr error
	select {
	case derr = <-deleted:
	case <-ctx.Done():
		t.Fatal("organization delete stalled; no behavioral verdict")
	}
	if !waited {
		t.Error("the organization delete did not wait for the held save")
	}
	if derr != nil {
		t.Error("the organization delete failed beside a binding save")
	}
	if r.client.ServiceAccountID == nil || *r.client.ServiceAccountID != saID {
		t.Error("the save did not bind the service account")
	}
	var tombstoned bool
	if err := pool.QueryRow(ctx, `SELECT deleted_at IS NOT NULL FROM oauth_clients WHERE id = $1`, id).Scan(&tombstoned); err != nil {
		t.Fatal("final scratch client read failed")
	}
	if !tombstoned {
		t.Error("the organization delete did not tombstone the client")
	}
}
