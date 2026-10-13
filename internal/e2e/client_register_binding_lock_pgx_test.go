//go:build integration

package e2e

import (
	"context"
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

// O9 (OSS-0913-O9-FIX): a new client that binds a service account gets the
// same protection the C1 fix gave the client save. Before the fix the create
// validated the account through its own connection and then inserted the
// client with no lock on the account: the insert's foreign key takes only
// FOR KEY SHARE, which an UPDATE that changes no key (OSS soft-deletes and
// deactivates accounts by UPDATE) does not wait for. So a soft delete or a
// deactivation that landed after the check left a new client bound to a dead
// account. Same harness and fixtures as client_update_lock_c1_pgx_test.go;
// no test prints a client row, a secret, an SQL argument or a database error.

// RULE: CLIENT-REGISTER-BINDING-LOCK-1
func TestClientRegisterBindingLock(t *testing.T) {
	t.Run("account_soft_deleted_after_the_check", func(t *testing.T) { o9AccountChangedAfterTheCheck(t, c1fixSoftDelete) })
	t.Run("account_deactivated_after_the_check", func(t *testing.T) { o9AccountChangedAfterTheCheck(t, c1fixDeactivate) })
	t.Run("soft_delete_waits_for_a_binding_create", func(t *testing.T) { o9AccountChangeWaits(t, c1fixSoftDelete) })
	t.Run("deactivate_waits_for_a_binding_create", func(t *testing.T) { o9AccountChangeWaits(t, c1fixDeactivate) })
	t.Run("org_delete_during_a_binding_create", o9OrgDeleteDuringBindingCreate)
	t.Run("control: a live account binds", o9LiveAccountBinds)
}

// o9Seed seeds an active organization and a live service account in it.
func o9Seed(t *testing.T, pool *pgxpool.Pool) (orgID, saID uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	orgID, saID = uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO organizations (id, name, domain, org_slug, active)
		VALUES ($1, 'O9 scratch', $2, $3, true)`, orgID, orgID.String()+".example.invalid", "o9-"+orgID.String()); err != nil {
		t.Fatal("seed scratch organization failed")
	}
	// A description, as the production create writes one: the account read
	// that validates a binding refuses a NULL there.
	if _, err := pool.Exec(ctx, `INSERT INTO service_accounts (id, organization_id, name, description) VALUES ($1, $2, 'O9 scratch', '')`, saID, orgID); err != nil {
		t.Fatal("seed scratch service account failed")
	}
	t.Cleanup(func() {
		cleanup, cc := context.WithTimeout(context.Background(), 5*time.Second)
		defer cc()
		_, _ = pool.Exec(cleanup, `DELETE FROM oauth_clients WHERE organization_id = $1`, orgID)
		_, _ = pool.Exec(cleanup, `DELETE FROM service_accounts WHERE id = $1`, saID)
		_, _ = pool.Exec(cleanup, `DELETE FROM organizations WHERE id = $1`, orgID)
	})
	return orgID, saID
}

func o9Options(orgID, saID uuid.UUID) service.RegisterClientOptions {
	return service.RegisterClientOptions{
		Name:             "o9 client",
		OrganizationID:   &orgID,
		ServiceAccountID: &saID,
		Scope:            "openid",
		RedirectURIs:     []string{"https://o9.example.invalid/cb"},
	}
}

type o9Result struct {
	client *domain.Client
	err    error
}

// o9BoundClients counts live clients of org bound to saID, read on the pool.
func o9BoundClients(t *testing.T, ctx context.Context, pool *pgxpool.Pool, orgID, saID uuid.UUID) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM oauth_clients WHERE organization_id = $1 AND service_account_id = $2 AND deleted_at IS NULL`, orgID, saID).Scan(&n); err != nil {
		t.Fatal("final scratch client count failed")
	}
	return n
}

// o9CheckGateTx holds the create just before its FIRST statement that touches
// the account or inserts the client: after the binding was validated on the
// pool, before anything in the create's transaction. Before the fix that
// statement is the INSERT; after it, the share-lock read of the account.
type o9CheckGateTx struct {
	pgx.Tx
	gate *c1fixAccountGate
}

func (tx *o9CheckGateTx) Begin(ctx context.Context) (pgx.Tx, error) {
	nested, err := tx.Tx.Begin(ctx)
	if err != nil {
		return nil, err
	}
	return &o9CheckGateTx{Tx: nested, gate: tx.gate}, nil
}

func (tx *o9CheckGateTx) hold(ctx context.Context, sql string) {
	s := strings.ToLower(sql)
	if !strings.Contains(s, "from service_accounts") && !strings.Contains(s, "insert into oauth_clients") {
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

func (tx *o9CheckGateTx) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	tx.hold(ctx, sql)
	return tx.Tx.Exec(ctx, sql, args...)
}

func (tx *o9CheckGateTx) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	tx.hold(ctx, sql)
	return tx.Tx.QueryRow(ctx, sql, args...)
}

// The account is soft-deleted or deactivated after the create validated it.
// The create refuses with the plain reason the client save uses and no client
// is bound. Before the fix the client was created bound to the changed account.
func o9AccountChangedAfterTheCheck(t *testing.T, change c1fixChange) {
	pool := f2ScratchPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	orgID, saID := o9Seed(t, pool)
	a := f2Begin(t, ctx, pool)
	gate := &c1fixAccountGate{entered: make(chan struct{}), release: make(chan struct{})}
	var workers sync.WaitGroup
	defer func() { cancel(); workers.Wait() }()
	svc := c1fixBindingService(&o9CheckGateTx{Tx: a, gate: gate}, pool)
	ra := make(chan o9Result, 1)
	workers.Add(1)
	go func() {
		defer workers.Done()
		c, _, err := svc.RegisterClient(ctx, o9Options(orgID, saID))
		ra <- o9Result{client: c, err: err}
	}()
	f2Await(t, ctx, gate.entered)
	cctx, ccancel := context.WithTimeout(ctx, 3*time.Second)
	defer ccancel()
	if err := change(cctx, pool, saID, orgID); err != nil {
		t.Fatal("the account change failed while no create held the account")
	}
	close(gate.release)
	var r o9Result
	select {
	case r = <-ra:
	case <-ctx.Done():
		t.Fatal("binding create stalled; no behavioral verdict")
	}
	if err := a.Commit(ctx); err != nil {
		t.Fatal("scratch A commit failed")
	}
	if r.err == nil {
		t.Error("the create bound a new client to a service account that changed after the check")
	} else if domain.IsAuthStoreUnavailable(r.err) || !strings.Contains(r.err.Error(), "nothing was saved") {
		t.Error("the refusal must be a plain reason, not a store failure")
	}
	if n := o9BoundClients(t, ctx, pool, orgID, saID); n != 0 {
		t.Errorf("%d client(s) bound to the changed service account; want 0", n)
	}
}

// o9InsertGateTx holds the create right AFTER its client INSERT returned, with
// its transaction still open: every lock the create takes is held.
type o9InsertGateTx struct {
	pgx.Tx
	gate *f2ReadGate
}

func (tx *o9InsertGateTx) Begin(ctx context.Context) (pgx.Tx, error) {
	nested, err := tx.Tx.Begin(ctx)
	if err != nil {
		return nil, err
	}
	return &o9InsertGateTx{Tx: nested, gate: tx.gate}, nil
}

func (tx *o9InsertGateTx) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	row := tx.Tx.QueryRow(ctx, sql, args...)
	if !strings.Contains(strings.ToLower(sql), "insert into oauth_clients") {
		return row
	}
	selected := false
	tx.gate.once.Do(func() { selected = true; close(tx.gate.entered) })
	if !selected {
		return row
	}
	return &f2GatedRow{row: row, ctx: ctx, gate: tx.gate}
}

// o9HeldCreate starts a binding create on the scratch transaction a and holds
// it after its client INSERT, every lock it takes still held.
func o9HeldCreate(t *testing.T, ctx context.Context, workers *sync.WaitGroup, pool *pgxpool.Pool, a pgx.Tx, orgID, saID uuid.UUID) (*f2ReadGate, chan o9Result) {
	t.Helper()
	ga := newF2ReadGate()
	svc := c1fixBindingService(&o9InsertGateTx{Tx: a, gate: ga}, pool)
	ra := make(chan o9Result, 1)
	workers.Add(1)
	go func() {
		defer workers.Done()
		c, _, err := svc.RegisterClient(ctx, o9Options(orgID, saID))
		ra <- o9Result{client: c, err: err}
	}()
	f2Await(t, ctx, ga.scanned)
	return ga, ra
}

// While a binding create holds the account, its soft delete or deactivation
// waits until the create commits; the create binds a live account and the
// change lands after it. Before the fix the change did not wait.
func o9AccountChangeWaits(t *testing.T, change c1fixChange) {
	pool := f2ScratchPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	orgID, saID := o9Seed(t, pool)
	a := f2Begin(t, ctx, pool)
	var workers sync.WaitGroup
	defer func() { cancel(); workers.Wait() }()
	ga, ra := o9HeldCreate(t, ctx, &workers, pool, a, orgID, saID)

	changed := make(chan error, 1)
	workers.Add(1)
	go func() {
		defer workers.Done()
		changed <- change(ctx, pool, saID, orgID)
	}()
	waited := c1fixObserveWait(t, ctx, pool, a.Conn().PgConn().PID(), changed)
	close(ga.release)
	var r o9Result
	select {
	case r = <-ra:
	case <-ctx.Done():
		t.Fatal("binding create stalled; no behavioral verdict")
	}
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
		t.Error("the account change did not wait for the create that binds the account")
	}
	if cerr != nil {
		t.Error("the account change failed after the create committed")
	}
	if r.err != nil || r.client == nil || r.client.ServiceAccountID == nil || *r.client.ServiceAccountID != saID {
		t.Error("the create did not bind the live service account")
	}
}

// An organization delete that comes while a binding create holds the account
// waits for the create, takes the account and then the clients (the create's
// own order, so no deadlock) and tombstones the new client with the rest of
// the organization. Before the fix the delete did not wait, did not see the
// uncommitted client, and the client outlived its organization.
func o9OrgDeleteDuringBindingCreate(t *testing.T) {
	pool := f2ScratchPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	orgID, saID := o9Seed(t, pool)
	a := f2Begin(t, ctx, pool)
	var workers sync.WaitGroup
	defer func() { cancel(); workers.Wait() }()
	ga, ra := o9HeldCreate(t, ctx, &workers, pool, a, orgID, saID)

	deleted := make(chan error, 1)
	workers.Add(1)
	go func() {
		defer workers.Done()
		deleted <- postgres.NewPgxOrganizationRepository(pool).Delete(ctx, orgID)
	}()
	waited := c1fixObserveWait(t, ctx, pool, a.Conn().PgConn().PID(), deleted)
	close(ga.release)
	var r o9Result
	select {
	case r = <-ra:
	case <-ctx.Done():
		t.Fatal("binding create stalled; no behavioral verdict")
	}
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
		t.Error("the organization delete did not wait for the held create")
	}
	if derr != nil {
		t.Error("the organization delete failed beside a binding create")
	}
	if r.err != nil || r.client == nil {
		t.Fatal("the create did not complete beside the organization delete")
	}
	var tombstoned bool
	if err := pool.QueryRow(ctx, `SELECT deleted_at IS NOT NULL FROM oauth_clients WHERE id = $1`, r.client.ID).Scan(&tombstoned); err != nil {
		t.Fatal("final scratch client read failed")
	}
	if !tombstoned {
		t.Error("the organization delete did not tombstone the new client")
	}
}

// Control, green before and after: a create that binds a live account, with
// nothing in between, succeeds and binds it.
func o9LiveAccountBinds(t *testing.T) {
	pool := f2ScratchPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	orgID, saID := o9Seed(t, pool)
	svc := c1fixBindingService(pool, pool)
	c, _, err := svc.RegisterClient(ctx, o9Options(orgID, saID))
	if err != nil || c == nil || c.ServiceAccountID == nil || *c.ServiceAccountID != saID {
		t.Fatal("a create binding a live account did not bind it")
	}
	if n := o9BoundClients(t, ctx, pool, orgID, saID); n != 1 {
		t.Errorf("%d client(s) bound; want 1", n)
	}
}
