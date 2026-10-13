//go:build integration

package e2e

import (
	"context"
	"errors"
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

// O1 (OSS-0913-O9-FIX report; OSS-0913-ACA-LOCK): an agent communication
// authorization create has the same unlocked check-then-insert the client
// create had before O9. The service reads each participant account and client
// on its own connection, then the repository inserts the authorization and its
// participants. The participant foreign keys take only FOR KEY SHARE, which an
// UPDATE that changes no key (OSS soft-deletes, deactivates and re-owns an
// account by UPDATE; a client save is an UPDATE) does not wait for. So a change
// that lands after the check leaves a live authorization naming an account or
// client that no longer passes the create's own checks. Same harness as
// client_register_binding_lock_pgx_test.go; no test prints a row, a key, an SQL
// argument or a database error.

// RULE: ACA-CREATE-LOCK-1
func TestAgentCommunicationCreateLock(t *testing.T) {
	t.Run("account_soft_deleted_after_the_check", func(t *testing.T) {
		aclChangedAfterTheCheck(t, aclAccount(c1fixSoftDelete), domain.ErrServiceAccountNotFound)
	})
	t.Run("account_deactivated_after_the_check", func(t *testing.T) {
		aclChangedAfterTheCheck(t, aclAccount(c1fixDeactivate), domain.ErrAgentCommunicationParticipantNotUsable)
	})
	t.Run("account_owner_changed_after_the_check", func(t *testing.T) {
		aclChangedAfterTheCheck(t, aclReOwn, domain.ErrAgentCommunicationOwnerMismatch)
	})
	t.Run("client_unbound_after_the_check", func(t *testing.T) {
		aclChangedAfterTheCheck(t, aclUnbindClient, domain.ErrAgentCommunicationClientNotBound)
	})
	t.Run("client_deleted_after_the_check", func(t *testing.T) {
		aclChangedAfterTheCheck(t, aclDeleteClient, domain.ErrClientNotFound)
	})
	t.Run("soft_delete_waits_for_a_create", func(t *testing.T) { aclChangeWaits(t, aclAccount(c1fixSoftDelete)) })
	t.Run("deactivate_waits_for_a_create", func(t *testing.T) { aclChangeWaits(t, aclAccount(c1fixDeactivate)) })
	t.Run("owner_change_waits_for_a_create", func(t *testing.T) { aclChangeWaits(t, aclReOwn) })
	t.Run("client_unbind_waits_for_a_create", func(t *testing.T) { aclChangeWaits(t, aclUnbindClient) })
	t.Run("org_delete_during_a_create", aclOrgDeleteDuringCreate)
	t.Run("control: live participants authorize", aclLiveParticipantsAuthorize)
}

// The owner-transfer guard (SA-OWNER-TRANSFER-LIVE-1) reads "is there a live
// authorization" and then re-owns the account, also with no lock: a transfer
// that runs beside a create sees no authorization yet and re-owns the account
// under the one the create commits. Either the transfer is refused or the
// create is; never both succeed.
func TestAgentCommunicationOwnerTransferLock(t *testing.T) {
	t.Run("transfer_during_a_create", aclTransferDuringCreate)
}

// aclWorld is one organization with two org admins (owner and other), two live
// service accounts owned by owner, and one private_key_jwt client bound to each.
type aclWorld struct {
	orgID, owner, other uuid.UUID
	sa                  [2]uuid.UUID
	client              [2]uuid.UUID
	clientID            [2]string
}

func aclSeed(t *testing.T, pool *pgxpool.Pool) *aclWorld {
	t.Helper()
	ctx := context.Background()
	w := &aclWorld{orgID: uuid.New(), owner: uuid.New(), other: uuid.New()}
	if _, err := pool.Exec(ctx, `INSERT INTO organizations (id, name, domain, org_slug, active)
		VALUES ($1, 'ACL scratch', $2, $3, true)`, w.orgID, w.orgID.String()+".example.invalid", "acl-"+w.orgID.String()); err != nil {
		t.Fatal("seed scratch organization failed")
	}
	for _, u := range []uuid.UUID{w.owner, w.other} {
		if _, err := pool.Exec(ctx, `INSERT INTO users (id, email, password_hash, organization_id, role)
			VALUES ($1, $2, 'x', $3, 'org_admin')`, u, u.String()+"@acl.example.invalid", w.orgID); err != nil {
			t.Fatal("seed scratch user failed")
		}
	}
	for i := range w.sa {
		w.sa[i], w.client[i] = uuid.New(), uuid.New()
		w.clientID[i] = "acl-" + w.client[i].String()
		if _, err := pool.Exec(ctx, `INSERT INTO service_accounts (id, organization_id, name, description, owner_user_id)
			VALUES ($1, $2, $3, '', $4)`, w.sa[i], w.orgID, "ACL scratch "+w.sa[i].String(), w.owner); err != nil {
			t.Fatal("seed scratch service account failed")
		}
		if _, err := pool.Exec(ctx, `INSERT INTO oauth_clients (id, client_id, client_secret_hash, name, redirect_uris, scope,
			service_account_id, organization_id, token_endpoint_auth_method, jwks)
			VALUES ($1, $2, '', 'acl client', '{}', 'openid', $3, $4, 'private_key_jwt', '{"keys":[{"kty":"OKP"}]}')`,
			w.client[i], w.clientID[i], w.sa[i], w.orgID); err != nil {
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
	return w
}

func (w *aclWorld) input() service.CreateAgentCommunicationAuthorizationInput {
	roles := [2]domain.AgentCommunicationParticipantRole{domain.AgentCommunicationRoleInitiator, domain.AgentCommunicationRoleResponder}
	in := service.CreateAgentCommunicationAuthorizationInput{
		OrganizationID:      w.orgID,
		OwnerID:             w.owner,
		RelayAudience:       "https://relay.acl.example.invalid",
		ExpiresAt:           time.Now().Add(time.Hour),
		MaxMessages:         10,
		MaxMessageSizeBytes: 1024,
	}
	for i := range w.sa {
		in.Participants = append(in.Participants, service.AgentCommunicationParticipantInput{
			ServiceAccountID:   w.sa[i],
			ClientID:           w.clientID[i],
			Role:               roles[i],
			ProofKeyThumbprint: "acl-thumbprint-" + string(rune('a'+i)),
			Capabilities:       []string{"communication.discuss"},
		})
	}
	return in
}

// aclService checks participants on the pool and writes through db, as the
// runtime does (lookups and the repository share no transaction today).
func aclService(db postgres.DBTX, pool *pgxpool.Pool) *service.AgentCommunicationAuthorizationService {
	return service.NewAgentCommunicationAuthorizationService(nil,
		postgres.NewPgxAgentCommunicationAuthorizationRepository(db),
		postgres.NewPgxServiceAccountRepository(pool),
		postgres.NewPgxClientRepository(pool),
		service.AgentCommunicationAuthorizationServiceOptions{})
}

// aclLive counts authorizations of the organization that are not revoked.
func aclLive(t *testing.T, ctx context.Context, pool *pgxpool.Pool, orgID uuid.UUID) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM agent_communication_authorizations WHERE organization_id = $1 AND revoked_at IS NULL`, orgID).Scan(&n); err != nil {
		t.Fatal("final scratch authorization count failed")
	}
	return n
}

// aclChange changes the first participant (its account or its client).
type aclChange func(ctx context.Context, pool *pgxpool.Pool, w *aclWorld) error

func aclAccount(change c1fixChange) aclChange {
	return func(ctx context.Context, pool *pgxpool.Pool, w *aclWorld) error {
		return change(ctx, pool, w.sa[0], w.orgID)
	}
}

func aclReOwn(ctx context.Context, pool *pgxpool.Pool, w *aclWorld) error {
	return postgres.NewPgxServiceAccountRepository(pool).UpdateOwner(ctx, w.sa[0], w.orgID, w.other)
}

// aclUnbindClient is the client save that removes the binding (C1 MutateClient).
func aclUnbindClient(ctx context.Context, pool *pgxpool.Pool, w *aclWorld) error {
	_, _, err := postgres.NewPgxClientRepository(pool).MutateClient(ctx, w.client[0], nil, func(c *domain.Client) error {
		c.ServiceAccountID = nil
		return nil
	})
	return err
}

func aclDeleteClient(ctx context.Context, pool *pgxpool.Pool, w *aclWorld) error {
	org := w.orgID
	return postgres.NewPgxClientRepository(pool).Delete(ctx, w.client[0], &org)
}

// aclGateTx wraps the scratch transaction the repository writes through. In
// "check" mode it holds the create before the FIRST statement of its own
// transaction: after every participant check on the pool, before anything
// the create's transaction reads or writes. In "commit" mode it holds the
// create at the end of its transaction, every lock it took still held.
type aclGateTx struct {
	pgx.Tx
	gate   *c1fixAccountGate
	commit bool
	nested bool
}

func (tx *aclGateTx) Begin(ctx context.Context) (pgx.Tx, error) {
	inner, err := tx.Tx.Begin(ctx)
	if err != nil {
		return nil, err
	}
	return &aclGateTx{Tx: inner, gate: tx.gate, commit: tx.commit, nested: true}, nil
}

func (tx *aclGateTx) hold(ctx context.Context) {
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

func (tx *aclGateTx) statement(ctx context.Context) {
	if tx.nested && !tx.commit {
		tx.hold(ctx)
	}
}

func (tx *aclGateTx) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	tx.statement(ctx)
	return tx.Tx.Exec(ctx, sql, args...)
}

func (tx *aclGateTx) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	tx.statement(ctx)
	return tx.Tx.QueryRow(ctx, sql, args...)
}

func (tx *aclGateTx) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	tx.statement(ctx)
	return tx.Tx.Query(ctx, sql, args...)
}

func (tx *aclGateTx) Commit(ctx context.Context) error {
	if tx.nested && tx.commit {
		tx.hold(ctx)
	}
	return tx.Tx.Commit(ctx)
}

type aclResult struct {
	a   *domain.AgentCommunicationAuthorization
	err error
}

func aclStart(ctx context.Context, workers *sync.WaitGroup, svc *service.AgentCommunicationAuthorizationService, in service.CreateAgentCommunicationAuthorizationInput) chan aclResult {
	r := make(chan aclResult, 1)
	workers.Add(1)
	go func() {
		defer workers.Done()
		a, err := svc.Create(ctx, in)
		r <- aclResult{a: a, err: err}
	}()
	return r
}

func aclAwait(t *testing.T, ctx context.Context, r chan aclResult) aclResult {
	t.Helper()
	select {
	case v := <-r:
		return v
	case <-ctx.Done():
		t.Fatal("authorization create stalled; no behavioral verdict")
		return aclResult{}
	}
}

// A participant changes after the create checked it. The create refuses with
// the verdict a create that came a moment later gets, not a store failure, and
// no authorization is written. Before the fix the authorization was written.
func aclChangedAfterTheCheck(t *testing.T, change aclChange, want error) {
	pool := f2ScratchPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	w := aclSeed(t, pool)
	a := f2Begin(t, ctx, pool)
	gate := &c1fixAccountGate{entered: make(chan struct{}), release: make(chan struct{})}
	var workers sync.WaitGroup
	defer func() { cancel(); workers.Wait() }()
	ra := aclStart(ctx, &workers, aclService(&aclGateTx{Tx: a, gate: gate}, pool), w.input())
	f2Await(t, ctx, gate.entered)
	cctx, ccancel := context.WithTimeout(ctx, 3*time.Second)
	defer ccancel()
	if err := change(cctx, pool, w); err != nil {
		t.Fatal("the participant change failed while no create held it")
	}
	close(gate.release)
	r := aclAwait(t, ctx, ra)
	if err := a.Commit(ctx); err != nil && r.err == nil {
		t.Fatal("scratch A commit failed")
	}
	switch {
	case r.err == nil:
		t.Error("the create wrote an authorization for a participant that changed after the check")
	case domain.IsAuthStoreUnavailable(r.err):
		t.Error("the refusal must be the participant verdict, not a store failure")
	case !errors.Is(r.err, want):
		t.Error("the refusal is not the verdict a later create gets for this participant")
	}
	if n := aclLive(t, ctx, pool, w.orgID); n != 0 {
		t.Errorf("%d live authorization(s) for a changed participant; want 0", n)
	}
}

// While a create holds its participants, a change to one waits until the
// create commits, then lands. Before the fix the change did not wait.
func aclChangeWaits(t *testing.T, change aclChange) {
	pool := f2ScratchPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	w := aclSeed(t, pool)
	a := f2Begin(t, ctx, pool)
	gate := &c1fixAccountGate{entered: make(chan struct{}), release: make(chan struct{})}
	var workers sync.WaitGroup
	defer func() { cancel(); workers.Wait() }()
	ra := aclStart(ctx, &workers, aclService(&aclGateTx{Tx: a, gate: gate, commit: true}, pool), w.input())
	f2Await(t, ctx, gate.entered)

	changed := make(chan error, 1)
	workers.Add(1)
	go func() {
		defer workers.Done()
		changed <- change(ctx, pool, w)
	}()
	waited := c1fixObserveWait(t, ctx, pool, a.Conn().PgConn().PID(), changed)
	close(gate.release)
	r := aclAwait(t, ctx, ra)
	if err := a.Commit(ctx); err != nil {
		t.Fatal("scratch A commit failed")
	}
	var cerr error
	select {
	case cerr = <-changed:
	case <-ctx.Done():
		t.Fatal("participant change stalled; no behavioral verdict")
	}
	if !waited {
		t.Error("the participant change did not wait for the create that names it")
	}
	if cerr != nil {
		t.Error("the participant change failed after the create committed")
	}
	if r.err != nil || r.a == nil {
		t.Error("the create of live participants did not complete")
	}
}

// An organization delete that comes while a create holds its participants
// completes without a deadlock (Postgres would abort one side after
// deadlock_timeout) and leaves no authorization a live client can use: the
// clients are tombstoned with the organization.
func aclOrgDeleteDuringCreate(t *testing.T) {
	pool := f2ScratchPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	w := aclSeed(t, pool)
	a := f2Begin(t, ctx, pool)
	gate := &c1fixAccountGate{entered: make(chan struct{}), release: make(chan struct{})}
	var workers sync.WaitGroup
	defer func() { cancel(); workers.Wait() }()
	ra := aclStart(ctx, &workers, aclService(&aclGateTx{Tx: a, gate: gate, commit: true}, pool), w.input())
	f2Await(t, ctx, gate.entered)

	deleted := make(chan error, 1)
	workers.Add(1)
	go func() {
		defer workers.Done()
		deleted <- postgres.NewPgxOrganizationRepository(pool).Delete(ctx, w.orgID)
	}()
	waited := c1fixObserveWait(t, ctx, pool, a.Conn().PgConn().PID(), deleted)
	close(gate.release)
	r := aclAwait(t, ctx, ra)
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
		t.Error("the organization delete failed beside an authorization create")
	}
	if r.err != nil || r.a == nil {
		t.Fatal("the create did not complete beside the organization delete")
	}
	var live int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM oauth_clients WHERE organization_id = $1 AND deleted_at IS NULL`, w.orgID).Scan(&live); err != nil {
		t.Fatal("final scratch client read failed")
	}
	if live != 0 {
		t.Error("the organization delete left a participant client live")
	}
}

// Control, green before and after: two live participants authorize.
func aclLiveParticipantsAuthorize(t *testing.T) {
	pool := f2ScratchPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	w := aclSeed(t, pool)
	a, err := aclService(pool, pool).Create(ctx, w.input())
	if err != nil || a == nil {
		t.Fatal("a create of two live participants did not authorize")
	}
	if n := aclLive(t, ctx, pool, w.orgID); n != 1 {
		t.Errorf("%d live authorization(s); want 1", n)
	}
}

// A transfer of a participant account to another org admin runs while a
// create holds its participants. Exactly one may win: the transfer refused
// because the authorization is live, or the create refused because the owner
// changed. Before any fix both succeeded.
func aclTransferDuringCreate(t *testing.T) {
	pool := f2ScratchPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	w := aclSeed(t, pool)
	a := f2Begin(t, ctx, pool)
	gate := &c1fixAccountGate{entered: make(chan struct{}), release: make(chan struct{})}
	var workers sync.WaitGroup
	defer func() { cancel(); workers.Wait() }()
	ra := aclStart(ctx, &workers, aclService(&aclGateTx{Tx: a, gate: gate, commit: true}, pool), w.input())
	f2Await(t, ctx, gate.entered)

	sas := service.NewServiceAccountService(nil, postgres.NewPgxServiceAccountRepository(pool)).
		WithOwnerAssignment(postgres.NewPgxUserRepository(pool), postgres.NewPgxAgentCommunicationAuthorizationRepository(pool))
	actor := &domain.Principal{UserID: w.owner, OrganizationID: w.orgID, Role: domain.RoleOrgAdmin}
	other := w.other
	transferred := make(chan error, 1)
	workers.Add(1)
	go func() {
		defer workers.Done()
		_, err := sas.AssignOwnerForActor(ctx, actor, w.sa[0], service.AssignServiceAccountOwnerInput{OwnerUserID: &other})
		transferred <- err
	}()
	_ = c1fixObserveWait(t, ctx, pool, a.Conn().PgConn().PID(), transferred)
	close(gate.release)
	r := aclAwait(t, ctx, ra)
	if r.err == nil {
		if err := a.Commit(ctx); err != nil {
			t.Fatal("scratch A commit failed")
		}
	}
	var terr error
	select {
	case terr = <-transferred:
	case <-ctx.Done():
		t.Fatal("owner transfer stalled; no behavioral verdict")
	}
	switch {
	case r.err == nil && terr == nil:
		t.Error("the owner transfer and the create both succeeded: a live authorization names an account its owner no longer owns")
	case r.err == nil && !errors.Is(terr, service.ErrSAOwnerTransferBlocked):
		t.Error("the transfer beside a committed create failed for a reason other than the live authorization")
	case r.err != nil && terr == nil && !errors.Is(r.err, domain.ErrAgentCommunicationOwnerMismatch):
		t.Error("the create beside a committed transfer failed for a reason other than the owner change")
	case r.err != nil && terr != nil:
		t.Error("the transfer and the create both failed")
	}
}
