package service

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/identuum/identuum-idp-oss/internal/lifecycle"
	"github.com/identuum/identuum-idp-oss/internal/postgres"
)

// P3-14 PART A regression pin. DELETE /api/v1/clients/:id is a mounted,
// documented site-admin route whose handler calls
// ClientService.DeleteClient(ctx, id, nil) — nil meaning "any org". The pgx
// repository dereferenced orgID unconditionally, so EVERY call of the route
// panicked (surfaced as a gin.Recovery 500). The route had zero coverage —
// no handler test, no service test, no e2e — which is how a
// panics-on-every-call defect shipped. This file is the permanent floor:
// the exact repro shape, service -> real pgx repository -> stub DBTX, so
// the nil-deref line itself is executed, not a mock of it.

// execRecorderDBTX is the minimal DBTX: it records Exec calls and succeeds.
// Query/QueryRow/Begin are unreachable in these tests and fail loudly.
type execRecorderDBTX struct {
	execSQL  []string
	execArgs [][]any
}

func (s *execRecorderDBTX) Exec(_ context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	s.execSQL = append(s.execSQL, sql)
	s.execArgs = append(s.execArgs, args)
	return pgconn.NewCommandTag("DELETE 1"), nil
}

func (s *execRecorderDBTX) Query(context.Context, string, ...any) (pgx.Rows, error) {
	return nil, errors.New("unexpected Query in DeleteClient path")
}

func (s *execRecorderDBTX) QueryRow(context.Context, string, ...any) pgx.Row {
	panic("unexpected QueryRow in DeleteClient path")
}

func (s *execRecorderDBTX) Begin(context.Context) (pgx.Tx, error) {
	return nil, errors.New("unexpected Begin in DeleteClient path")
}

// TestClientService_DeleteClient_NilOrgIDDoesNotPanic is the repro: before
// a3e1e61's follow-up fix this call panicked with "invalid memory address
// or nil pointer dereference" at the `*orgID` dereference in
// PgxClientRepository.Delete. It must complete without panic and without
// error, and must issue the unscoped (site-admin, any-org) DELETE.
func TestClientService_DeleteClient_NilOrgIDDoesNotPanic(t *testing.T) {
	stub := &execRecorderDBTX{}
	svc := NewClientService(lifecycle.NewStartupReport(), postgres.NewPgxClientRepository(stub))

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("DeleteClient(ctx, id, nil) panicked: %v — the site-admin DELETE /clients/:id route 500s on every call (P3-14 PART A regression)", r)
		}
	}()
	if err := svc.DeleteClient(context.Background(), uuid.New(), nil); err != nil {
		t.Fatalf("DeleteClient(ctx, id, nil): %v", err)
	}
	if len(stub.execSQL) != 1 {
		t.Fatalf("Exec calls = %d, want 1", len(stub.execSQL))
	}
	if len(stub.execArgs[0]) != 1 {
		t.Fatalf("unscoped delete must bind only the id, got %d args", len(stub.execArgs[0]))
	}
}

// Control: the org-scoped path still scopes — two bind args, no panic.
func TestClientService_DeleteClient_OrgScopedStillScopes(t *testing.T) {
	stub := &execRecorderDBTX{}
	svc := NewClientService(lifecycle.NewStartupReport(), postgres.NewPgxClientRepository(stub))

	orgID := uuid.New()
	if err := svc.DeleteClient(context.Background(), uuid.New(), &orgID); err != nil {
		t.Fatalf("DeleteClient(ctx, id, &orgID): %v", err)
	}
	if len(stub.execSQL) != 1 || len(stub.execArgs[0]) != 2 {
		t.Fatalf("org-scoped delete must bind id+org, got %d call(s) / %d args", len(stub.execSQL), len(stub.execArgs[0]))
	}
}
