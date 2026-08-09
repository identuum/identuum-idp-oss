package postgres

// rows_err_propagation_test.go — P2-15: repository list/scan loops must
// surface a mid-stream iteration error (rows.Err()) and a per-row Scan
// error, instead of silently returning a PARTIAL slice as if complete.
//
// A minimal fake pgx.Rows/DBTX yields N rows and then reports a
// post-iteration error via Err() (or a Scan error on a chosen row); the
// repository method under test must return that error and NOT a partial
// slice.

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// fakeRows implements pgx.Rows. Scan is a no-op (leaves dest zero-valued)
// so the tested scanX helpers succeed on the success rows; teeth come
// from finalErr (post-iteration) and scanErrAt (per-row Scan failure).
type fakeRows struct {
	total     int   // number of rows to yield
	idx       int   // rows consumed so far
	scanErrAt int   // 1-based row where Scan returns an error (0 = never)
	finalErr  error // returned by Err() after iteration ends
	closed    bool
}

func (f *fakeRows) Next() bool {
	if f.idx >= f.total {
		return false
	}
	f.idx++
	return true
}
func (f *fakeRows) Scan(_ ...any) error {
	if f.scanErrAt != 0 && f.idx == f.scanErrAt {
		return errors.New("fake scan error")
	}
	return nil
}
func (f *fakeRows) Err() error                                   { return f.finalErr }
func (f *fakeRows) Close()                                       { f.closed = true }
func (f *fakeRows) CommandTag() pgconn.CommandTag                { return pgconn.CommandTag{} }
func (f *fakeRows) FieldDescriptions() []pgconn.FieldDescription { return nil }
func (f *fakeRows) Values() ([]any, error)                       { return nil, nil }
func (f *fakeRows) RawValues() [][]byte                          { return nil }
func (f *fakeRows) Conn() *pgx.Conn                              { return nil }

// fakeDBTX implements DBTX; only Query is exercised by the list loops.
type fakeDBTX struct {
	rows     *fakeRows
	queryErr error
}

func (d *fakeDBTX) Query(_ context.Context, _ string, _ ...any) (pgx.Rows, error) {
	if d.queryErr != nil {
		return nil, d.queryErr
	}
	return d.rows, nil
}
func (d *fakeDBTX) Exec(_ context.Context, _ string, _ ...any) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, nil
}
func (d *fakeDBTX) QueryRow(_ context.Context, _ string, _ ...any) pgx.Row {
	panic("QueryRow not expected in these tests")
}
func (d *fakeDBTX) Begin(_ context.Context) (pgx.Tx, error) {
	panic("Begin not expected in these tests")
}

var _ DBTX = (*fakeDBTX)(nil)
var _ pgx.Rows = (*fakeRows)(nil)

// --- rows.Err() propagation across TWO representative methods ---

// TestScopeTemplateList_RowsErrPropagated: 3 rows then a mid-stream error
// via rows.Err() → List returns the error and a NIL slice (not the 3
// partial rows). TEETH: delete the rows.Err() check in
// PgxScopeTemplateRepository.List and this fails (nil error + 3 rows).
func TestScopeTemplateList_RowsErrPropagated(t *testing.T) {
	streamErr := errors.New("connection reset mid-stream")
	repo := NewPgxScopeTemplateRepository(&fakeDBTX{rows: &fakeRows{total: 3, finalErr: streamErr}})
	list, err := repo.List(context.Background(), uuid.New())
	if !errors.Is(err, streamErr) {
		t.Fatalf("err = %v, want the mid-stream rows.Err()", err)
	}
	if list != nil {
		t.Fatalf("PARTIAL result returned (%d rows) despite a mid-stream error", len(list))
	}
}

// TestIdentityProviderList_RowsErrPropagated: same property on a second
// representative method (ListByOrganization).
func TestIdentityProviderList_RowsErrPropagated(t *testing.T) {
	streamErr := errors.New("connection reset mid-stream")
	repo := NewPgxIdentityProviderRepository(&fakeDBTX{rows: &fakeRows{total: 4, finalErr: streamErr}})
	list, err := repo.ListByOrganization(context.Background(), uuid.New())
	if !errors.Is(err, streamErr) {
		t.Fatalf("err = %v, want the mid-stream rows.Err()", err)
	}
	if list != nil {
		t.Fatalf("PARTIAL result returned (%d rows) despite a mid-stream error", len(list))
	}
}

// TestScopeTemplateList_ScanErrPropagated: a row whose Scan fails → the
// method returns the error, not a shorter slice.
func TestScopeTemplateList_ScanErrPropagated(t *testing.T) {
	repo := NewPgxScopeTemplateRepository(&fakeDBTX{rows: &fakeRows{total: 3, scanErrAt: 2}})
	list, err := repo.List(context.Background(), uuid.New())
	if err == nil {
		t.Fatalf("expected a Scan error; got nil (silently dropped a row): list=%d", len(list))
	}
	if list != nil {
		t.Fatalf("partial slice returned on Scan error: %d rows", len(list))
	}
}

// TestScopeTemplateList_Success: all rows returned, no error (success path
// unchanged).
func TestScopeTemplateList_Success(t *testing.T) {
	repo := NewPgxScopeTemplateRepository(&fakeDBTX{rows: &fakeRows{total: 2}})
	list, err := repo.List(context.Background(), uuid.New())
	if err != nil {
		t.Fatalf("success path returned error: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("success path returned %d rows, want 2", len(list))
	}
}
