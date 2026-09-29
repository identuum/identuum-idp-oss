package runtime

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

type fakeRow struct{ present bool }

func (r fakeRow) Scan(dest ...any) error {
	*(dest[0].(*bool)) = r.present
	return nil
}

type fakeQuerier struct {
	present bool
	sql     string
	arg     any
}

func (q *fakeQuerier) QueryRow(_ context.Context, sql string, args ...any) pgx.Row {
	q.sql = sql
	if len(args) > 0 {
		q.arg = args[0]
	}
	return fakeRow{present: q.present}
}

// OSS-RC: the bare binary on an unmigrated database logged
// `relation "signing_keys" does not exist`, retried the instance lease as a
// "transient error" for a minute, blamed "another live instance" and exited.
// Start now checks the migrations table right after the pool opens and says
// what to do.
func TestRequireMigratedSchema(t *testing.T) {
	q := &fakeQuerier{present: false}
	err := requireMigratedSchema(context.Background(), q)
	if err == nil || !strings.Contains(err.Error(), "identuum-idp migrate") {
		t.Fatalf("unmigrated database: err = %v, want one naming `identuum-idp migrate`", err)
	}
	if q.arg != "goose_db_version" {
		t.Fatalf("checked %v, want the goose_db_version table", q.arg)
	}
	if err := requireMigratedSchema(context.Background(), &fakeQuerier{present: true}); err != nil {
		t.Fatalf("migrated database: err = %v, want nil", err)
	}
}
