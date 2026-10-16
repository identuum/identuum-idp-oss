//go:build integration

package postgres_test

import (
	"context"
	"testing"
)

// G6R-F1: the rotation test must remove the key rows it seeded. Its cleanup
// once ran on a pool a deferred Close had already shut, so its active and
// rotating rows stayed behind in the reused test database.
func TestSigningKeyRotation_RemovesItsOwnRows(t *testing.T) {
	pool := keyEncPool(t)
	t.Cleanup(pool.Close)
	ctx := context.Background()
	count := func() int {
		t.Helper()
		var n int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM signing_keys WHERE kid LIKE 'rotate-%'`).Scan(&n); err != nil {
			t.Fatalf("count rotation rows: %v", err)
		}
		return n
	}
	before := count()
	t.Run("rotation", TestSigningKeyRotation_AtomicPromotesNewRetiresOld)
	if after := count(); after != before {
		t.Fatalf("rotation test left %d signing_keys row(s) behind", after-before)
	}
}
