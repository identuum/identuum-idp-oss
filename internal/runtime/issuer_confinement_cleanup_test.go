package runtime

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/postgres"
)

// TestSeedActiveEdDSAKey_RemovesItsOwnRow pins G6: the fixture stores a
// PUBLIC-ONLY active EdDSA row. Left in a reused test database it makes a
// later suite's "is there an active key?" check pass while no row can sign,
// so token minting fails with "no compatible signing key". The fixture must
// delete exactly its own row when the test ends, and nothing else.
//
// TEETH: drop the helper's t.Cleanup and the owned row survives → this test fails.
func TestSeedActiveEdDSAKey_RemovesItsOwnRow(t *testing.T) {
	dbURL := testDBURL(t)
	migrateTestSchema(t, dbURL)

	ctx := context.Background()
	pool, err := postgres.NewPool(ctx, dbURL, nil)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	defer pool.Close()

	// An unrelated pre-existing row the fixture's cleanup must not touch.
	otherID := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO signing_keys (id, kid, algorithm, private_key, public_key, state)
		VALUES ($1, $2, 'EdDSA', '', 'unrelated', 'deprecated')`, otherID, "g6-unrelated-"+uuid.NewString()); err != nil {
		t.Fatalf("seed unrelated row: %v", err)
	}
	t.Cleanup(func() {
		c, err := postgres.NewPool(context.Background(), dbURL, nil)
		if err != nil {
			t.Errorf("cleanup pool: %v", err)
			return
		}
		defer c.Close()
		if _, err := c.Exec(context.Background(), `DELETE FROM signing_keys WHERE id = $1`, otherID); err != nil {
			t.Errorf("cleanup unrelated row: %v", err)
		}
	})

	kid := "g6-cleanup-" + uuid.NewString()
	t.Run("fixture", func(t *testing.T) {
		seedActiveEdDSAKey(t, dbURL, kid)
	})

	var owned int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM signing_keys WHERE kid = $1`, kid).Scan(&owned); err != nil {
		t.Fatalf("count owned: %v", err)
	}
	if owned != 0 {
		t.Errorf("fixture left %d public-only signing_keys row(s) behind after its test ended", owned)
	}
	var other int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM signing_keys WHERE id = $1 AND state = 'deprecated' AND public_key = 'unrelated'`, otherID).Scan(&other); err != nil {
		t.Fatalf("count unrelated: %v", err)
	}
	if other != 1 {
		t.Errorf("fixture cleanup touched an unrelated row: found %d, want 1", other)
	}
}
