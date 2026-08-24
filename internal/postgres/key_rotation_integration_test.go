//go:build integration

package postgres_test

// Integration teeth for signing-key rotation lifecycle (KEY-ROTATE-1).
//
// Asserted against the live SQL through the service Rotate, which delegates to
// PgxKeyRepository.RotateSigningKey: a successful rotation moves the old active
// key to 'rotating' (still validates, no longer the primary signer) and the
// new key to 'active' in ONE transaction; a rotation that cannot complete
// (unknown new key) rolls BOTH steps back, leaving the old key active rather
// than stranded in 'rotating'. FAIL-not-skip, same posture as the other teeth
// in this package.

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/crypto"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/postgres"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

func keyState(t *testing.T, ctx context.Context, db postgres.DBTX, kid string) string {
	t.Helper()
	var state string
	if err := db.QueryRow(ctx, `SELECT state FROM signing_keys WHERE kid = $1`, kid).Scan(&state); err != nil {
		t.Fatalf("read state: %v", err)
	}
	return state
}

// RULE: SIGNING-KEY-ROTATE-1
func TestSigningKeyRotation_AtomicPromotesNewRetiresOld(t *testing.T) {
	pool := keyEncPool(t)
	defer pool.Close()
	ctx := context.Background()
	cipher, _ := crypto.NewCryptoService(keyEncTestHexKey)
	repo := postgres.NewPgxKeyRepository(pool, cipher)
	svc := service.NewKeyService(repo)

	seed := func(state domain.KeyState) string {
		privPEM, pubPEM := genEdDSAPEM(t)
		kid := "rotate-" + uuid.NewString()
		if err := repo.CreateSigningKey(ctx, &domain.SigningKey{
			ID: uuid.New(), KID: kid, Algorithm: domain.KeyAlgorithmEdDSA,
			PublicKey: pubPEM, PrivateKey: privPEM, State: state,
		}); err != nil {
			t.Fatalf("CreateSigningKey(%s): %v", state, err)
		}
		return kid
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM signing_keys WHERE kid LIKE 'rotate-%'`)
	})

	// Happy path: old active -> rotating, new -> active, atomically.
	oldKID := seed(domain.KeyStateActive)
	newKID := seed(domain.KeyStateRotating)
	exp := time.Now().Add(24 * time.Hour)
	if err := svc.Rotate(ctx, oldKID, newKID, &exp); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if got := keyState(t, ctx, pool, oldKID); got != string(domain.KeyStateRotating) {
		t.Errorf("old key state = %q after rotation, want rotating (still validates, no longer signs)", got)
	}
	if got := keyState(t, ctx, pool, newKID); got != string(domain.KeyStateActive) {
		t.Errorf("new key state = %q after rotation, want active", got)
	}

	// Atomicity: rotating to an UNKNOWN new key must fail and roll back, so the
	// still-active old key is NOT stranded in 'rotating'.
	old2 := seed(domain.KeyStateActive)
	if err := svc.Rotate(ctx, old2, "no-such-new-kid-"+uuid.NewString(), &exp); err == nil {
		t.Fatalf("rotation to an unknown new key must fail")
	}
	if got := keyState(t, ctx, pool, old2); got != string(domain.KeyStateActive) {
		t.Errorf("after a failed rotation the old key state = %q, want active (transaction must roll back)", got)
	}
}
