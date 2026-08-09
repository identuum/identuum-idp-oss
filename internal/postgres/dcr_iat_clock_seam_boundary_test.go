//go:build integration

// Integration boundary test for the DCR initial-access-token expiry instant
// (FREEZE-THE-DATABASE-CLOCK, 2026-08-04).
//
// WHY THIS ONE NEEDED A DATABASE. DCRInitialAccessTokenService.clock is one of
// two seams in the fleet that the gate classifies STAMP while genuinely
// deciding a deadline: nothing in Go compares its value. The comparison is
//
//	AND expires_at > $2
//
// inside ConsumeByHash's UPDATE, and $2 is `s.clock().UTC()`. The seam is
// therefore real, its boundary is real, and neither is visible to an AST
// classifier — the only way to stand on the instant is to run the statement.
//
// THE OPERATOR IS `expires_at > $2`, STRICT, so a token whose expires_at is
// EXACTLY the supplied instant is already unusable. One MICROSECOND earlier it
// consumes. Microsecond, not nanosecond: timestamptz truncates below that, and
// a nanosecond step would put both sides of the boundary on the same stored
// value.
package postgres_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/postgres"
	"github.com/identuum/identuum-idp-oss/internal/repository"
)

// dcrSeamEpoch is far from any plausible wall clock, so a case that escapes the
// injected instant fails loudly rather than drifting into a date-dependent pass.
var dcrSeamEpoch = time.Date(2031, 3, 1, 12, 0, 0, 0, time.UTC)

// seedDCRToken inserts one IAT row whose expires_at is the LITERAL epoch, never
// a value derived from the instant under test.
func seedDCRToken(t *testing.T, ctx context.Context, db postgres.DBTX, label string) string {
	t.Helper()
	// The hash carries a fresh id. token_hash is UNIQUE and this table is not
	// truncated between runs, so a fixed value makes the test pass once and fail
	// on every re-run — the same trap the org-slug and claim-token boundary tests
	// hit. Found by re-running it.
	sum := sha256.Sum256([]byte("dcr-seam-" + label + "-" + uuid.NewString()))
	hash := hex.EncodeToString(sum[:])
	_, err := db.Exec(ctx, `
		INSERT INTO dcr_initial_access_tokens
			(id, token_hash, expires_at, max_uses, uses_count, created_at, updated_at)
		VALUES ($1, $2, $3, 0, 0, $4, $4)`,
		uuid.New(), hash, dcrSeamEpoch, dcrSeamEpoch.Add(-time.Hour))
	if err != nil {
		t.Fatalf("seed dcr_initial_access_tokens: %v", err)
	}
	return hash
}

// TestIntegration_DCRIATSeam_ExpiredExactlyAtExpiry pins the instant
// DCRInitialAccessTokenService.clock supplies to ConsumeByHash.
func TestIntegration_DCRIATSeam_ExpiredExactlyAtExpiry(t *testing.T) {
	dbURL := setupStateTestDBURL(t)
	ctx := context.Background()
	pool, err := postgres.NewPool(ctx, dbURL, nil)
	if err != nil {
		t.Fatalf("new pool (URL redacted): %v", err)
	}
	defer pool.Close()

	repo := postgres.NewPgxDynamicRegistrationTokenRepository(pool)

	// EXACTLY at expires_at the token is already unusable: `expires_at > $2` is
	// false when they are equal, so the UPDATE matches nothing and the
	// disambiguating SELECT reports the row inactive rather than missing.
	hashAt := seedDCRToken(t, ctx, pool, "at")
	if _, err := repo.ConsumeByHash(ctx, hashAt, dcrSeamEpoch); err == nil {
		t.Errorf("at expires_at exactly: ConsumeByHash succeeded; `expires_at > $2` is STRICT and must refuse")
	} else if errors.Is(err, repository.ErrDynamicRegistrationTokenNotFound) {
		t.Errorf("at expires_at exactly: err = %v — the row exists, so this must not read as NOT FOUND", err)
	}

	// One MICROSECOND earlier the same token consumes.
	hashBefore := seedDCRToken(t, ctx, pool, "before")
	got, err := repo.ConsumeByHash(ctx, hashBefore, dcrSeamEpoch.Add(-time.Microsecond))
	if err != nil {
		t.Fatalf("a microsecond before expires_at: err = %v, want nil", err)
	}
	if got == nil || got.UsesCount != 1 {
		t.Errorf("a microsecond before expires_at: uses_count did not advance (%+v)", got)
	}
}
