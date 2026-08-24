//go:build integration

package postgres_test

// Integration teeth for the OAuth-consent revoke sink (CONSENT-REVOKE-1).
//
// Asserted against the live SQL: Revoke flips revoked_at on ONLY the row
// matching (user_id, client_id, audience) — the same user's consent for a
// different client and another user's consent for the same client both stay
// live — and is idempotent (a repeat leaves the original revoked_at untouched).
// FAIL-not-skip.

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/postgres"
)

// RULE: CONSENT-REVOKE-1
func TestOAuthConsentRevoke_ScopedToUserClientAudience(t *testing.T) {
	pool := keyEncPool(t)
	defer pool.Close()
	ctx := context.Background()
	repo := postgres.NewPgxOAuthConsentRepository(pool)

	userA, userB := uuid.New(), uuid.New()
	clientX := "cx-" + uuid.NewString()
	clientY := "cy-" + uuid.NewString()
	aud := "aud-" + uuid.NewString()

	seed := func(u uuid.UUID, cid string) {
		if _, err := repo.Upsert(ctx, &domain.OAuthConsent{
			ID: uuid.New(), UserID: u, ClientID: cid, Audience: aud, Scope: "openid", GrantedAt: time.Now(),
		}); err != nil {
			t.Fatalf("seed consent (%s,%s): %v", u, cid, err)
		}
	}
	seed(userA, clientX) // target
	seed(userA, clientY) // same user, other client — must stay live
	seed(userB, clientX) // other user, same client — must stay live
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM oauth_consents WHERE client_id = ANY($1)`, []string{clientX, clientY})
	})

	readRevoked := func(u uuid.UUID, cid string) *time.Time {
		var at *time.Time
		if err := pool.QueryRow(ctx,
			`SELECT revoked_at FROM oauth_consents WHERE user_id=$1 AND client_id=$2 AND audience=$3`,
			u, cid, aud).Scan(&at); err != nil {
			t.Fatalf("read revoked_at (%s,%s): %v", u, cid, err)
		}
		return at
	}

	// Revoke (userA, clientX, aud) flips ONLY that row.
	if err := repo.Revoke(ctx, userA, clientX, aud, time.Now()); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	rax := readRevoked(userA, clientX)
	if rax == nil {
		t.Fatalf("Revoke did not set revoked_at on the targeted consent")
	}
	if readRevoked(userA, clientY) != nil {
		t.Errorf("Revoke must not touch the same user's consent for another client")
	}
	if readRevoked(userB, clientX) != nil {
		t.Errorf("Revoke must not touch another user's consent for the same client")
	}

	// Idempotent: a repeat revoke leaves the original revoked_at untouched.
	if err := repo.Revoke(ctx, userA, clientX, aud, time.Now().Add(time.Minute)); err != nil {
		t.Errorf("second Revoke: %v", err)
	}
	if rax2 := readRevoked(userA, clientX); rax2 == nil || !rax2.Equal(*rax) {
		t.Errorf("Revoke not idempotent: revoked_at moved %v -> %v", rax, rax2)
	}
}
