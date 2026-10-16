//go:build integration

package postgres_test

// D3 (self-service consents), integration teeth for the two new pgx sinks:
//
//   - PgxOAuthConsentRepository.ListActiveByUser returns ONLY the user's rows
//     with revoked_at IS NULL (a revoked row and another user's row never
//     appear); RevokeAllForClient flips every audience row of (user, client)
//     and nothing else.
//   - PgxRefreshTokenRepository.RevokeAllBySubjectAndClientReturningAccessJTIs
//     revokes only (subject, client) live rows and returns their linked
//     access JTIs; the same subject's other client and another subject's row
//     for the same client stay live.
//
// FAIL-not-skip; needs the scratch PostgreSQL.

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/postgres"
)

func TestOAuthConsentListActiveByUser_AndRevokeAllForClient(t *testing.T) {
	pool := keyEncPool(t)
	t.Cleanup(pool.Close)
	ctx := context.Background()
	repo := postgres.NewPgxOAuthConsentRepository(pool)

	userA, userB := uuid.New(), uuid.New()
	clientX := "cx-" + uuid.NewString()
	clientY := "cy-" + uuid.NewString()
	clientZ := "cz-" + uuid.NewString()
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM oauth_consents WHERE client_id = ANY($1)`, []string{clientX, clientY, clientZ})
	})
	seed := func(u uuid.UUID, cid, aud string) {
		if _, err := repo.Upsert(ctx, &domain.OAuthConsent{
			ID: uuid.New(), UserID: u, ClientID: cid, Audience: aud, Scope: "openid", GrantedAt: time.Now(),
		}); err != nil {
			t.Fatalf("seed consent (%s,%s,%q): %v", u, cid, aud, err)
		}
	}
	seed(userA, clientX, "")
	seed(userA, clientX, "https://api.x/")
	seed(userA, clientY, "")
	seed(userA, clientZ, "")
	seed(userB, clientX, "")
	if err := repo.Revoke(ctx, userA, clientZ, "", time.Now()); err != nil {
		t.Fatalf("seed revoke: %v", err)
	}

	rows, err := repo.ListActiveByUser(ctx, userA)
	if err != nil {
		t.Fatalf("ListActiveByUser: %v", err)
	}
	got := map[string]int{}
	for _, r := range rows {
		if r.UserID != userA {
			t.Errorf("ListActiveByUser returned another user's row (%s)", r.UserID)
		}
		if r.RevokedAt != nil {
			t.Errorf("ListActiveByUser returned a revoked row (%s)", r.ClientID)
		}
		got[r.ClientID]++
	}
	if got[clientX] != 2 || got[clientY] != 1 || got[clientZ] != 0 || len(rows) != 3 {
		t.Fatalf("ListActiveByUser rows by client = %v (n=%d), want clientX:2 clientY:1 and no revoked clientZ", got, len(rows))
	}

	n, err := repo.RevokeAllForClient(ctx, userA, clientX, time.Now())
	if err != nil || n != 2 {
		t.Fatalf("RevokeAllForClient = (%d, %v), want (2, nil) — both audience rows", n, err)
	}
	for _, aud := range []string{"", "https://api.x/"} {
		if c, _ := repo.GetActive(ctx, userA, clientX, aud); c != nil {
			t.Errorf("userA/clientX audience %q still active after RevokeAllForClient", aud)
		}
	}
	if c, _ := repo.GetActive(ctx, userA, clientY, ""); c == nil {
		t.Errorf("RevokeAllForClient touched the same user's other client")
	}
	if c, _ := repo.GetActive(ctx, userB, clientX, ""); c == nil {
		t.Errorf("RevokeAllForClient touched another user's consent for the same client")
	}
}

// RULE: REFRESH-SUBJECT-CLIENT-REVOKE-1
func TestRefreshRevokeAllBySubjectAndClient_ScopedAndReturnsJTIs(t *testing.T) {
	pool := keyEncPool(t)
	t.Cleanup(pool.Close)
	ctx := context.Background()
	repo := postgres.NewPgxRefreshTokenRepository(pool)

	subA, subB := uuid.NewString(), uuid.NewString()
	clientX := "rx-" + uuid.NewString()
	clientY := "ry-" + uuid.NewString()
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM oauth_refresh_tokens WHERE client_id = ANY($1)`, []string{clientX, clientY})
	})
	insert := func(sub, client, jti string) uuid.UUID {
		id := uuid.New()
		if err := repo.Insert(ctx, &domain.RefreshToken{
			ID: id, ValidatorHash: "h-" + id.String(), ClientID: client, ClientKind: domain.RefreshTokenKindOAuthClient,
			Subject: sub, Scope: "openid offline_access", ExpiresAt: time.Now().Add(time.Hour), AccessJTI: jti,
		}); err != nil {
			t.Fatalf("seed refresh (%s,%s): %v", sub, client, err)
		}
		return id
	}
	target := insert(subA, clientX, "jti-a-x")
	otherClient := insert(subA, clientY, "jti-a-y")
	otherSubject := insert(subB, clientX, "jti-b-x")

	n, jtis, err := repo.RevokeAllBySubjectAndClientReturningAccessJTIs(ctx, subA, clientX, time.Now())
	if err != nil || n != 1 || len(jtis) != 1 || jtis[0].JTI != "jti-a-x" {
		t.Fatalf("RevokeAllBySubjectAndClientReturningAccessJTIs = (%d, %v, %v), want (1, [jti-a-x], nil)", n, jtis, err)
	}
	if row, _ := repo.GetByID(ctx, target); row == nil || row.RevokedAt == nil {
		t.Errorf("target row not revoked")
	}
	for name, id := range map[string]uuid.UUID{"same subject, other client": otherClient, "other subject, same client": otherSubject} {
		if row, _ := repo.GetByID(ctx, id); row == nil || row.RevokedAt != nil {
			t.Errorf("%s row was revoked", name)
		}
	}
	// Idempotent: a repeat revokes nothing and returns no JTIs.
	if n2, j2, err := repo.RevokeAllBySubjectAndClientReturningAccessJTIs(ctx, subA, clientX, time.Now()); err != nil || n2 != 0 || len(j2) != 0 {
		t.Errorf("repeat = (%d, %v, %v), want (0, [], nil)", n2, j2, err)
	}
	// Empty subject or client is a no-op, never a broad UPDATE.
	if n3, _, _ := repo.RevokeAllBySubjectAndClientReturningAccessJTIs(ctx, "", clientY, time.Now()); n3 != 0 {
		t.Errorf("empty subject revoked %d rows", n3)
	}
}
