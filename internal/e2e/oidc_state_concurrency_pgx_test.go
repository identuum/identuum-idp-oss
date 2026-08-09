//go:build integration

// Package e2e — P0-8 regression: the OIDC upstream-login state single-use
// gate under REAL concurrency against Postgres.
//
// Why this must be concurrent (and against the DB): the pre-fix consume
// did GetAndLock (SELECT … FOR UPDATE) on a bare POOL QueryRow — an
// implicit transaction that committed and RELEASED the row lock the
// instant the statement finished — then a SEPARATE Delete whose error the
// callback ignored. A SEQUENTIAL replay test PASSES against that broken
// code: the first callback deletes the row, so the second read finds
// nothing. The replay/CSRF defense only fails when two callbacks BOTH read
// the still-present row before either deletes it. Only firing N
// simultaneous consumes of the SAME state, against the real
// DELETE … RETURNING row lock, exercises the atomic single-use gate.
//
// Run:
//
//	go test -tags integration -v ./internal/e2e/...
//
// Safety: no state token, nonce, or DB URL is echoed; the seeded org
// (which cascade-owns the state row) is deleted on every exit path.
package e2e

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/postgres"
)

func TestE2E_OSS_OIDCState_ConcurrentSingleUse(t *testing.T) {
	dbURL := testDBURL(t)
	applyMigrations(t, dbURL)

	ctx := context.Background()
	pool, err := postgres.NewPool(ctx, dbURL, nil)
	if err != nil {
		t.Fatalf("open pool: %v", classifyOpenError(err))
	}
	defer pool.Close()

	repos := postgres.NewPgxRepositories(pool, e2eSigningKeyCipher())
	states := postgres.NewPgxOIDCStateRepository(pool)

	// oidc_states.organization_id REFERENCES organizations(id) ON DELETE
	// CASCADE — seed a live org; its deletion reaps the state row.
	orgID, _ := uuid.NewV7()
	slug := uuid.NewString()[:8]
	createdOrg, err := repos.Organization.Create(ctx, &domain.Organization{
		ID:        orgID,
		Name:      "e2e-oidcstate-" + slug,
		Domain:    "e2e-oidcstate-" + slug + ".example.invalid",
		OrgSlug:   "e2e-oidcstate-" + slug,
		Active:    true,
		MFAPolicy: "optional",
	})
	if err != nil {
		t.Fatalf("seed org: %v", err)
	}
	t.Cleanup(func() {
		_ = repos.Organization.Delete(context.Background(), createdOrg.ID)
	})

	// oidc_states.provider_id REFERENCES identity_providers(id) — seed a
	// minimal provider (id/org/type/name/slug; other columns default).
	// Direct SQL keeps the fixture small; org deletion cascades it away.
	providerID, _ := uuid.NewV7()
	if _, err := pool.Exec(ctx,
		`INSERT INTO identity_providers (id, organization_id, type, name, slug)
		 VALUES ($1, $2, 'oidc', 'e2e-provider', $3)`,
		providerID, createdOrg.ID, "e2e-prov-"+slug); err != nil {
		t.Fatalf("seed provider: %v", err)
	}
	stateKey := "e2e-state-" + uuid.NewString()
	if err := states.Create(ctx, &domain.OIDCState{
		State:                 stateKey,
		OrganizationID:        createdOrg.ID,
		ProviderID:            providerID,
		Nonce:                 "nonce-" + uuid.NewString(),
		PKCEVerifierEncrypted: "enc-verifier-placeholder-not-a-real-ciphertext",
		RedirectURI:           "https://idp.example/api/v1/auth/idp/callback",
		ReturnURL:             "/",
		CodeChallengeMethod:   "S256",
		ExpiresAt:             time.Now().Add(10 * time.Minute),
	}); err != nil {
		t.Fatalf("seed state: %v", err)
	}

	// Fire N consumes that all block on the same barrier so they race on
	// the still-present row instead of serializing by scheduling.
	const n = 16
	var (
		wg      sync.WaitGroup
		start   = make(chan struct{})
		mu      sync.Mutex
		winners int
		rejects int
		other   []error
	)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			st, cErr := states.ConsumeByState(ctx, stateKey)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case cErr != nil:
				other = append(other, cErr)
			case st != nil:
				winners++ // won the atomic DELETE … RETURNING
			default:
				rejects++ // nil row = already consumed = reject (no session)
			}
		}()
	}
	close(start) // release all goroutines simultaneously
	wg.Wait()

	if len(other) != 0 {
		t.Fatalf("consume returned unexpected DB errors (losers must be nil-row rejects): %v", other)
	}
	if winners != 1 {
		t.Fatalf("state replay detected: want exactly 1 winner, got winners=%d rejects=%d of n=%d",
			winners, rejects, n)
	}
	if rejects != n-1 {
		t.Fatalf("want %d rejected losers, got rejects=%d winners=%d", n-1, rejects, winners)
	}

	// Fully consumed — a later consume also returns (nil, nil): reject.
	if st, replayErr := states.ConsumeByState(ctx, stateKey); replayErr != nil || st != nil {
		t.Fatalf("replay after consume: want (nil,nil), got row=%v err=%v", st != nil, replayErr)
	}
}
