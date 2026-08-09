//go:build integration

// Package e2e — P0-1 regression: the authorization_code single-use gate
// under REAL concurrency against Postgres.
//
// Why this must be concurrent (and against the DB): the pre-fix
// Consume did read-then-mark, and the mark UPDATE discarded its command
// tag. A SEQUENTIAL double-consume test PASSES against that broken code
// — the second Consume's GetActiveByCodeHash already sees consumed_at
// set and returns invalid_grant before ever reaching the mark. The
// double-spend only manifests when two callers BOTH read the still-active
// row before either marks it. Only firing N simultaneous consumes of the
// same code + verifier, against the real UPDATE ... WHERE consumed_at IS
// NULL row lock, exercises the atomic gate.
//
// Run:
//
//	go test -tags integration -v ./internal/e2e/...
//
// Safety: no raw code, verifier, or DB URL is ever echoed; the seeded
// row is deleted on every exit path (no FK — random principal IDs).
package e2e

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/postgres"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

func TestE2E_OSS_AuthCodeConsume_ConcurrentSingleUse(t *testing.T) {
	dbURL := testDBURL(t)
	applyMigrations(t, dbURL)

	ctx := context.Background()
	pool, err := postgres.NewPool(ctx, dbURL, nil)
	if err != nil {
		t.Fatalf("open pool: %v", classifyOpenError(err))
	}
	defer pool.Close()

	repo := postgres.NewPgxOAuthAuthorizationCodeRepository(pool)
	svc := service.NewAuthorizationCodeService(nil, repo, service.AuthorizationCodeServiceOptions{TTL: time.Hour})

	const (
		clientID    = "cli-concurrency"
		redirectURI = "https://app.example.com/cb"
		verifier    = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	)
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	created, err := svc.Create(ctx, service.CreateAuthorizationCodeInput{
		ClientID:            clientID,
		UserID:              uuid.New(),
		SessionID:           uuid.New(),
		RedirectURI:         redirectURI,
		Scope:               "openid",
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
	})
	if err != nil {
		t.Fatalf("create code: %v", err)
	}
	t.Cleanup(func() {
		// No FK + random principal IDs → a direct delete by id is safe
		// and self-contained. Best-effort; a residual row is harmless.
		_, _ = pool.Exec(context.Background(),
			"DELETE FROM oauth_authorization_codes WHERE id = $1", created.ID)
	})

	// Fire N consumes that all block on the same barrier, so they race
	// on the still-active row instead of serializing by scheduling.
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
			out, cErr := svc.Consume(ctx, service.ConsumeAuthorizationCodeInput{
				Code:         created.Code,
				ClientID:     clientID,
				RedirectURI:  redirectURI,
				CodeVerifier: verifier,
			})
			mu.Lock()
			defer mu.Unlock()
			switch {
			case cErr == nil && out != nil:
				winners++
			case errors.Is(cErr, service.ErrAuthCodeInvalidGrant):
				rejects++
			default:
				other = append(other, cErr)
			}
		}()
	}
	close(start) // release all goroutines simultaneously
	wg.Wait()

	if len(other) != 0 {
		t.Fatalf("losers must reject with invalid_grant, got unexpected errors: %v", other)
	}
	if winners != 1 {
		t.Fatalf("double-spend detected: want exactly 1 winner, got winners=%d rejects=%d of n=%d",
			winners, rejects, n)
	}
	if rejects != n-1 {
		t.Fatalf("want %d rejected losers, got rejects=%d winners=%d", n-1, rejects, winners)
	}

	// The code is now fully spent — a later consume is also rejected.
	if _, replayErr := svc.Consume(ctx, service.ConsumeAuthorizationCodeInput{
		Code:         created.Code,
		ClientID:     clientID,
		RedirectURI:  redirectURI,
		CodeVerifier: verifier,
	}); !errors.Is(replayErr, service.ErrAuthCodeInvalidGrant) {
		t.Fatalf("replay after spend: want ErrAuthCodeInvalidGrant, got %v", replayErr)
	}
}
