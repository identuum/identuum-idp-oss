//go:build integration

package postgres_test

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/identuum/identuum-idp-oss/internal/postgres"
)

// G7 R1: two setup repositories share one pool of two connections. The lock
// holder needs a second connection for its work while the other repository
// waits for the lock. Both must finish, one at a time, before the deadline.
func TestSetupCompletionLock_SmallSharedPoolMakesProgress(t *testing.T) {
	dbURL := setupStateTestDBURL(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cfg, err := pgxpool.ParseConfig(dbURL)
	if err != nil {
		t.Fatal("parse pool config failed (URL suppressed)")
	}
	cfg.MaxConns = 2
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal("open pool failed (URL suppressed)")
	}
	defer pool.Close()

	var holders, overlap atomic.Int32
	work := func(ctx context.Context) error {
		if holders.Add(1) > 1 {
			overlap.Store(1)
		}
		defer holders.Add(-1)
		_, err := pool.Exec(ctx, "SELECT 1")
		return err
	}

	entered := make(chan struct{})
	waiterStarted := make(chan struct{})
	first := make(chan error, 1)
	go func() {
		first <- postgres.NewPgxSetupStateRepository(pool).WithCompletionLock(ctx, func(ctx context.Context) error {
			close(entered)
			<-waiterStarted
			// Give the other repository time to reach the lock wait.
			time.Sleep(300 * time.Millisecond)
			return work(ctx)
		})
	}()
	<-entered
	second := make(chan error, 1)
	go func() {
		close(waiterStarted)
		second <- postgres.NewPgxSetupStateRepository(pool).WithCompletionLock(ctx, work)
	}()

	for _, done := range []chan error{first, second} {
		if err := <-done; err != nil {
			t.Fatalf("completion lock did not make progress: %v", err)
		}
	}
	if overlap.Load() != 0 {
		t.Fatal("two holders ran inside the completion lock at once")
	}
}
