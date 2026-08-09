package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// PoolOptions controls connection-pool sizing. Zero values are replaced
// with conservative defaults that match the monolith's pool tuning
// (MaxConns=25, MaxConnLifetime=30m, MaxConnIdleTime=5m). Override only
// when there's a measured reason to.
type PoolOptions struct {
	MaxConns        int32
	MaxConnLifetime time.Duration
	MaxConnIdleTime time.Duration
}

// NewPool opens a pgxpool against databaseURL, attaches DBTracer for
// query-latency metrics, applies the connection-pool sizing in opts (or
// safe defaults if opts is nil), and verifies connectivity with Ping.
// Error wrapping omits the URL so credentials never leak into logs.
func NewPool(ctx context.Context, databaseURL string, opts *PoolOptions) (*pgxpool.Pool, error) {
	if databaseURL == "" {
		return nil, errors.New("postgres: database URL is empty")
	}

	cfg, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("postgres: parse pool config failed: %w", err)
	}

	resolved := PoolOptions{
		MaxConns:        25,
		MaxConnLifetime: 30 * time.Minute,
		MaxConnIdleTime: 5 * time.Minute,
	}
	if opts != nil {
		if opts.MaxConns > 0 {
			resolved.MaxConns = opts.MaxConns
		}
		if opts.MaxConnLifetime > 0 {
			resolved.MaxConnLifetime = opts.MaxConnLifetime
		}
		if opts.MaxConnIdleTime > 0 {
			resolved.MaxConnIdleTime = opts.MaxConnIdleTime
		}
	}

	cfg.MaxConns = resolved.MaxConns
	cfg.MaxConnLifetime = resolved.MaxConnLifetime
	cfg.MaxConnIdleTime = resolved.MaxConnIdleTime
	cfg.ConnConfig.Tracer = &DBTracer{}

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("postgres: open pool failed: %w", err)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("postgres: ping failed: %w", err)
	}

	return pool, nil
}
