package repository

import (
	"context"
	"time"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// LoginAttemptRepository persists login attempts and powers the
// rate-limit window query.
type LoginAttemptRepository interface {
	// Insert records a fresh attempt.
	Insert(ctx context.Context, a *domain.LoginAttempt) error

	// CountAccountFailuresSince returns the number of rows where
	// success=false AND purpose=purpose AND created_at >= since AND
	// email_hash = emailHash AND ip_hash = ipHash  (AND, not OR).
	//
	// P2-10: the counter is keyed on the (email AND ip) PAIR, not the
	// email alone. Keying on email alone (the prior OR keyspace) let 5
	// wrong-password tries against ANY known email from ANY IP lock that
	// account out — an unauthenticated account-DoS (V1). Requiring the
	// SAME (email, ip) pair means an attacker rotating IPs can never
	// accumulate a per-account lockout; the counter now bounds only a
	// single host hammering a single account.
	CountAccountFailuresSince(ctx context.Context, emailHash, ipHash, purpose string, since time.Time) (int, error)

	// CountDistinctAccountsFromIPSince returns COUNT(DISTINCT email_hash)
	// over rows where success=false AND purpose=purpose AND
	// created_at >= since AND ip_hash = ipHash.
	//
	// P2-10: this is the independent per-IP signal. The prior OR keyspace
	// counted RAW failures from an IP, so 5 failures behind one NAT/proxy
	// denied every LATER user on that shared IP (V2). Counting DISTINCT
	// accounts instead means benign co-tenants behind a NAT (each failing
	// their own login a few times) never trip it; only a credential-
	// stuffing run spraying MANY distinct accounts from one IP does.
	CountDistinctAccountsFromIPSince(ctx context.Context, ipHash, purpose string, since time.Time) (int, error)

	// DeleteOlderThan prunes rows older than cutoff.
	DeleteOlderThan(ctx context.Context, cutoff time.Time) (int64, error)
}
