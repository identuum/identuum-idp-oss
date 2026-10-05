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
	//
	// oldest is the time of the oldest counted failure (zero when none): the
	// bound it trips lifts when that failure leaves the window (FUNC-M2).
	CountAccountFailuresSince(ctx context.Context, emailHash, ipHash, purpose string, since time.Time) (n int, oldest time.Time, err error)

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
	//
	// oldest is the time of the oldest counted failure (zero when none).
	CountDistinctAccountsFromIPSince(ctx context.Context, ipHash, purpose string, since time.Time) (n int, oldest time.Time, err error)

	// AccountFailuresAnyIPSince returns the failures for emailHash from any
	// ip_hash after the later of since and the account's last success for
	// purpose, and the time of the newest of them (zero when none). It
	// drives the account-wide slow-down (owner ruling, v0.9.5), which delays
	// and never locks: an attacker rotating addresses is slowed, and the
	// owner's success starts the count again.
	AccountFailuresAnyIPSince(ctx context.Context, emailHash, purpose string, since time.Time) (int, time.Time, error)

	// DeleteOlderThan prunes rows older than cutoff.
	DeleteOlderThan(ctx context.Context, cutoff time.Time) (int64, error)
}
