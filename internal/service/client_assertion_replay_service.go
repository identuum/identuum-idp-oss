package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/identuum/identuum-idp-oss/internal/lifecycle"
	"github.com/identuum/identuum-idp-oss/internal/repository"
)

// ClientAssertionReplayService is the OSS facade in front of the
// oauth_client_assertion_replays table. It implements RFC 7523 /
// OIDC Core §9 replay defence for private_key_jwt client
// assertions.
//
// Pipeline: ClientAssertionValidator calls Mark(ctx, clientID, jti,
// exp) AFTER signature + claims validation. The service hashes the
// jti, clamps the TTL to [TTLMin, TTLMax], and atomically inserts
// (client_id, jti_hash). A primary-key conflict means the same
// (client_id, jti_hash) pair was already seen — the service
// reports REPLAY by returning (false, nil). A repository error
// returns (false, err) so the caller can fail-CLOSED at the wire
// layer (RFC 6749 §5.2 invalid_client).
//
// The raw jti NEVER leaves this service or lands in the DB.
type ClientAssertionReplayService struct {
	repo   repository.ClientAssertionReplayRepository
	ttlMin time.Duration
	ttlMax time.Duration
	now    func() time.Time
}

// ClientAssertionReplayServiceOptions parameterises the service.
//
// TTLMin defaults to 1 minute. Lower bound prevents clock-skew
// races on very-short-lived assertions.
//
// TTLMax defaults to 5 minutes. Upper bound matches the validator's
// max-lifetime clamp on assertions — the replay window can never
// exceed what the assertion itself permits.
type ClientAssertionReplayServiceOptions struct {
	TTLMin time.Duration
	TTLMax time.Duration
}

const (
	defaultReplayTTLMin = 1 * time.Minute
	defaultReplayTTLMax = 5 * time.Minute
)

// NewClientAssertionReplayService constructs the service.
// repo is required; nil panics so a misconfigured deployment
// cannot silently degrade replay protection.
func NewClientAssertionReplayService(report *lifecycle.StartupReport, repo repository.ClientAssertionReplayRepository, opts ClientAssertionReplayServiceOptions) *ClientAssertionReplayService {
	if repo == nil {
		report.Fatal("NewClientAssertionReplayService", "service: NewClientAssertionReplayService requires a non-nil ClientAssertionReplayRepository")
	}
	ttlMin := opts.TTLMin
	if ttlMin <= 0 {
		ttlMin = defaultReplayTTLMin
	}
	ttlMax := opts.TTLMax
	if ttlMax <= 0 {
		ttlMax = defaultReplayTTLMax
	}
	if ttlMin > ttlMax {
		ttlMin = ttlMax
	}
	return &ClientAssertionReplayService{
		repo:   repo,
		ttlMin: ttlMin,
		ttlMax: ttlMax,
		now:    time.Now,
	}
}

// ErrReplayInvalidInput is the programmer-error sentinel
// returned when client_id or jti are empty.
var ErrReplayInvalidInput = errors.New("service: replay mark requires non-empty client_id and jti")

// Mark records (clientID, jti) in the replay store with the
// supplied assertion exp. Behavior:
//
//   - (true, nil)  : first use — the assertion is accepted, the
//     row was inserted, and a future identical (client_id, jti)
//     pair will REPLAY for as long as the stored exp_at remains
//     in the future.
//   - (false, nil) : REPLAY — the (client_id, jti_hash) pair was
//     already in the store within its TTL window. The validator
//     MUST treat this as invalid_client.
//   - (false, err) : repository error. The validator MUST treat
//     this as invalid_client too (fail-CLOSED).
//
// The raw jti is hashed via SHA-256 before storage. The TTL is
// derived from assertionExp minus now and clamped to [TTLMin,
// TTLMax]. Empty inputs return ErrReplayInvalidInput.
func (s *ClientAssertionReplayService) Mark(ctx context.Context, clientID, jti string, assertionExp time.Time) (bool, error) {
	clientID = strings.TrimSpace(clientID)
	jti = strings.TrimSpace(jti)
	if clientID == "" || jti == "" {
		return false, ErrReplayInvalidInput
	}
	now := s.now().UTC()
	rowExpiresAt := s.clampedExpiry(now, assertionExp)
	return s.repo.Insert(ctx, clientID, hashJTI(jti), rowExpiresAt)
}

// DeleteExpired prunes rows whose stored expires_at has passed.
// The cleanup driver loops over this on the configured interval.
func (s *ClientAssertionReplayService) DeleteExpired(ctx context.Context) (int64, error) {
	return s.repo.DeleteExpiredBefore(ctx, s.now().UTC())
}

// clampedExpiry bounds the stored row's expires_at to the range
// [now+TTLMin, now+TTLMax] regardless of what the assertion
// claimed. This prevents an assertion with an absurdly long exp
// from squatting on a (client_id, jti) pair for hours.
func (s *ClientAssertionReplayService) clampedExpiry(now, assertionExp time.Time) time.Time {
	want := assertionExp
	if want.IsZero() || want.Before(now.Add(s.ttlMin)) {
		want = now.Add(s.ttlMin)
	}
	if cap := now.Add(s.ttlMax); want.After(cap) {
		want = cap
	}
	return want
}

// hashJTI returns the SHA-256 hex digest of the raw jti. Same
// hash family the OSS token-revocation and refresh-token stores
// already use, so operators do not need to reason about
// multiple hash families on the same DB.
func hashJTI(jti string) string {
	sum := sha256.Sum256([]byte(jti))
	return hex.EncodeToString(sum[:])
}
