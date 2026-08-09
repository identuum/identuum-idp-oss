package service

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/lifecycle"
	"github.com/identuum/identuum-idp-oss/internal/repository"
)

// TokenRevocationService is the OSS-narrow facade in front of the
// TokenRevocationRepository. It owns the "what may safely land in
// the metadata blob" policy: the brief forbids raw tokens, raw
// client secrets, raw claims, and raw jti values from audit
// metadata. The service applies the same filter here so that even
// if a careless caller passes a wider map it lands in the DB with
// only the operator-safe keys.
//
// The service is deliberately tiny: it offers RevokeJTI (called
// from the revocation handler), IsRevoked (called from the
// introspection service), and DeleteExpired (called from a
// cleanup driver — wiring is operator's choice, the service just
// exposes the entry point).
type TokenRevocationService struct {
	repo repository.TokenRevocationRepository
	now  func() time.Time
}

// NewTokenRevocationService constructs the service. repo must be
// non-nil; a nil repo is a programmer error and panics so a
// misconfigured deployment cannot silently accept revocations
// that never persist.
func NewTokenRevocationService(report *lifecycle.StartupReport, repo repository.TokenRevocationRepository) *TokenRevocationService {
	if repo == nil {
		report.Fatal("NewTokenRevocationService", "service: NewTokenRevocationService requires a non-nil TokenRevocationRepository")
	}
	return &TokenRevocationService{repo: repo, now: time.Now}
}

// allowedMetadataKeys is the operator-safe key set the service
// will pass through to the repository. Everything else is dropped.
// The set is intentionally narrow: it must NEVER include keys
// that could carry token text, client secrets, signing material,
// or raw claim blobs.
var allowedMetadataKeys = map[string]struct{}{
	"client_id":   {},
	"client_kind": {},
	"reason":      {},
}

// sanitizeMetadata copies only the operator-safe keys from in.
// Returns nil when nothing survives the filter so the repository
// can use its DEFAULT '{}' column value.
func sanitizeMetadata(in map[string]any) map[string]any {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]any, len(in))
	for k, v := range in {
		if _, ok := allowedMetadataKeys[k]; !ok {
			continue
		}
		// Reject any value that itself looks like a banned secret —
		// e.g. a multi-line string. Cheap defense-in-depth.
		if s, isStr := v.(string); isStr {
			if strings.ContainsAny(s, "\n\r") {
				continue
			}
		}
		out[k] = v
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// RevokeJTI persists a revocation row for jti up to expiresAt.
// The revocation is idempotent at the repository level — a
// duplicate revoke is a no-op. Empty jti is a programmer error
// and returns ErrTokenRevocationInvalidJTI.
//
// If expiresAt is in the past, the call is a no-op (already
// expired tokens cannot become any more invalid by adding a row).
// Returns nil for that case so the wire layer's RFC 7009 §2.2
// "always 200" contract still holds.
func (s *TokenRevocationService) RevokeJTI(ctx context.Context, jti string, expiresAt time.Time, reason string, metadata map[string]any) error {
	if strings.TrimSpace(jti) == "" {
		return ErrTokenRevocationInvalidJTI
	}
	if expiresAt.IsZero() {
		return ErrTokenRevocationInvalidExpiry
	}
	if expiresAt.Before(s.now()) {
		// Already expired — repository write would just become
		// fodder for the next cleanup pass. Skip it.
		return nil
	}
	if reason == "" {
		reason = "oauth_token_revoked"
	}
	return s.repo.Insert(ctx, &domain.TokenRevocation{
		Jti:       jti,
		ExpiresAt: expiresAt,
		Reason:    reason,
		Metadata:  sanitizeMetadata(metadata),
	})
}

// IsRevoked reports whether a jti has been revoked. Empty jti
// returns (false, nil) — an introspection on a token that carries
// no jti claim cannot be "revoked" by this store.
//
// The function is intentionally fail-OPEN on repository errors:
// the introspection path's wire contract is `{"active":false}` on
// ANY failure, and a transient repo error must not flip a
// not-revoked token to "active:false" silently. Callers (the
// IntrospectionService) MUST treat a non-nil error as a "could
// not verify" signal — see how it routes errors below.
func (s *TokenRevocationService) IsRevoked(ctx context.Context, jti string) (bool, error) {
	if strings.TrimSpace(jti) == "" {
		return false, nil
	}
	return s.repo.Exists(ctx, jti)
}

// DeleteExpired prunes rows whose ExpiresAt has passed.
// Designed to be called from a cleanup driver; returns the row
// count for observability.
func (s *TokenRevocationService) DeleteExpired(ctx context.Context) (int64, error) {
	return s.repo.DeleteExpiredBefore(ctx, s.now())
}

// Sentinel errors.
var (
	// ErrTokenRevocationInvalidJTI is returned when an empty jti
	// reaches the service. The wire layer maps this to the same
	// 400 invalid_request envelope as any other malformed
	// request.
	ErrTokenRevocationInvalidJTI = errors.New("service: token revocation requires a non-empty jti")

	// ErrTokenRevocationInvalidExpiry is returned when expiresAt
	// is zero. The wire layer maps this to a 400 invalid_request
	// envelope.
	ErrTokenRevocationInvalidExpiry = errors.New("service: token revocation requires a non-zero expires_at")
)
