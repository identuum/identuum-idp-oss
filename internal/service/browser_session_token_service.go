// Package service — BrowserSessionTokenService owns the
// browser-cookie-indirection layer. The browser cookie value is a
// 48-byte cryptographically-random opaque token; only its SHA-256
// hex digest lands in the browser_session_tokens table. Resolution
// maps a presented cookie back to a session row via the digest.
//
// The indirection is the difference between "cookie compromise =
// refresh-token compromise" (the prior shape) and "cookie
// compromise = browser session compromise" (this shape). The
// underlying user-session refresh token is now never exposed in a
// cookie at all.
package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/lifecycle"
	"github.com/identuum/identuum-idp-oss/internal/repository"
	"github.com/identuum/identuum-idp-oss/internal/utils/uuidgen"
)

// BrowserSessionTokenService is the cookie-token issuer + resolver.
type BrowserSessionTokenService struct {
	repo repository.BrowserSessionTokenRepository
	ttl  time.Duration
	now  func() time.Time
}

// BrowserSessionTokenServiceOptions parameterises the service.
// TTL defaults to 12 hours (matches the existing default user-
// session TTL).
type BrowserSessionTokenServiceOptions struct {
	TTL time.Duration
}

// NewBrowserSessionTokenService constructs the service. repo
// required.
func NewBrowserSessionTokenService(report *lifecycle.StartupReport, repo repository.BrowserSessionTokenRepository, opts BrowserSessionTokenServiceOptions) *BrowserSessionTokenService {
	if repo == nil {
		report.Fatal("NewBrowserSessionTokenService", "service: NewBrowserSessionTokenService requires a non-nil BrowserSessionTokenRepository")
	}
	ttl := opts.TTL
	if ttl <= 0 {
		ttl = 12 * time.Hour
	}
	return &BrowserSessionTokenService{repo: repo, ttl: ttl, now: time.Now}
}

// IssueInput drives Issue.
type IssueBrowserSessionTokenInput struct {
	SessionID      uuid.UUID
	UserID         uuid.UUID
	OrganizationID *uuid.UUID
	UserAgent      string
	IPAddress      string
	ExpiresAt      time.Time // optional; defaults to now + TTL.
}

// IssuedBrowserSessionToken is the one-time projection returned by
// Issue. Token is the caller-visible opaque cookie value — returned
// EXACTLY ONCE.
type IssuedBrowserSessionToken struct {
	ID        uuid.UUID
	Token     string
	ExpiresAt time.Time
}

// ResolvedBrowserSession is the safe projection returned by
// Resolve. It carries only the IDs the consuming handler needs —
// the user/session rows themselves are loaded by the existing
// cookie-session lookup path.
type ResolvedBrowserSession struct {
	SessionID uuid.UUID
	UserID    uuid.UUID
}

// Sentinel errors.
var (
	ErrBrowserSessionTokenInvalidInput = errors.New("service: browser session token invalid input")
	ErrBrowserSessionTokenGeneration   = errors.New("service: browser session token generation failed")
)

// Issue creates a fresh browser-session-token row and returns the
// caller-visible opaque cookie value EXACTLY ONCE.
func (s *BrowserSessionTokenService) Issue(ctx context.Context, in IssueBrowserSessionTokenInput) (*IssuedBrowserSessionToken, error) {
	if in.SessionID == uuid.Nil || in.UserID == uuid.Nil {
		return nil, ErrBrowserSessionTokenInvalidInput
	}
	rnd := make([]byte, 48)
	if _, err := rand.Read(rnd); err != nil {
		return nil, ErrBrowserSessionTokenGeneration
	}
	wire := base64.RawURLEncoding.EncodeToString(rnd)
	id, err := uuidgen.NewV7()
	if err != nil {
		return nil, ErrBrowserSessionTokenGeneration
	}
	now := s.now().UTC()
	exp := in.ExpiresAt
	if exp.IsZero() {
		exp = now.Add(s.ttl)
	}
	row := &domain.BrowserSessionToken{
		ID:             id,
		SessionID:      in.SessionID,
		UserID:         in.UserID,
		OrganizationID: in.OrganizationID,
		TokenHash:      hashBrowserSessionToken(wire),
		UserAgent:      in.UserAgent,
		IPAddress:      in.IPAddress,
		ExpiresAt:      exp,
	}
	if err := s.repo.Insert(ctx, row); err != nil {
		return nil, err
	}
	return &IssuedBrowserSessionToken{
		ID:        id,
		Token:     wire,
		ExpiresAt: exp,
	}, nil
}

// Resolve takes the cookie wire token, hashes it, looks the row
// up, and returns the safe projection.
//
// Returns (nil, nil) when the token is unknown / revoked / expired
// / malformed. A non-nil error is reserved for repository-layer
// failures.
func (s *BrowserSessionTokenService) Resolve(ctx context.Context, wireToken string) (*ResolvedBrowserSession, error) {
	wireToken = strings.TrimSpace(wireToken)
	if wireToken == "" {
		return nil, nil
	}
	row, err := s.repo.GetByTokenHash(ctx, hashBrowserSessionToken(wireToken), s.now().UTC())
	if err != nil {
		return nil, err
	}
	if row == nil {
		return nil, nil
	}
	return &ResolvedBrowserSession{
		SessionID: row.SessionID,
		UserID:    row.UserID,
	}, nil
}

// Revoke marks the row whose token_hash matches as revoked.
// Idempotent. Used by the logout path.
func (s *BrowserSessionTokenService) Revoke(ctx context.Context, wireToken string) error {
	wireToken = strings.TrimSpace(wireToken)
	if wireToken == "" {
		return nil
	}
	return s.repo.RevokeByTokenHash(ctx, hashBrowserSessionToken(wireToken), s.now().UTC())
}

// RevokeAllForSession revokes every browser-session-token bound to
// the supplied session ID. Used on session-wide revocation paths.
func (s *BrowserSessionTokenService) RevokeAllForSession(ctx context.Context, sessionID uuid.UUID) error {
	if sessionID == uuid.Nil {
		return nil
	}
	return s.repo.RevokeBySessionID(ctx, sessionID, s.now().UTC())
}

// DeleteExpired prunes rows older than now. The cleanup driver
// calls this on each tick.
func (s *BrowserSessionTokenService) DeleteExpired(ctx context.Context) (int64, error) {
	return s.repo.DeleteExpiredBefore(ctx, s.now().UTC())
}

func hashBrowserSessionToken(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
