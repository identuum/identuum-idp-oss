// Package service — AuthorizationCodeService is the OSS-narrow
// authorization-code lifecycle service. It owns Create / Consume
// / DeleteExpired primitives the future /authorize handler + the
// optional authorization_code grant on /oauth/token will compose.
//
// What the service WILL NOT do:
//
//   - Validate the authenticated client. That is the caller's
//     job (the future /oauth/token handler runs RequireOAuthClient
//     first; /authorize runs its own client-id-from-query lookup).
//   - Validate the redirect URI against the client's allowlist.
//     That's also the caller's job — the service simply
//     constant-time-compares the redirect URI supplied at
//     consume time against the one stored at create time.
//   - Mint an access token. The token-side grant handler composes
//     UserTokenService for that.
package service

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/crypto"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/lifecycle"
	"github.com/identuum/identuum-idp-oss/internal/repository"
	"github.com/identuum/identuum-idp-oss/internal/utils/uuidgen"
	"github.com/identuum/identuum-idp-oss/pkg/pkce"
)

// AuthorizationCodeService is the OSS façade in front of the
// oauth_authorization_codes table.
type AuthorizationCodeService struct {
	repo repository.OAuthAuthorizationCodeRepository
	ttl  time.Duration
	now  func() time.Time

	// reuseRevoker, when wired, is called on a REPLAYED authorization code
	// (P0-1b). Nil leaves the pre-P0-1b behaviour exactly: reject the replay,
	// touch nothing else.
	reuseRevoker AuthCodeReuseRevoker
}

// AuthCodeReuseRevoker revokes the credentials a replayed authorization code
// already minted.
//
// RFC 6819 §5.2.1.1 and the OAuth 2.0 Security BCP treat a second presentation
// of an authorization code as evidence that the code leaked: the attacker and
// the legitimate client both hold it, and rejecting the second exchange alone
// leaves whoever exchanged it FIRST in possession of live tokens. Rejecting is
// necessary and not sufficient.
//
// THE TRADEOFF IS REAL AND WAS RULED ON, not discovered here: a buggy client
// that double-submits one code will revoke its own user's tokens. The owner
// ruled 2026-08-04 that this is the correct failure direction, because the
// alternative is leaving an attacker's tokens valid.
type AuthCodeReuseRevoker interface {
	// RevokeForReusedCode revokes what the original exchange of `code` minted.
	// Implementations should be idempotent: a code can be replayed repeatedly.
	RevokeForReusedCode(ctx context.Context, code *domain.OAuthAuthorizationCode, at time.Time) error
}

// WithReuseRevoker wires the P0-1b revoke-on-reuse behaviour. Returns the
// service for chaining, matching the other With* seams here.
func (s *AuthorizationCodeService) WithReuseRevoker(r AuthCodeReuseRevoker) *AuthorizationCodeService {
	s.reuseRevoker = r
	return s
}

// revokeOnReuse fires the revoker for a detected replay. A revoker failure is
// logged by the caller's error path but must NOT change the wire response: the
// client gets invalid_grant either way, and telling a replaying attacker
// whether the revocation succeeded is free information.
func (s *AuthorizationCodeService) revokeOnReuse(ctx context.Context, code *domain.OAuthAuthorizationCode, at time.Time) {
	if s.reuseRevoker == nil || code == nil {
		return
	}
	_ = s.reuseRevoker.RevokeForReusedCode(ctx, code, at)
}

// AuthorizationCodeServiceOptions parameterises the service.
// TTL defaults to 10 minutes (matches the OAuth2 §4.1.2
// recommendation and the monolith's behavior).
type AuthorizationCodeServiceOptions struct {
	TTL time.Duration
}

const defaultAuthCodeTTL = 10 * time.Minute

// NewAuthorizationCodeService constructs the service.
func NewAuthorizationCodeService(report *lifecycle.StartupReport, repo repository.OAuthAuthorizationCodeRepository, opts AuthorizationCodeServiceOptions) *AuthorizationCodeService {
	if repo == nil {
		report.Fatal("NewAuthorizationCodeService", "service: NewAuthorizationCodeService requires a non-nil OAuthAuthorizationCodeRepository")
	}
	ttl := opts.TTL
	if ttl <= 0 {
		ttl = defaultAuthCodeTTL
	}
	return &AuthorizationCodeService{repo: repo, ttl: ttl, now: time.Now}
}

// CreateAuthorizationCodeInput drives Create.
type CreateAuthorizationCodeInput struct {
	ClientID            string
	UserID              uuid.UUID
	OrganizationID      *uuid.UUID
	SessionID           uuid.UUID
	RedirectURI         string
	Scope               string
	Audience            string
	CodeChallenge       string
	CodeChallengeMethod string
	Nonce               string
	Metadata            map[string]any
}

// CreatedAuthorizationCode carries the one-time visible code + the
// persisted row metadata. The Code field is shown to the caller
// EXACTLY ONCE.
type CreatedAuthorizationCode struct {
	Code      string
	ID        uuid.UUID
	ExpiresAt time.Time
}

// ConsumeAuthorizationCodeInput drives Consume.
type ConsumeAuthorizationCodeInput struct {
	Code         string
	ClientID     string
	RedirectURI  string
	CodeVerifier string
}

// ConsumedAuthorizationCode is the safe projection returned on
// successful Consume. Carries the policy fields the token-side
// grant handler needs to mint an access token.
type ConsumedAuthorizationCode struct {
	UserID         uuid.UUID
	OrganizationID *uuid.UUID
	SessionID      uuid.UUID
	Scope          string
	Audience       string
	Nonce          string
}

// Sentinel errors.
var (
	// ErrAuthCodeInvalidInput is the programmer-error sentinel
	// for missing required fields on Create.
	ErrAuthCodeInvalidInput = errors.New("service: authorization code requires client_id / user_id / session_id / redirect_uri / code_challenge")

	// ErrAuthCodeUnsupportedChallenge is returned when the
	// supplied code_challenge_method is anything other than the
	// supported set. The OSS slice supports S256 only; "plain"
	// is REJECTED.
	ErrAuthCodeUnsupportedChallenge = errors.New("service: authorization code requires PKCE S256")

	// ErrAuthCodeGenerationFailed wraps a randomness-source
	// failure during code generation.
	ErrAuthCodeGenerationFailed = errors.New("service: authorization code generation failed")

	// ErrAuthCodeInvalidGrant is the single opaque sentinel
	// returned by Consume for every verification failure
	// (unknown / expired / reused / client mismatch / redirect
	// mismatch / PKCE mismatch). The wire layer maps this to
	// RFC 6749 §5.2 `invalid_grant`.
	ErrAuthCodeInvalidGrant = errors.New("service: authorization code invalid_grant")
)

// Create persists a new authorization code row and returns the
// one-time wire code. The supplied input MUST carry ClientID,
// UserID, SessionID, RedirectURI, and CodeChallenge.
// CodeChallengeMethod MUST be "S256" — the slice rejects "plain"
// even though RFC 7636 §4.2 allows it, because allowing plain
// degrades the PKCE binding to a no-op against passive observers.
func (s *AuthorizationCodeService) Create(ctx context.Context, in CreateAuthorizationCodeInput) (*CreatedAuthorizationCode, error) {
	if strings.TrimSpace(in.ClientID) == "" ||
		in.UserID == uuid.Nil ||
		in.SessionID == uuid.Nil ||
		strings.TrimSpace(in.RedirectURI) == "" {
		return nil, ErrAuthCodeInvalidInput
	}
	// THE-PKCE-DECISION: a challenge is OPTIONAL at bind time — the
	// authorize service enforces the per-client posture (public clients
	// must send one) BEFORE this call. When one IS bound it must be S256,
	// and Consume verifies the verifier against it unconditionally:
	// optional to send, never to honor.
	if strings.TrimSpace(in.CodeChallenge) != "" {
		if in.CodeChallengeMethod != "S256" {
			return nil, ErrAuthCodeUnsupportedChallenge
		}
	} else if strings.TrimSpace(in.CodeChallengeMethod) != "" {
		return nil, ErrAuthCodeInvalidInput
	}
	rawCode, err := crypto.GenerateRandomString(32)
	if err != nil {
		return nil, ErrAuthCodeGenerationFailed
	}
	id, err := uuidgen.NewV7()
	if err != nil {
		return nil, ErrAuthCodeGenerationFailed
	}
	now := s.now().UTC()
	exp := now.Add(s.ttl)
	row := &domain.OAuthAuthorizationCode{
		ID:                  id,
		CodeHash:            hashAuthCode(rawCode),
		ClientID:            in.ClientID,
		UserID:              in.UserID,
		OrganizationID:      in.OrganizationID,
		SessionID:           in.SessionID,
		RedirectURI:         in.RedirectURI,
		Scope:               in.Scope,
		Audience:            in.Audience,
		CodeChallenge:       in.CodeChallenge,
		CodeChallengeMethod: in.CodeChallengeMethod,
		Nonce:               in.Nonce,
		ExpiresAt:           exp,
		Metadata:            sanitizeAuthCodeMetadata(in.Metadata),
	}
	if err := s.repo.Insert(ctx, row); err != nil {
		return nil, err
	}
	return &CreatedAuthorizationCode{
		Code:      rawCode,
		ID:        id,
		ExpiresAt: exp,
	}, nil
}

// Consume validates the supplied wire code, the client + redirect
// URI binding, and the PKCE code_verifier, then marks the row
// consumed. Returns the safe policy projection on success.
//
// Failure semantics:
//   - Empty code / clientID / redirectURI → invalid_grant.
//   - Unknown / expired / already-consumed code → invalid_grant.
//   - ClientID mismatch → invalid_grant.
//   - RedirectURI mismatch (constant-time) → invalid_grant.
//   - PKCE mismatch, verifier missing on a bound challenge, or a
//     gratuitous verifier on a challenge-less code → invalid_grant.
//
// The code_verifier is NOT in the always-required set since
// THE-PKCE-DECISION: a code minted without a challenge (confidential
// client, per-client-optional PKCE) legitimately consumes without one.
// The challenge-conditional block below enforces both directions.
//
// The raw code is consumed exactly once. A second attempt with
// the same code returns invalid_grant.
func (s *AuthorizationCodeService) Consume(ctx context.Context, in ConsumeAuthorizationCodeInput) (*ConsumedAuthorizationCode, error) {
	if strings.TrimSpace(in.Code) == "" ||
		strings.TrimSpace(in.ClientID) == "" ||
		strings.TrimSpace(in.RedirectURI) == "" {
		return nil, ErrAuthCodeInvalidGrant
	}
	codeHash := hashAuthCode(in.Code)
	now := s.now().UTC()
	row, err := s.repo.GetActiveByCodeHash(ctx, codeHash, now)
	if err != nil {
		return nil, err
	}
	if row == nil {
		// P0-1b: "not active" covers THREE different things — never issued,
		// expired, and ALREADY CONSUMED — and only the third is evidence of
		// compromise. Ask the question the active lookup cannot answer.
		if prior, perr := s.repo.GetByCodeHashAnyState(ctx, codeHash); perr == nil &&
			prior != nil && prior.ConsumedAt != nil {
			s.revokeOnReuse(ctx, prior, now)
		}
		return nil, ErrAuthCodeInvalidGrant
	}
	if subtle.ConstantTimeCompare([]byte(row.ClientID), []byte(in.ClientID)) != 1 {
		return nil, ErrAuthCodeInvalidGrant
	}
	if subtle.ConstantTimeCompare([]byte(row.RedirectURI), []byte(in.RedirectURI)) != 1 {
		return nil, ErrAuthCodeInvalidGrant
	}
	// THE-PKCE-DECISION: never to HONOR — a bound challenge is ALWAYS
	// verified. A code bound without a challenge (confidential client that
	// chose not to send one) must not receive a verifier either: accepting
	// a gratuitous verifier would let a downgrade pass silently, so it is
	// invalid_grant (OAuth Security BCP posture, stricter than RFC 7636's
	// server-may-ignore).
	if row.CodeChallenge != "" {
		if !pkce.Verify(in.CodeVerifier, row.CodeChallenge) {
			return nil, ErrAuthCodeInvalidGrant
		}
	} else if strings.TrimSpace(in.CodeVerifier) != "" {
		return nil, ErrAuthCodeInvalidGrant
	}
	won, err := s.repo.MarkConsumed(ctx, row.ID, now)
	if err != nil {
		return nil, err
	}
	if !won {
		// Same evidence, different route: the row was active at read time and
		// consumed by someone between the read and the flip. That is a second
		// presentation of one code, which is what §5.2.1.1 is about, so it
		// revokes too.
		s.revokeOnReuse(ctx, row, now)
		// Lost the atomic single-use race, or a replay of an
		// already-consumed code. The winning caller flipped
		// consumed_at first; every other concurrent caller sees zero
		// rows affected. A code is single-use — reject with the same
		// invalid_grant the read-side reuse check returns.
		return nil, ErrAuthCodeInvalidGrant
	}
	return &ConsumedAuthorizationCode{
		UserID:         row.UserID,
		OrganizationID: row.OrganizationID,
		SessionID:      row.SessionID,
		Scope:          row.Scope,
		Audience:       row.Audience,
		Nonce:          row.Nonce,
	}, nil
}

// DeleteExpired prunes expired rows. The cleanup driver loops
// over this on the configured interval.
func (s *AuthorizationCodeService) DeleteExpired(ctx context.Context) (int64, error) {
	return s.repo.DeleteExpiredBefore(ctx, s.now().UTC())
}

// hashAuthCode returns the SHA-256 hex digest of the supplied
// wire code. Same hash family the OSS audit and refresh-token
// stores already use.
func hashAuthCode(code string) string {
	sum := sha256.Sum256([]byte(code))
	return hex.EncodeToString(sum[:])
}

// authCodeAllowedMetadataKeys mirrors the OSS audit-metadata
// allowlist pattern. Issue-time metadata is filtered to a small
// operator-safe set so a careless caller cannot land a raw
// token, password, or signing key in the JSONB column.
var authCodeAllowedMetadataKeys = map[string]struct{}{
	"client_id":  {},
	"user_id":    {},
	"session_id": {},
	"grant_type": {},
}

func sanitizeAuthCodeMetadata(in map[string]any) map[string]any {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]any, len(in))
	for k, v := range in {
		if _, ok := authCodeAllowedMetadataKeys[k]; !ok {
			continue
		}
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
