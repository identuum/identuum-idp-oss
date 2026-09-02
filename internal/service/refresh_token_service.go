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
	"go.uber.org/zap"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/lifecycle"
	"github.com/identuum/identuum-idp-oss/internal/metrics"
	"github.com/identuum/identuum-idp-oss/internal/repository"
	"github.com/identuum/identuum-idp-oss/internal/utils/uuidgen"
	"github.com/identuum/identuum-idp-oss/logger"
	"github.com/identuum/identuum-idp-oss/tools"
)

// RefreshUserOrgLookup is the narrow seam the OAuth refresh-rotation path
// uses to revalidate the subject at rotation time (R1-secondary). It
// reuses the existing GetUserOrganization query, which returns a non-nil
// org ONLY when the user is non-banned AND the org is active — so a nil/
// error result means the rotation must be refused. *repository.UserRepository
// satisfies it. Nil (unwired) ⇒ revalidation is skipped (the lifecycle
// cascade remains the primary enforcement).
type RefreshUserOrgLookup interface {
	GetUserOrganization(ctx context.Context, userID uuid.UUID) (*domain.Organization, error)
}

// RefreshTokenService is the OSS facade in front of the
// oauth_refresh_tokens table. It owns:
//
//   - Issue: creates a new selector/validator pair, persists the
//     row with the validator's SHA-256 hex digest, returns the
//     caller-visible token EXACTLY ONCE.
//   - Consume: parses a caller-supplied wire token, looks up the
//     row by selector, constant-time-compares the validator hash,
//     enforces client_id binding + expiry + non-revocation, then
//     atomically rotates: the old row is marked revoked +
//     replaced_by, the new row is persisted.
//   - RevokeByRawToken: parses + looks up + marks revoked. Returns
//     the row's AccessJTI (if any) so the revoke handler can
//     cascade an access-token jti revocation.
//   - DeleteExpired: prunes expired rows.
//
// The service NEVER stores or logs the raw wire token; the only
// derived value persisted is the validator's SHA-256 hex digest.
type RefreshTokenService struct {
	repo             repository.RefreshTokenRepository
	tokenRevocations *TokenRevocationService
	userOrgLookup    RefreshUserOrgLookup
	ttl              time.Duration
	now              func() time.Time
	generateToken    func() (*domain.SecureRefreshToken, error)
}

// RefreshTokenServiceOptions parameterises the service.
//
// TTL is the lifetime applied to newly issued refresh tokens.
// Zero falls back to the documented 30-day default.
type RefreshTokenServiceOptions struct {
	TTL time.Duration
}

const defaultRefreshTokenTTL = 30 * 24 * time.Hour

// NewRefreshTokenService constructs the service. repo is required;
// a nil repo panics so a misconfigured deployment cannot silently
// accept Issue calls that never persist.
func NewRefreshTokenService(report *lifecycle.StartupReport, repo repository.RefreshTokenRepository, opts RefreshTokenServiceOptions) *RefreshTokenService {
	if repo == nil {
		report.Fatal("NewRefreshTokenService", "service: NewRefreshTokenService requires a non-nil RefreshTokenRepository")
	}
	ttl := opts.TTL
	if ttl <= 0 {
		ttl = defaultRefreshTokenTTL
	}
	return &RefreshTokenService{
		repo:          repo,
		ttl:           ttl,
		now:           time.Now,
		generateToken: tools.GenerateSecureRefreshToken,
	}
}

// WithTokenRevocationService composes the existing access-token JTI
// revocation store into user-scoped refresh-token revocations. When
// wired, RevokeAllForUser revokes access JTIs linked from refresh-token
// rows that are newly revoked by that call. Nil disables the cascade.
func (s *RefreshTokenService) WithTokenRevocationService(r *TokenRevocationService) *RefreshTokenService {
	s.tokenRevocations = r
	return s
}

// WithUserOrgLookup wires the rotation-time subject revalidation seam
// (R1-secondary). When set, Consume refuses a rotation whose subject is
// banned/deleted or whose org is inactive. Nil disables the check.
func (s *RefreshTokenService) WithUserOrgLookup(l RefreshUserOrgLookup) *RefreshTokenService {
	s.userOrgLookup = l
	return s
}

// IssueRefreshTokenInput is the parameter object accepted by
// Issue. Caller MUST populate ClientID + ClientKind + Subject.
// Scope / Audience are echoed into the row for the consume path
// to replay.
type IssueRefreshTokenInput struct {
	ClientID   string
	ClientKind domain.RefreshTokenKind
	Subject    string
	Scope      string
	Audience   string
	AccessJTI  string
	Metadata   map[string]any
}

// IssuedRefreshToken carries the one-time visible wire token plus
// the persisted row metadata. The wire token format is
// `<selector>.<base64url(validator)>` per
// domain.SecureRefreshToken.Encode; callers MUST return it to the
// HTTP caller verbatim and MUST NOT log it.
type IssuedRefreshToken struct {
	Token     string
	ID        uuid.UUID
	ExpiresAt time.Time
	Subject   string
	Scope     string
	Audience  string
}

// Issue generates a new selector/validator pair, persists the row,
// and returns the one-time wire token. The raw token is consumed
// by the caller exactly once; it is NEVER recoverable from the
// service or repository after Issue returns.
func (s *RefreshTokenService) Issue(ctx context.Context, in IssueRefreshTokenInput) (*IssuedRefreshToken, error) {
	if strings.TrimSpace(in.ClientID) == "" {
		return nil, ErrRefreshTokenInvalidInput
	}
	if strings.TrimSpace(in.Subject) == "" {
		return nil, ErrRefreshTokenInvalidInput
	}
	if in.ClientKind == "" {
		in.ClientKind = domain.RefreshTokenKindOAuthClient
	}
	secure, err := s.generateToken()
	if err != nil {
		return nil, ErrRefreshTokenGenerationFailed
	}
	// Seed a NEW rotation family for this lineage (RFC 9700 §4.13.2).
	// Every subsequent Consume rotation inherits this id, so reuse of any
	// token in the chain revokes exactly this family.
	familyID, err := uuidgen.NewV7()
	if err != nil {
		return nil, ErrRefreshTokenGenerationFailed
	}
	now := s.now().UTC()
	exp := now.Add(s.ttl)
	row := &domain.RefreshToken{
		ID:            secure.Selector,
		ValidatorHash: hashValidator(secure.Validator),
		ClientID:      in.ClientID,
		ClientKind:    in.ClientKind,
		Subject:       in.Subject,
		Scope:         in.Scope,
		Audience:      in.Audience,
		ExpiresAt:     exp,
		AccessJTI:     in.AccessJTI,
		Metadata:      sanitizeRefreshMetadata(in.Metadata),
		FamilyID:      familyID.String(),
	}
	if err := s.repo.Insert(ctx, row); err != nil {
		return nil, err
	}
	return &IssuedRefreshToken{
		Token:     secure.Encode(),
		ID:        row.ID,
		ExpiresAt: exp,
		Subject:   row.Subject,
		Scope:     row.Scope,
		Audience:  row.Audience,
	}, nil
}

// ConsumeRefreshTokenInput drives Consume.
type ConsumeRefreshTokenInput struct {
	RawToken string
	ClientID string
}

// ConsumeResult carries the post-rotation projection. NewToken
// is the wire string of the rotated refresh token (one-time
// visible). ReplacedBy is the new row's selector. The Subject /
// Scope / Audience fields are copied from the consumed row so
// the caller can mint a new access token without re-validating
// the original policy.
type ConsumeResult struct {
	NewToken   string
	OldID      uuid.UUID
	NewID      uuid.UUID
	ExpiresAt  time.Time
	Subject    string
	Scope      string
	Audience   string
	ClientID   string
	ClientKind domain.RefreshTokenKind
}

// Consume validates the supplied wire token, atomically rotates
// the row (old revoked + replaced_by, new inserted), and returns
// the new token + the consumed row's policy projection.
//
// Returns:
//   - ErrRefreshTokenInvalidGrant for any verification failure
//     (parse error, unknown selector, validator mismatch, expired,
//     revoked, client_id mismatch). The wire layer maps this to
//     400 invalid_grant.
//   - The repo errors directly when persistence fails.
//
// The raw wire token is NEVER stored, logged, or returned in the
// error path.
func (s *RefreshTokenService) Consume(ctx context.Context, in ConsumeRefreshTokenInput) (*ConsumeResult, error) {
	if strings.TrimSpace(in.RawToken) == "" {
		return nil, ErrRefreshTokenInvalidGrant
	}
	secure, parseErr := domain.ParseSecureRefreshToken(in.RawToken)
	if parseErr != nil {
		return nil, ErrRefreshTokenInvalidGrant
	}
	row, err := s.repo.GetByID(ctx, secure.Selector)
	if err != nil {
		// AUTH-503: the repository answers (nil, nil) for an unknown token;
		// a non-nil error is the store class, never invalid_grant.
		return nil, domain.AuthStoreUnavailable("refresh-token", err)
	}
	if row == nil {
		return nil, ErrRefreshTokenInvalidGrant
	}
	if !constantTimeHashEqual(row.ValidatorHash, hashValidator(secure.Validator)) {
		return nil, ErrRefreshTokenInvalidGrant
	}
	now := s.now().UTC()
	if !row.Active(now) {
		// A presented token whose validator MATCHES but whose row was
		// already ROTATED (ReplacedBy set) is a replay of a superseded
		// refresh token — reuse, per OAuth 2.1 / RFC 9700 §4.13.2. Revoke
		// the compromised token's rotation FAMILY (its own lineage) and
		// emit the breach signal rather than returning a silent
		// invalid_grant. A row that is merely expired or directly revoked
		// (no successor) stays a generic invalid_grant; only a rotated-away
		// row signals an attack.
		//
		// Family-scoped (converges with CE-SEC-4): the automated reuse
		// signal is weak/ambiguous, so it cuts only the affected lineage,
		// not the subject's every session/device/client. Legacy
		// (pre-migration) rows carry no family_id — for those we FALL BACK
		// to the prior subject-wide revocation so they keep the old strong
		// behavior during the ~30-day transition (no regression window).
		// The DELIBERATE subject-wide paths (RevokeAllForUser) are
		// unaffected.
		if row.ReplacedBy != nil {
			// Revoke the compromised lineage's refresh rows AND — when the
			// access-token denylist is wired — cascade onto the family's
			// live access tokens so the attacker's just-minted JWT dies
			// immediately instead of surviving to its ~1h TTL.
			s.revokeReuseLineage(ctx, row, now)
			logger.ErrorContext(ctx, "SECURITY ALERT: OAuth refresh-token reuse detected — revoking token family lineage",
				zap.String("subject", row.Subject), zap.Stringer("token_id", row.ID))
			// Metric label rule: NEVER a user id / subject (or any
			// unbounded, attacker-drivable value) as a label — one series
			// per replayed subject is a cardinality DoS on a security
			// metric. The refresh-token row does not carry the
			// organization, so org_id is emitted as the bounded empty
			// value; per-subject attribution lives in the ERROR log above.
			metrics.AuthPolicyViolation.WithLabelValues("token_reuse", "").Inc()
			return nil, domain.ErrRefreshTokenReuse
		}
		return nil, ErrRefreshTokenInvalidGrant
	}
	if strings.TrimSpace(in.ClientID) != "" && in.ClientID != row.ClientID {
		// CE-SEC-4b (RFC 9700 §4.13.2 client binding): a DIFFERENT client
		// presenting another client's ACTIVE refresh token (validator
		// matched, row still active) is a leak/compromise signal — so, like
		// the reuse branch above, revoke the presented token's rotation
		// lineage (family-scoped when family_id is set, subject-wide fallback
		// for legacy NULL-family rows, with the access-jti cascade when
		// wired) and emit the breach signal. RevokeByFamily is active-scoped,
		// so it also revokes the presented ACTIVE row itself — intended.
		// All revoke/denylist errors are swallowed inside revokeReuseLineage
		// (fail-soft), so the wire response is UNCHANGED: the same generic
		// invalid_grant returned below, with no wrong-client-vs-reuse-vs-
		// unknown enumeration.
		s.revokeReuseLineage(ctx, row, now)
		logger.ErrorContext(ctx, "SECURITY ALERT: OAuth refresh-token wrong-client presentation — revoking token family lineage",
			zap.String("subject", row.Subject), zap.Stringer("token_id", row.ID))
		// Bounded label parallel to the reuse path's "token_reuse" — NEVER a
		// subject / unbounded value (cardinality-DoS guard on a security
		// metric); per-subject attribution lives in the ERROR log above.
		metrics.AuthPolicyViolation.WithLabelValues("token_wrong_client", "").Inc()
		return nil, ErrRefreshTokenInvalidGrant
	}
	// Rotation-time subject revalidation (R1-secondary). GetUserOrganization
	// returns a non-nil org ONLY when the user is non-banned/non-deleted AND
	// the org is active; a nil/error result refuses the rotation, mirroring
	// the ancestor validateRefreshTargetPgx. Skipped when the seam is unwired
	// (the lifecycle cascade remains the primary enforcement).
	if s.userOrgLookup != nil {
		if subjectID, perr := uuid.Parse(row.Subject); perr == nil {
			org, lookErr := s.userOrgLookup.GetUserOrganization(ctx, subjectID)
			if lookErr != nil && !errors.Is(lookErr, domain.ErrUserOrganizationNotFound) {
				// AUTH-503: the subject/org STORE erred — the rotation is refused
				// as 503, not presented as an invalid_grant verdict.
				return nil, domain.AuthStoreUnavailable("user-organization", lookErr)
			}
			if lookErr != nil || org == nil {
				return nil, ErrRefreshTokenInvalidGrant
			}
		}
	}
	// Issue a successor row before flipping the old one — that way
	// a transient error on either insert or rotate leaves the old
	// row consumable for a retry.
	newSecure, genErr := s.generateToken()
	if genErr != nil {
		return nil, ErrRefreshTokenGenerationFailed
	}
	newRow := &domain.RefreshToken{
		ID:            newSecure.Selector,
		ValidatorHash: hashValidator(newSecure.Validator),
		ClientID:      row.ClientID,
		ClientKind:    row.ClientKind,
		Subject:       row.Subject,
		Scope:         row.Scope,
		Audience:      row.Audience,
		ExpiresAt:     now.Add(s.ttl),
		Metadata:      row.Metadata,
		// Inherit the consumed parent's family so the whole rotation
		// lineage shares one family_id (RFC 9700 §4.13.2).
		FamilyID: row.FamilyID,
	}
	if err := s.repo.Insert(ctx, newRow); err != nil {
		return nil, err
	}
	if err := s.repo.MarkRotated(ctx, row.ID, newRow.ID, now); err != nil {
		// P3-1: losing the compare-and-set means a concurrent request already
		// exchanged this exact token. That is REUSE, not an internal error, so
		// it takes the same lineage-revocation path as a replayed token rather
		// than surfacing as a 500 — and the attacker's just-minted access token
		// dies with the family instead of surviving to its TTL.
		if errors.Is(err, repository.ErrRefreshAlreadyRotated) {
			s.revokeReuseLineage(ctx, row, now)
			logger.ErrorContext(ctx, "SECURITY ALERT: concurrent OAuth refresh-token rotation lost the compare-and-set — treating as reuse and revoking the family lineage",
				zap.String("subject", row.Subject), zap.Stringer("token_id", row.ID))
			metrics.AuthPolicyViolation.WithLabelValues("token_reuse", "").Inc()
			return nil, domain.ErrRefreshTokenReuse
		}
		return nil, err
	}
	return &ConsumeResult{
		NewToken:   newSecure.Encode(),
		OldID:      row.ID,
		NewID:      newRow.ID,
		ExpiresAt:  newRow.ExpiresAt,
		Subject:    row.Subject,
		Scope:      row.Scope,
		Audience:   row.Audience,
		ClientID:   row.ClientID,
		ClientKind: row.ClientKind,
	}, nil
}

// revokeReuseLineage revokes the compromised refresh lineage on reuse
// detection and, when the access-token denylist is wired, cascades the
// revocation onto the lineage's live access tokens.
//
// Scope mirrors the refresh-row revocation exactly (RFC 9700 §4.13.2 /
// commit a26168b): family-scoped when family_id is set, subject-wide
// fallback for legacy NULL-family rows — the DELIBERATE subject-wide paths
// (RevokeAllForUser) are unaffected. The access-jti cascade runs ONLY when a
// TokenRevocationService is wired AND the repo implements the access-jti
// extension (same gating as RevokeAllForUser); otherwise it degrades to the
// plain refresh-row revocation with no cascade, exactly as before.
//
// Fail-soft: every error (revoking rows, or denylisting jtis inside
// revokeLinkedAccessJTIs) is swallowed here so the reuse path always returns
// a single domain.ErrRefreshTokenReuse regardless of denylist-store health.
// RevokeLineageByID revokes the refresh token identified by id together with
// its whole rotation family and the access tokens linked to it — the same
// cascade a detected refresh-token replay triggers. It exists for the
// authorization-code reuse revoker (THE-CODE-REUSE-REVOKER): the code row
// records the refresh token's id, not its raw value, so RevokeByRawToken is
// not usable there. An unknown id revokes nothing and is not an error.
func (s *RefreshTokenService) RevokeLineageByID(ctx context.Context, id uuid.UUID, at time.Time) error {
	if id == uuid.Nil {
		return nil
	}
	row, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return err
	}
	if row == nil {
		return nil
	}
	s.revokeReuseLineage(ctx, row, at.UTC())
	return nil
}

func (s *RefreshTokenService) revokeReuseLineage(ctx context.Context, row *domain.RefreshToken, now time.Time) {
	if extRepo, hasExt := s.repo.(repository.RefreshTokenAccessJTIRevocationRepository); s.tokenRevocations != nil && hasExt {
		var jtis []repository.RevokedRefreshTokenAccessJTI
		if row.FamilyID != "" {
			_, jtis, _ = extRepo.RevokeByFamilyReturningAccessJTIs(ctx, row.FamilyID, now)
		} else {
			_, jtis, _ = extRepo.RevokeAllBySubjectReturningAccessJTIs(ctx, row.Subject, now)
		}
		_ = s.revokeLinkedAccessJTIs(ctx, jtis)
		return
	}
	if row.FamilyID != "" {
		_, _ = s.repo.RevokeByFamily(ctx, row.FamilyID, now)
	} else {
		_, _ = s.repo.RevokeAllBySubject(ctx, row.Subject, now)
	}
}

// SetAccessJTI records the jti of the access token most recently
// minted against the supplied refresh row. The token endpoint
// calls this after issuing a successor access token so the
// revoke handler can cascade.
func (s *RefreshTokenService) SetAccessJTI(ctx context.Context, id uuid.UUID, accessJTI string) error {
	if id == uuid.Nil {
		return nil
	}
	return s.repo.SetAccessJTI(ctx, id, accessJTI, s.now().UTC())
}

// RevokeByRawTokenResult is returned by RevokeByRawToken so the
// revoke handler can decide whether to cascade onto the access
// token jti.
type RevokeByRawTokenResult struct {
	Found     bool
	AccessJTI string
	ClientID  string
	// OwnerMismatch is set when the row was found and the validator
	// matched, but an authenticated OAuth client other than the row's
	// owning client presented it — so the row was deliberately NOT
	// revoked (RFC 7009 §2.1 client-binding). The caller surfaces a
	// silent idempotent 200; the token stays valid.
	OwnerMismatch bool
}

// RevokeByRawToken parses the wire token, looks up the row, marks
// it revoked, and returns whether a row was actually found plus
// the associated access_jti (if any). The wire-level contract for
// RFC 7009 §2.2 is always-200, so the boolean Found is for the
// handler's audit/cascade decision only — the wire response is
// the same either way.
//
// authenticatedClientID enforces RFC 7009 §2.1 client-binding (R4): when
// non-empty (an authenticated OAuth client is calling) and the row is
// bound to a DIFFERENT non-empty client, the row is NOT revoked and the
// result carries OwnerMismatch (the handler then returns a silent
// idempotent 200; the token stays valid). An empty authenticatedClientID
// is the site_admin authority path (no OAuth client in context) — the
// broad revoke is preserved. A clientless legacy row (empty ClientID) has
// no owner to protect and is revoked (parity with the ancestor's
// `session.ClientID != nil` guard). The single GetByID lookup is reused —
// no extra round-trip.
func (s *RefreshTokenService) RevokeByRawToken(ctx context.Context, rawToken, authenticatedClientID string) (*RevokeByRawTokenResult, error) {
	if strings.TrimSpace(rawToken) == "" {
		return &RevokeByRawTokenResult{}, nil
	}
	secure, parseErr := domain.ParseSecureRefreshToken(rawToken)
	if parseErr != nil {
		return &RevokeByRawTokenResult{}, nil
	}
	row, err := s.repo.GetByID(ctx, secure.Selector)
	if err != nil {
		return nil, err
	}
	if row == nil {
		return &RevokeByRawTokenResult{}, nil
	}
	if !constantTimeHashEqual(row.ValidatorHash, hashValidator(secure.Validator)) {
		// Selector existed but validator did not match. We do NOT
		// reveal that fact to the caller — wire response is the
		// same 200. We also do NOT revoke the row, because doing
		// so would let an attacker who guesses a selector revoke
		// legitimate tokens.
		return &RevokeByRawTokenResult{}, nil
	}
	// RFC 7009 §2.1 client-binding gate (R4). A cross-client caller does
	// NOT revoke another client's token; we recognize the row (Found) but
	// leave it valid and signal OwnerMismatch.
	if authenticatedClientID != "" && row.ClientID != "" && row.ClientID != authenticatedClientID {
		return &RevokeByRawTokenResult{
			Found:         true,
			ClientID:      row.ClientID,
			OwnerMismatch: true,
		}, nil
	}
	now := s.now().UTC()
	if err := s.repo.MarkRevoked(ctx, row.ID, now); err != nil {
		return nil, err
	}
	return &RevokeByRawTokenResult{
		Found:     true,
		AccessJTI: row.AccessJTI,
		ClientID:  row.ClientID,
	}, nil
}

// DeleteExpired prunes rows whose ExpiresAt has passed. The
// cleanup driver loops over this method on the configured
// interval.
func (s *RefreshTokenService) DeleteExpired(ctx context.Context) (int64, error) {
	return s.repo.DeleteExpiredBefore(ctx, s.now().UTC())
}

// RevokeAllForUser marks every active refresh token bound to the
// supplied user as revoked. The user UUID is rendered as a string
// and matched against the subject column — OSS-issued user-bound
// refresh tokens populate subject with userID.String() during
// Issue. Returns the count of rows actually flipped from active to
// revoked so caller flows (admin MFA reset, password reset
// completion) can pin the value in audit metadata. uuid.Nil is a
// safe no-op that returns (0, nil) without touching the DB. The
// call is idempotent: a second invocation after a successful one
// affects zero rows.
//
// The method does NOT expose token material to callers, logs,
// responses, or audit metadata. Linked access JTIs, when available,
// stay inside this service call long enough to persist revocation rows;
// raw validator bytes and validator_hash values never leave the
// repository layer.
func (s *RefreshTokenService) RevokeAllForUser(ctx context.Context, userID uuid.UUID) (int64, error) {
	if userID == uuid.Nil {
		return 0, nil
	}
	now := s.now().UTC()
	if s.tokenRevocations == nil {
		return s.repo.RevokeAllBySubject(ctx, userID.String(), now)
	}
	repo, ok := s.repo.(repository.RefreshTokenAccessJTIRevocationRepository)
	if !ok {
		return s.repo.RevokeAllBySubject(ctx, userID.String(), now)
	}
	n, accessJTIs, err := repo.RevokeAllBySubjectReturningAccessJTIs(ctx, userID.String(), now)
	if err != nil {
		return 0, err
	}
	return n, s.revokeLinkedAccessJTIs(ctx, accessJTIs)
}

func (s *RefreshTokenService) revokeLinkedAccessJTIs(ctx context.Context, accessJTIs []repository.RevokedRefreshTokenAccessJTI) error {
	seen := make(map[string]struct{}, len(accessJTIs))
	var firstErr error
	for _, linked := range accessJTIs {
		jti := strings.TrimSpace(linked.JTI)
		if jti == "" {
			continue
		}
		if _, ok := seen[jti]; ok {
			continue
		}
		seen[jti] = struct{}{}
		if err := s.tokenRevocations.RevokeJTI(ctx, jti, linked.ExpiresAt, "user_security_event", map[string]any{
			"reason": "user_security_event",
		}); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// UserRefreshTokenRevoker is the narrow seam consumed by recovery
// flows that need to invalidate every refresh token bound to a
// single user after a credential-significant event (admin MFA
// reset, password reset completion, future account-takeover
// recovery). Satisfied by *RefreshTokenService; tests can
// substitute RecorderRefreshTokenRevoker.
type UserRefreshTokenRevoker interface {
	RevokeAllForUser(ctx context.Context, userID uuid.UUID) (int64, error)
}

// Compile-time assertion that *RefreshTokenService satisfies the
// seam so adding a method to UserRefreshTokenRevoker breaks the
// build at the service definition site, not at every caller.
var _ UserRefreshTokenRevoker = (*RefreshTokenService)(nil)

// Sentinel errors.
var (
	// ErrRefreshTokenInvalidInput is returned when Issue is called
	// with a missing client_id or subject — those are not RFC
	// errors, they are programmer errors.
	ErrRefreshTokenInvalidInput = errors.New("service: refresh token issue requires client_id and subject")

	// ErrRefreshTokenGenerationFailed wraps a randomness-source
	// failure. The wire layer maps this to 500 server_error.
	ErrRefreshTokenGenerationFailed = errors.New("service: refresh token generation failed")

	// ErrRefreshTokenInvalidGrant is the single opaque sentinel
	// returned by Consume for any verification failure. The wire
	// layer maps this to RFC 6749 §5.2 invalid_grant.
	ErrRefreshTokenInvalidGrant = errors.New("service: invalid_grant")
)

// hashValidator returns the SHA-256 hex digest of the validator
// bytes. We deliberately use the same algorithm as the existing
// OSS audit and password-hash helpers so operators do not need to
// reason about multiple hash families in the same DB.
func hashValidator(validator []byte) string {
	sum := sha256.Sum256(validator)
	return hex.EncodeToString(sum[:])
}

// constantTimeHashEqual constant-time-compares two hex digests
// after a length check. Returns false on any size mismatch
// without leaking timing information.
func constantTimeHashEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// refreshTokenAllowedMetadataKeys mirrors the existing OSS
// token-revocation allowlist. Issue metadata flows through the
// same filter so a careless caller cannot plant a raw token,
// secret, or signing material in a JSONB column.
var refreshTokenAllowedMetadataKeys = map[string]struct{}{
	"client_id":   {},
	"client_kind": {},
	"reason":      {},
	"grant_type":  {},
}

func sanitizeRefreshMetadata(in map[string]any) map[string]any {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]any, len(in))
	for k, v := range in {
		if _, ok := refreshTokenAllowedMetadataKeys[k]; !ok {
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
