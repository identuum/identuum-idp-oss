// claim_service.go — OSS port of the monolith organization claim
// flow.
//
// Source-of-truth reference for behaviour:
//   identuum-idp/internal/service/claim_service.go
//   identuum-idp/internal/handlers/handler_claim.go
//
// We do NOT import monolith code; the port reimplements the
// observable contract on top of OSS repository / audit / notifier
// seams.
//
// Wire contract (mirrors monolith for UI compatibility — see
// identuum-ui/src/app/claim/actions.ts):
//
//   GET  /api/v1/auth/claim/validate?token=<raw>
//       response: always 200
//           valid:   { valid: true, organization_name, target_email? }
//           invalid: { valid: false }
//
//   POST /api/v1/auth/claim
//       request:  { token, email?, name?, password }
//       response: always 200
//           success:                  { success: true }
//           bad token/expired:        { success: false }
//           password policy violation:{ success: false, message, attempts_remaining }
//           max attempts exhausted:   { success: false, message, attempts_exhausted: true }
//
// Anti-enumeration rules (matches monolith §7.9 oracle-hardening):
//
//   - Every failure mode returns 200 (no 4xx). The wire cannot be
//     used to distinguish "claim does not exist" from "claim exists
//     but is expired" from "claim was already consumed" from
//     "internal error".
//   - validate?token= with an empty / unknown / expired token returns
//     {valid: false}. Same shape regardless of failure mode.
//   - consume with an unknown / expired / already-consumed token
//     returns {success: false}. No leak of which clause hit.
//
// Token model:
//
//   - Generated via crypto.GenerateRandomString(32) → 64 hex chars.
//   - SHA-256(raw_token) is the PK on `organization_claims.token_hash`.
//   - TTL: 48 hours (matches the monolith — claim links travel via
//     email so the operator may not click them immediately).
//   - Single-use: ConsumeClaim deletes the row on success BEFORE the
//     new org_admin is created. A subsequent attempt finds no row
//     and is rejected via the opaque {success:false}.
//   - Max attempts: domain.ClaimMaxPasswordAttempts. After exhaustion
//     the row is deleted and subsequent consume attempts return
//     {attempts_exhausted: true, success: false}.
//
// Email binding:
//
//   - When the claim was issued with TargetEmail != "" and
//     EmailBound = true, consume requires the supplied email to
//     match (case-insensitive). Otherwise consume rejects with
//     {success: false} — same opaque shape.
//   - When EmailBound = false (out-of-band token), any well-formed
//     email is accepted at consume time and is used as the new
//     org_admin's email.

package service

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/crypto"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/repository"
	"github.com/identuum/identuum-idp-oss/internal/utils/uuidgen"
)

// DefaultClaimTTL is the wall-clock lifetime of a single
// organization-claim token. Matches the monolith.
const DefaultClaimTTL = 48 * time.Hour

// Claim sentinels. These NEVER surface on the wire — the handler
// collapses them onto the standard 200 {valid:false} / {success:false}
// envelope. The service layer surfaces them so tests can pin the
// failure paths.
var (
	ErrClaimInvalidRequest    = errors.New("claim: invalid request")
	ErrClaimWeakPassword      = errors.New("claim: weak password")
	ErrClaimMaxAttemptsBurned = errors.New("claim: max attempts burned")
)

// claimOrganizationLookup is the narrow seam this service consumes
// from the organization repository.
type claimOrganizationLookup interface {
	GetByID(ctx context.Context, id uuid.UUID) (*domain.Organization, error)
}

// claimOrganizationAdminLookup is the extended seam for pre-active
// orgs.
type claimOrganizationAdminLookup interface {
	GetByIDAdmin(ctx context.Context, id uuid.UUID) (*domain.Organization, error)
}

// claimUserCreator is the narrow seam used to mint the new
// org_admin row at consume time. PgxUserRepository satisfies it via
// Create (auto-hashes plaintext passwords). Kept separate from
// claimUserExistsCheck so test fakes can return non-nil errors on
// Create without also stubbing FindUsersByEmail.
type claimUserCreator interface {
	Create(ctx context.Context, user *domain.User) (*domain.User, error)
}

// claimUserExistsCheck is the narrow seam used to enforce the
// "no existing org_admin" invariant before consume mints a new
// org_admin row. PgxUserRepository satisfies it via FindUsersByEmail.
type claimUserExistsCheck interface {
	FindUsersByEmail(ctx context.Context, email string) ([]*domain.User, error)
}

// repos.User in production wiring is a single instance that
// satisfies both seams (Create + FindUsersByEmail).

// ClaimService orchestrates generation + validation + consumption.
type ClaimService struct {
	claims  repository.ClaimRepository
	orgs    claimOrganizationLookup
	orgs2   claimOrganizationAdminLookup
	users   claimUserCreator
	exists  claimUserExistsCheck
	audit   audit.Service
	logger  *zap.Logger
	now     func() time.Time
	tokenSz int
	ttl     time.Duration

	minPasswordLength int
}

// ClaimServiceConfig holds the dependencies AND optional knobs the
// service needs. As of `agent-claude-20260624-idp-oss-constructor-arity-refactor`,
// the previously-positional dependency args (Claims, Orgs, OrgsAdmin,
// Users, Exists, Audit) live here too — `NewClaimService` now takes a
// single argument of this type instead of 7 positional args.
//
// Required: Claims, Orgs, Users, Exists. Optional: OrgsAdmin, Audit
// (default audit.NoopService), Logger (zap.NewNop), Now (time.Now),
// TTL (DefaultClaimTTL), MinPasswordLength (12).
type ClaimServiceConfig struct {
	Claims    repository.ClaimRepository
	Orgs      claimOrganizationLookup
	OrgsAdmin claimOrganizationAdminLookup
	Users     claimUserCreator
	Exists    claimUserExistsCheck
	Audit     audit.Service

	TTL               time.Duration
	MinPasswordLength int
	Logger            *zap.Logger
	Now               func() time.Time
}

// NewClaimService constructs the service. cfg.Claims, cfg.Orgs,
// cfg.Users, cfg.Exists are REQUIRED. cfg.OrgsAdmin (admin lookup)
// and cfg.Audit are optional.
//
// Single-argument shape replaces the prior 7-positional-arg
// constructor — refactored 2026-06-24 to satisfy the ≤5-arg target
// from `findings/identuum-idp-oss-findings-claude.md`.
func NewClaimService(cfg ClaimServiceConfig) *ClaimService {
	auditSvc := cfg.Audit
	if auditSvc == nil {
		auditSvc = audit.NoopService{}
	}
	logger := cfg.Logger
	if logger == nil {
		logger = zap.NewNop()
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	ttl := cfg.TTL
	if ttl <= 0 {
		ttl = DefaultClaimTTL
	}
	minLen := cfg.MinPasswordLength
	if minLen <= 0 {
		minLen = 12 // claim consume creates a new org_admin — stricter floor
	}
	return &ClaimService{
		claims:            cfg.Claims,
		orgs:              cfg.Orgs,
		orgs2:             cfg.OrgsAdmin,
		users:             cfg.Users,
		exists:            cfg.Exists,
		audit:             auditSvc,
		logger:            logger,
		now:               now,
		tokenSz:           32,
		ttl:               ttl,
		minPasswordLength: minLen,
	}
}

// GenerateClaimToken mints a new claim token for the supplied org.
//
// recipientEmail (optional) — when non-empty the claim is email-bound:
// consume must present a matching email and the URL is delivered via
// email. Empty is the out-of-band path: the operator copies the URL
// manually and the claimant supplies any well-formed email at
// consume time.
//
// The raw token is returned ONCE to the caller; the SHA-256 hash is
// persisted on `organization_claims.token_hash`. The raw token is
// NEVER stored, logged, or audited.
func (s *ClaimService) GenerateClaimToken(ctx context.Context, orgID uuid.UUID, recipientEmail string) (string, time.Time, error) {
	if orgID == uuid.Nil {
		return "", time.Time{}, ErrClaimInvalidRequest
	}
	// Existence + state guards. Pre-active orgs are intentionally
	// allowed — that is the entire point of the claim flow.
	if _, err := s.loadOrganization(ctx, orgID); err != nil {
		return "", time.Time{}, err
	}
	raw, hash, err := s.generateToken()
	if err != nil {
		return "", time.Time{}, err
	}
	now := s.now().UTC()
	id, err := uuidgen.NewV7()
	if err != nil {
		return "", time.Time{}, err
	}
	claim := &domain.OrganizationClaim{
		ID:             id,
		OrganizationID: orgID,
		TokenHash:      hash,
		ExpiresAt:      now.Add(s.ttl),
		CreatedAt:      now,
		TargetEmail:    strings.ToLower(strings.TrimSpace(recipientEmail)),
		EmailBound:     recipientEmail != "",
	}
	if err := s.claims.Create(ctx, claim); err != nil {
		return "", time.Time{}, err
	}
	_ = s.audit.Record(ctx, audit.Event{
		Action:         domain.AuditClaimGenerated,
		Outcome:        "success",
		SubjectID:      orgID,
		SubjectType:    "organization",
		OrganizationID: orgID,
		Metadata: map[string]any{
			"target_email": claim.TargetEmail,
			"email_bound":  claim.EmailBound,
			"claim_id":     id.String(),
		},
	})
	return raw, claim.ExpiresAt, nil
}

// ValidateClaimResult is the GET /claim/validate response payload.
type ValidateClaimResult struct {
	Valid            bool
	OrganizationName string
	TargetEmail      string
}

// ValidateClaim implements the GET pre-flight. It is the
// oracle-hardened entry point: every failure mode returns
// {Valid:false} so the wire cannot distinguish bad-token /
// unknown-token / expired-token / consumed-token / internal-error.
func (s *ClaimService) ValidateClaim(ctx context.Context, rawToken string) (*ValidateClaimResult, error) {
	if rawToken == "" {
		return &ValidateClaimResult{Valid: false}, nil
	}
	hash := hashToken(rawToken)
	claim, err := s.claims.GetByTokenHash(ctx, hash)
	if err != nil || claim == nil {
		return &ValidateClaimResult{Valid: false}, nil
	}
	if claim.IsExpired(s.now()) {
		return &ValidateClaimResult{Valid: false}, nil
	}
	if claim.IsMaxAttemptsReached() {
		return &ValidateClaimResult{Valid: false}, nil
	}
	org, err := s.loadOrganization(ctx, claim.OrganizationID)
	if err != nil || org == nil {
		return &ValidateClaimResult{Valid: false}, nil
	}
	out := &ValidateClaimResult{
		Valid:            true,
		OrganizationName: org.Name,
	}
	if claim.EmailBound {
		out.TargetEmail = claim.TargetEmail
	}
	return out, nil
}

// ConsumeClaimInput captures the POST values.
type ConsumeClaimInput struct {
	Token     string
	Email     string
	Name      string
	Password  string
	IPAddress string
	UserAgent string
}

// ConsumeClaimResult is the consume outcome the handler surfaces.
type ConsumeClaimResult struct {
	Success           bool
	AttemptsExhausted bool
	AttemptsRemaining int
	Reason            string // diagnostic only — handler hides
}

// ConsumeClaim consumes the supplied token: validates email binding,
// mints the org_admin row, deletes the claim row, and emits an
// audit event. Failure modes are oracle-hardened — the handler
// inspects ConsumeClaimResult and never echoes the underlying
// failure cause unless it is a password-policy or max-attempts
// outcome (both of which the UI surfaces by design).
func (s *ClaimService) ConsumeClaim(ctx context.Context, in ConsumeClaimInput) (*ConsumeClaimResult, error) {
	if in.Token == "" {
		return &ConsumeClaimResult{Success: false}, nil
	}
	if strings.TrimSpace(in.Password) == "" {
		return &ConsumeClaimResult{Success: false}, nil
	}
	email := strings.ToLower(strings.TrimSpace(in.Email))
	if email == "" {
		return &ConsumeClaimResult{Success: false}, nil
	}
	hash := hashToken(in.Token)
	claim, err := s.claims.GetByTokenHash(ctx, hash)
	if err != nil || claim == nil {
		return &ConsumeClaimResult{Success: false}, nil
	}
	if claim.IsExpired(s.now()) {
		return &ConsumeClaimResult{Success: false}, nil
	}
	if claim.IsMaxAttemptsReached() {
		// Burn the row idempotently — the next attempt also sees
		// "max reached" because the row is gone after this
		// branch. Mirror monolith semantics.
		_ = s.claims.Delete(ctx, claim.ID)
		return &ConsumeClaimResult{Success: false, AttemptsExhausted: true, Reason: "max_attempts_reached"}, nil
	}
	// Email-binding guard. Mismatch counts as a failed attempt
	// because a hostile claimant who guesses the URL must not be
	// able to retry indefinitely with different emails.
	if claim.EmailBound {
		if !strings.EqualFold(strings.TrimSpace(claim.TargetEmail), email) {
			s.incrementAttemptsOrBurn(ctx, claim)
			return &ConsumeClaimResult{Success: false}, nil
		}
	}
	// Cheap length floor — saves the DB roundtrip on obvious weak
	// inputs. The full per-org complexity check runs AFTER the org
	// load below so the policy is known.
	if len(in.Password) < s.minPasswordLength {
		newCount, _ := s.claims.IncrementAttemptCount(ctx, claim.ID)
		remaining := domain.ClaimMaxPasswordAttempts - newCount
		if remaining < 0 {
			remaining = 0
		}
		return &ConsumeClaimResult{
			Success:           false,
			AttemptsRemaining: remaining,
			Reason:            "weak_password",
		}, nil
	}
	// Org must exist + be pre-active. Mirror monolith.
	org, err := s.loadOrganization(ctx, claim.OrganizationID)
	if err != nil || org == nil {
		return &ConsumeClaimResult{Success: false}, nil
	}
	if org.Active {
		// Org was activated through another path; the claim is now
		// stale. Burn it.
		_ = s.claims.Delete(ctx, claim.ID)
		return &ConsumeClaimResult{Success: false}, nil
	}
	// Per-org PasswordComplexityEnabled enforcement (Decision D-015 §9,
	// slice agent-a-20260715). The org the claim targets is the
	// policy source; default true (strict) when unset on the org row.
	// A policy violation still increments the attempt counter so a
	// hostile claimant cannot brute-force a strong password.
	if err := domain.ValidatePasswordPolicy(in.Password, s.minPasswordLength, org.PasswordComplexityEnabled); err != nil {
		newCount, _ := s.claims.IncrementAttemptCount(ctx, claim.ID)
		remaining := domain.ClaimMaxPasswordAttempts - newCount
		if remaining < 0 {
			remaining = 0
		}
		return &ConsumeClaimResult{
			Success:           false,
			AttemptsRemaining: remaining,
			Reason:            "weak_password",
		}, nil
	}
	// Pre-existing org_admin guard. Even with a valid URL, we MUST
	// NOT mint a second org_admin row.
	if s.exists != nil {
		existing, _ := s.exists.FindUsersByEmail(ctx, email)
		for _, u := range existing {
			if u != nil && u.OrganizationID == org.ID {
				return &ConsumeClaimResult{Success: false, Reason: "email_exists"}, nil
			}
		}
	}
	// Burn-before-write: delete the claim BEFORE the new org_admin is created
	// so a parallel attempt cannot land two writes.
	//
	// P3-2: that sentence is only true because Delete now REPORTS whether it
	// removed a row. It used to discard the command tag, so a concurrent
	// claimant deleted nothing, saw a nil error, and minted a SECOND org_admin
	// — the delete was idempotent, and idempotent is the one thing a delete
	// used as a mutex must not be. The loser now takes this branch.
	if err := s.claims.Delete(ctx, claim.ID); err != nil {
		return &ConsumeClaimResult{Success: false}, nil
	}
	id, err := uuidgen.NewV7()
	if err != nil {
		return &ConsumeClaimResult{Success: false}, nil
	}
	now := s.now().UTC()
	user := &domain.User{
		ID:             id,
		OrganizationID: org.ID,
		Email:          email,
		PasswordHash:   in.Password, // pgx Create auto-hashes plaintext via argon2id
		Role:           domain.RoleOrgAdmin,
		AuthSource:     domain.AuthSourceLocal,
		EmailVerified:  true, // claim consume is the email-verification ceremony
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	if strings.TrimSpace(in.Name) != "" {
		n := strings.TrimSpace(in.Name)
		user.Name = &n
	}
	if _, err := s.users.Create(ctx, user); err != nil {
		// Partial-consume audit: the claim row is gone but the
		// org_admin was not minted. The wire stays {success:false}.
		_ = s.audit.Record(ctx, audit.Event{
			Action:         domain.AuditClaimConsumptionPartial,
			Outcome:        "denied",
			SubjectID:      org.ID,
			SubjectType:    "organization",
			OrganizationID: org.ID,
			IPAddress:      in.IPAddress,
			UserAgent:      in.UserAgent,
			Metadata: map[string]any{
				"target_email": email,
				"claim_id":     claim.ID.String(),
			},
		})
		return &ConsumeClaimResult{Success: false}, nil
	}
	_ = s.audit.Record(ctx, audit.Event{
		Action:         domain.AuditClaimConsumed,
		Outcome:        "success",
		SubjectID:      user.ID,
		SubjectType:    "user",
		OrganizationID: org.ID,
		IPAddress:      in.IPAddress,
		UserAgent:      in.UserAgent,
		Metadata: map[string]any{
			"claim_id":  claim.ID.String(),
			"user_role": string(user.Role),
		},
	})
	return &ConsumeClaimResult{Success: true}, nil
}

// incrementAttemptsOrBurn increments the attempt counter and, on
// max-reach, deletes the claim row.
func (s *ClaimService) incrementAttemptsOrBurn(ctx context.Context, claim *domain.OrganizationClaim) {
	newCount, err := s.claims.IncrementAttemptCount(ctx, claim.ID)
	if err != nil {
		return
	}
	if newCount >= domain.ClaimMaxPasswordAttempts {
		_ = s.claims.Delete(ctx, claim.ID)
	}
}

func (s *ClaimService) loadOrganization(ctx context.Context, id uuid.UUID) (*domain.Organization, error) {
	if s.orgs2 != nil {
		org, err := s.orgs2.GetByIDAdmin(ctx, id)
		if err == nil && org != nil {
			return org, nil
		}
	}
	org, err := s.orgs.GetByID(ctx, id)
	if err != nil || org == nil {
		return nil, domain.ErrOrganizationNotFound
	}
	return org, nil
}

func (s *ClaimService) generateToken() (string, string, error) {
	raw, err := crypto.GenerateRandomString(s.tokenSz)
	if err != nil {
		return "", "", err
	}
	return raw, hashToken(raw), nil
}
