// organization_activation_service.go — OSS port of the monolith
// organization activation flow.
//
// Source-of-truth reference for behaviour:
//   identuum-idp/internal/service/organization_service_activation.go
//   identuum-idp/internal/handlers/handler_activation.go
//
// We do NOT import monolith code; the port reimplements the
// observable contract on top of OSS repository / audit / notifier
// seams.
//
// Wire contract (mirrors monolith for UI compatibility):
//
//   GET  /api/v1/auth/organizations/activate/:token
//       response: 200 { success: true, email, org_id } on accept
//                 400 { error: "invalid_token" } on bad / expired / consumed token
//
//   POST /api/v1/auth/organizations/activate
//       request:  { token, password }
//       response: 200 { success: true, organization{...} } on accept
//                 400 { error: "invalid_token" }            on bad / expired / consumed token
//                 400 { error: "weak_password" }            on policy reject
//                 409 { error: "organization_already_active" } on idempotent re-submit
//
// OSS scope notes (deliberate simplifications vs. the monolith):
//
//   - MFA is NOT generated during activation. The OSS login flow
//     enforces MFA enrollment via `IsMFARequiredForUser` AFTER the
//     org-admin's first password login, so the activation endpoint
//     only needs to set the password + flip Active. (Monolith's
//     activation generates+persists a TOTP secret here; we defer to
//     the existing OSS MFA enrolment endpoints landed in
//     auth_mfa_enroll.go.)
//   - OIDC linkage is NOT enforced here. The monolith blocks
//     activation when the org is not air-gapped AND the user is not
//     OIDC-linked; OSS treats activation as a local-credential path
//     and does not enforce that policy. CE composition may layer a
//     stricter gate without modifying OSS.
//
// Token model (uses the existing OSS columns
// `users.activation_token_hash` + `users.activation_token_expires_at`):
//
//   - Generated via crypto.GenerateRandomString(32) → 64 hex chars.
//   - SHA-256(raw_token) persisted on the user row; raw token NEVER
//     stored.
//   - TTL: 24 hours (matches the monolith).
//   - Single-use: ConsumeActivationToken clears the hash to NULL
//     BEFORE the password / Active flips are written
//     (burn-before-write). A subsequent attempt with the same raw
//     token finds the hash column NULL and is rejected.

package service

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/crypto"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/repository"
)

// DefaultOrganizationActivationTTL is the wall-clock lifetime of a
// single activation token. Matches the monolith.
const DefaultOrganizationActivationTTL = 24 * time.Hour

// Activation sentinels.
var (
	// ErrOrganizationActivationInvalidToken is the opaque sentinel for
	// every token-side failure (bad / unknown / expired / consumed /
	// user-missing / org-missing).
	ErrOrganizationActivationInvalidToken = errors.New("activation: invalid token")
	// ErrOrganizationActivationWeakPassword is returned when the supplied
	// password fails the configured length floor.
	ErrOrganizationActivationWeakPassword = errors.New("activation: weak password")
	// ErrOrganizationAlreadyActive is the conflict sentinel returned when
	// the operator re-submits an already-consumed activation flow whose
	// underlying organization has been flipped to active. The HTTP
	// boundary maps it to 409.
	ErrOrganizationAlreadyActive = errors.New("activation: organization already active")
	// ErrOrganizationActivationNoAdmin is returned when a resend is
	// requested for an org that has no org_admin to receive the token.
	// The HTTP boundary maps it to 404 (nothing to resend).
	ErrOrganizationActivationNoAdmin = errors.New("activation: no org_admin for organization")
)

// orgRepoActivationSurface is the narrow seam this service consumes
// from the organization repository: GetByID + Update + (optionally)
// GetByIDAdmin so we can read pre-activation rows that GetByID
// filters out.
type orgRepoActivationSurface interface {
	GetByID(ctx context.Context, id uuid.UUID) (*domain.Organization, error)
	Update(ctx context.Context, id uuid.UUID, opts repository.UpdateOrganizationOptions) (*domain.Organization, error)
}

// orgRepoActivationAdminSurface is the extended seam for orgs that
// are not yet active. PgxOrganizationRepository satisfies it via
// GetByIDAdmin.
type orgRepoActivationAdminSurface interface {
	GetByIDAdmin(ctx context.Context, id uuid.UUID) (*domain.Organization, error)
}

// OrganizationActivationNotifier is the minimum surface the service
// needs from the notification layer's SendActivationEmail.
type OrganizationActivationNotifier interface {
	SendActivationEmail(ctx context.Context, user *domain.User, rawToken string, expiresAt time.Time) error
}

// activationUserSurface is the narrow user-repo seam this service
// needs. PgxUserRepository satisfies it via Update +
// FindByActivationTokenHash.
type activationUserSurface interface {
	Update(ctx context.Context, id, orgID uuid.UUID, opts repository.UpdateUserOptions) (*domain.User, error)
	FindByActivationTokenHash(ctx context.Context, hash string) (*domain.User, error)
	// ConsumeActivationToken atomically claims the activation token, writes the
	// admin credentials, and activates the org in ONE transaction (P0-10).
	ConsumeActivationToken(ctx context.Context, activationTokenHash, newPasswordHash string) (*domain.User, bool, error)
	// ListByOrganization enumerates the org's users so resend can find
	// the pending org_admin. PgxUserRepository satisfies it.
	ListByOrganization(ctx context.Context, orgID uuid.UUID, opts repository.ListUserOptions) ([]*domain.User, int, error)
}

// OrganizationActivationService orchestrates issuance + validation +
// consumption.
type OrganizationActivationService struct {
	users     activationUserSurface
	orgs      orgRepoActivationSurface
	orgsAdmin orgRepoActivationAdminSurface
	notifier  OrganizationActivationNotifier
	audit     audit.Service
	logger    *zap.Logger
	now       func() time.Time
	tokenSize int
	ttl       time.Duration

	minPasswordLength int
}

// OrganizationActivationServiceConfig holds dependencies AND optional
// knobs. Refactored 2026-06-24 to satisfy the ≤5-arg target —
// `NewOrganizationActivationService` now takes a single argument of
// this type instead of 6 positional args.
//
// Required: Users, Orgs. Optional: OrgsAdmin (falls back to Orgs.GetByID
// which hides inactive orgs by default), Notifier, Audit (default
// audit.NoopService), Logger (zap.NewNop), Now (time.Now), TTL
// (DefaultOrganizationActivationTTL), MinPasswordLength (12).
type OrganizationActivationServiceConfig struct {
	Users     activationUserSurface
	Orgs      orgRepoActivationSurface
	OrgsAdmin orgRepoActivationAdminSurface
	Notifier  OrganizationActivationNotifier
	Audit     audit.Service

	TTL               time.Duration
	MinPasswordLength int
	Logger            *zap.Logger
	Now               func() time.Time
}

// NewOrganizationActivationService constructs the service.
// cfg.Users + cfg.Orgs are REQUIRED. cfg.OrgsAdmin is OPTIONAL — when
// nil the service falls back to GetByID and a not-yet-active org will
// be invisible (matches the OSS posture that GetByID hides inactive
// orgs by default).
func NewOrganizationActivationService(cfg OrganizationActivationServiceConfig) *OrganizationActivationService {
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
		ttl = DefaultOrganizationActivationTTL
	}
	minLen := cfg.MinPasswordLength
	if minLen <= 0 {
		minLen = 12 // monolith uses 12 for activation; keep stricter than reset
	}
	return &OrganizationActivationService{
		users:             cfg.Users,
		orgs:              cfg.Orgs,
		orgsAdmin:         cfg.OrgsAdmin,
		notifier:          cfg.Notifier,
		audit:             auditSvc,
		logger:            logger,
		now:               now,
		tokenSize:         32,
		ttl:               ttl,
		minPasswordLength: minLen,
	}
}

// IssueActivationToken mints a fresh activation token for the
// supplied org_admin user and emails it. The user must already
// carry RoleOrgAdmin. Returns the raw token so caller-side flows
// (e.g. an out-of-band recovery path) can echo it back to the
// operator; the raw token is NEVER logged or audited.
//
// The caller is responsible for selecting the user (typically the
// freshly-created org_admin row produced by the OSS organization
// create flow). The service stamps activation_token_hash +
// activation_token_expires_at on the user row.
func (s *OrganizationActivationService) IssueActivationToken(ctx context.Context, user *domain.User) (string, time.Time, error) {
	if user == nil {
		return "", time.Time{}, errors.New("activation: nil user")
	}
	if user.Role != domain.RoleOrgAdmin {
		return "", time.Time{}, errors.New("activation: user is not an org_admin")
	}
	raw, hash, err := s.generateToken()
	if err != nil {
		return "", time.Time{}, err
	}
	expiresAt := s.now().UTC().Add(s.ttl)
	if _, err := s.users.Update(ctx, user.ID, user.OrganizationID, repository.UpdateUserOptions{
		ActivationTokenHash:      &hash,
		ActivationTokenExpiresAt: &expiresAt,
	}); err != nil {
		return "", time.Time{}, err
	}
	if s.notifier != nil {
		if sendErr := s.notifier.SendActivationEmail(ctx, user, raw, expiresAt); sendErr != nil {
			s.logger.Warn("activation: send email failed",
				zap.String("user_id", user.ID.String()),
				zap.Error(sendErr),
			)
		}
	}
	return raw, expiresAt, nil
}

// ResendActivationToken re-issues a fresh activation token for a pending
// organization's org_admin and (re-)dispatches it — the OSS operator
// retrieval path for an unclaimed org whose activation email was lost or
// (in OSS) never wired.
//
// It reuses IssueActivationToken as the send seam: a NEW 32-byte random
// token is minted (crypto.GenerateRandomString — NOT a UUIDv7; the
// activation token is a secret, not an id), the org_admin's
// activation_token_hash is overwritten (so the OLD token is invalidated),
// and SendActivationEmail fires when a notifier is wired (nil in OSS,
// where the raw token is echoed via the API response instead). The raw
// token is returned for the caller to echo; it is NEVER logged or audited.
//
// Preconditions (fail-closed):
//   - the org must exist (admin-visible load, since a pending org is
//     hidden from GetByID) — else domain.ErrOrganizationNotFound.
//   - the org must NOT already be active — else ErrOrganizationAlreadyActive.
//   - the org must have an org_admin to receive the token — else
//     ErrOrganizationActivationNoAdmin.
func (s *OrganizationActivationService) ResendActivationToken(ctx context.Context, orgID uuid.UUID) (string, time.Time, string, error) {
	org, err := s.loadOrganization(ctx, orgID)
	if err != nil || org == nil {
		return "", time.Time{}, "", domain.ErrOrganizationNotFound
	}
	if org.Active {
		return "", time.Time{}, "", ErrOrganizationAlreadyActive
	}
	admin, err := s.findResendOrgAdmin(ctx, orgID)
	if err != nil {
		return "", time.Time{}, "", err
	}
	raw, expiresAt, err := s.IssueActivationToken(ctx, admin)
	if err != nil {
		return "", time.Time{}, "", err
	}
	return raw, expiresAt, admin.Email, nil
}

// findResendOrgAdmin returns the org's active org_admin — the recipient
// of the re-issued activation token. Missing → ErrOrganizationActivationNoAdmin.
func (s *OrganizationActivationService) findResendOrgAdmin(ctx context.Context, orgID uuid.UUID) (*domain.User, error) {
	users, _, err := s.users.ListByOrganization(ctx, orgID, repository.ListUserOptions{
		Pagination: repository.NewPagination(1, 50),
	})
	if err != nil {
		return nil, err
	}
	for _, u := range users {
		if u != nil && u.Role == domain.RoleOrgAdmin && u.DeletedAt == nil {
			return u, nil
		}
	}
	return nil, ErrOrganizationActivationNoAdmin
}

// ValidationResult is the GET /activate/:token response payload.
type ActivationValidationResult struct {
	Email string
	OrgID uuid.UUID
}

// ValidateActivationToken implements the GET pre-flight: looks up
// the user by activation_token_hash, checks the TTL, and returns
// the email + org id so the UI can render the password-setup form.
// The token is NOT consumed here — callers must POST to consume.
func (s *OrganizationActivationService) ValidateActivationToken(ctx context.Context, rawToken string) (*ActivationValidationResult, error) {
	if rawToken == "" {
		return nil, ErrOrganizationActivationInvalidToken
	}
	user, err := s.findByActivationToken(ctx, rawToken)
	if err != nil {
		return nil, err
	}
	if user.ActivationTokenExpiresAt != nil && s.now().After(*user.ActivationTokenExpiresAt) {
		return nil, ErrOrganizationActivationInvalidToken
	}
	org, err := s.loadOrganization(ctx, user.OrganizationID)
	if err != nil {
		return nil, err
	}
	if org.Active {
		return nil, ErrOrganizationAlreadyActive
	}
	return &ActivationValidationResult{Email: user.Email, OrgID: org.ID}, nil
}

// ConsumeActivationInput captures the POST values.
type ConsumeActivationInput struct {
	Token     string
	Password  string
	IPAddress string
	UserAgent string
}

// ConsumeActivationToken consumes the supplied token: sets the
// password, marks email_verified=true, flips the org to Active,
// and clears the activation token. Returns the activating user +
// updated org so the handler can echo back the org summary.
//
// Failure modes collapse onto the three exported sentinels.
func (s *OrganizationActivationService) ConsumeActivationToken(ctx context.Context, in ConsumeActivationInput) (*domain.User, *domain.Organization, error) {
	if in.Token == "" {
		return nil, nil, ErrOrganizationActivationInvalidToken
	}
	// Cheap length floor BEFORE the DB roundtrip — saves a query when
	// the password is obviously too short. Complexity check runs
	// AFTER the org lookup so the per-org policy is known.
	if len(in.Password) < s.minPasswordLength {
		return nil, nil, ErrOrganizationActivationWeakPassword
	}
	user, err := s.findByActivationToken(ctx, in.Token)
	if err != nil {
		return nil, nil, err
	}
	if user.ActivationTokenExpiresAt != nil && s.now().After(*user.ActivationTokenExpiresAt) {
		return nil, nil, ErrOrganizationActivationInvalidToken
	}
	org, err := s.loadOrganization(ctx, user.OrganizationID)
	if err != nil {
		return nil, nil, err
	}
	if org.Active {
		return nil, nil, ErrOrganizationAlreadyActive
	}
	// Per-org PasswordComplexityEnabled enforcement (Decision D-015 §9,
	// slice agent-a-20260715). The org being activated is the policy
	// source. Default true (strict) when unset on the org row.
	if err := domain.ValidatePasswordPolicy(in.Password, s.minPasswordLength, org.PasswordComplexityEnabled); err != nil {
		return nil, nil, ErrOrganizationActivationWeakPassword
	}
	// P0-10: atomic single-use claim + admin credential write + org activation
	// in ONE transaction. The password policy was validated FULLY above, BEFORE
	// any consume, so a policy-invalid password never burns the link. The
	// activation_token_hash is the atomic claim guard: a concurrent consumer
	// matches zero rows and is rejected; a failure in any write rolls the whole
	// transaction back (the link survives). Password is pre-hashed with argon2id.
	passwordHash, err := crypto.GenerateHash([]byte(in.Password))
	if err != nil {
		return nil, nil, fmt.Errorf("org_activation: hash password: %w", err)
	}
	updatedUser, claimed, err := s.users.ConsumeActivationToken(ctx, hashToken(in.Token), passwordHash)
	if err != nil {
		return nil, nil, fmt.Errorf("org_activation: consume activation token: %w", err)
	}
	if !claimed || updatedUser == nil {
		return nil, nil, ErrOrganizationActivationInvalidToken
	}
	// The transaction already flipped the org to Active; reflect it on the
	// loaded org for the response echo.
	org.Active = true
	updatedOrg := org
	_ = s.audit.Record(ctx, audit.Event{
		Action:         string(domain.AuditOrgActivated),
		Outcome:        "success",
		SubjectID:      updatedOrg.ID,
		SubjectType:    "organization",
		ActorID:        updatedUser.ID,
		OrganizationID: updatedOrg.ID,
		IPAddress:      in.IPAddress,
		UserAgent:      in.UserAgent,
		Metadata: map[string]any{
			"activated_by": updatedUser.Email,
		},
	})
	return updatedUser, updatedOrg, nil
}

// findByActivationToken hashes the raw token and walks the OSS user
// surface looking for a matching activation_token_hash.
//
// OSS user repos do not yet expose a "GetByActivationTokenHash"
// lookup — that affordance is a future helper. Until it lands, the
// fallback path here uses the existing user-by-id resolution via
// ListByOrganization is impractical without an org binding. The
// short-term solution: the user repo's FindByActivationTokenHash is
// added as a sibling helper in this slice; see
// FindUserByActivationTokenHash. Tests inject a stub seam.
func (s *OrganizationActivationService) findByActivationToken(ctx context.Context, rawToken string) (*domain.User, error) {
	hash := hashToken(rawToken)
	user, err := s.users.FindByActivationTokenHash(ctx, hash)
	if err != nil || user == nil {
		return nil, ErrOrganizationActivationInvalidToken
	}
	if user.ActivationTokenHash == nil {
		return nil, ErrOrganizationActivationInvalidToken
	}
	if subtle.ConstantTimeCompare([]byte(*user.ActivationTokenHash), []byte(hash)) != 1 {
		return nil, ErrOrganizationActivationInvalidToken
	}
	if user.DeletedAt != nil || user.Banned {
		return nil, ErrOrganizationActivationInvalidToken
	}
	return user, nil
}

func (s *OrganizationActivationService) loadOrganization(ctx context.Context, id uuid.UUID) (*domain.Organization, error) {
	if s.orgsAdmin != nil {
		// Inactive orgs are invisible via GetByID; the admin path is
		// the only way to reach them during activation.
		org, err := s.orgsAdmin.GetByIDAdmin(ctx, id)
		if err == nil && org != nil {
			return org, nil
		}
	}
	org, err := s.orgs.GetByID(ctx, id)
	if err != nil || org == nil {
		return nil, ErrOrganizationActivationInvalidToken
	}
	return org, nil
}

func (s *OrganizationActivationService) generateToken() (string, string, error) {
	raw, err := crypto.GenerateRandomString(s.tokenSize)
	if err != nil {
		return "", "", err
	}
	return raw, hashToken(raw), nil
}
