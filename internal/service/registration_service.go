package service

// registration_service.go — self-registration (owner ruling D-021, with
// rulings a-c of 2026-10-01).
//
//   - Two switches, both off: the instance switch (site_admin) is a ceiling;
//     under it an organization (org_admin) opens sign-up, may hold
//     registrants for approval, may require a verified email (refused
//     without SMTP) and may restrict email domains.
//   - The public answers never tell a closed, unknown or idp_only
//     organization apart (ruling c, D-007), nor a new address from an
//     existing one. A password the open organization's policy refuses is
//     the only other answer, checked before anything that could differ.
//   - A self-registrant is always org_user (D-008); its users row carries
//     registration_state, which the sign-in gate reads (ruling b).

import (
	"context"
	"errors"
	"net/mail"
	"strings"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/repository"
)

const registrationMinPasswordLength = 8

var (
	ErrRegistrationInstanceDisabled  = errors.New("registration: self-registration is off for this instance")
	ErrRegistrationSMTPNotConfigured = errors.New("registration: email delivery is not configured")
	ErrRegistrationInvalidDomain     = errors.New("registration: invalid email domain")
	ErrRegistrationNotPending        = errors.New("registration: user is not pending approval")
)

type registrationOrgs interface {
	GetBySlug(ctx context.Context, slug string) (*domain.Organization, error)
}

type registrationUsers interface {
	FindUsersByEmail(ctx context.Context, email string) ([]*domain.User, error)
	GetByID(ctx context.Context, id uuid.UUID) (*domain.User, error)
	Delete(ctx context.Context, id, orgID uuid.UUID) error
}

type registrationCreator interface {
	Create(ctx context.Context, opts CreateUserOptions) (*domain.User, error)
}

type registrationVerifier interface {
	IssueInitialVerification(ctx context.Context, user *domain.User) (string, error)
}

// RegistrationNotifier tells an address's owner that someone tried to
// register it (D-021: the answer discloses nothing; the mail does).
type RegistrationNotifier interface {
	SendRegistrationNoticeEmail(ctx context.Context, to, organizationName string) error
}

// RegistrationServiceConfig wires the service. SMTPConfigured is the
// runtime's own answer: verification can only be required when mail works.
type RegistrationServiceConfig struct {
	Repo           repository.RegistrationRepository
	Orgs           registrationOrgs
	Users          registrationUsers
	Creator        registrationCreator
	Verifier       registrationVerifier
	Notifier       RegistrationNotifier
	SMTPConfigured bool
	Audit          audit.Service
	Logger         *zap.Logger
}

type RegistrationService struct{ cfg RegistrationServiceConfig }

func NewRegistrationService(cfg RegistrationServiceConfig) *RegistrationService {
	if cfg.Audit == nil {
		cfg.Audit = audit.NoopService{}
	}
	if cfg.Logger == nil {
		cfg.Logger = zap.NewNop()
	}
	return &RegistrationService{cfg: cfg}
}

func actorEvent(actor *domain.Principal, ev audit.Event) audit.Event {
	if actor != nil {
		ev.ActorID, ev.ActorType, ev.ActorEmail, ev.ActorRole = actor.UserID, "user", actor.Email, string(actor.Role)
	}
	return ev
}

// ── switches ────────────────────────────────────────────────────────────

func (s *RegistrationService) InstanceEnabled(ctx context.Context) (bool, error) {
	return s.cfg.Repo.InstanceEnabled(ctx)
}

// SetInstanceEnabled is the site_admin's ceiling switch.
func (s *RegistrationService) SetInstanceEnabled(ctx context.Context, actor *domain.Principal, enabled bool) error {
	if actor == nil || !actor.IsSiteAdmin() {
		return domain.ErrForbidden
	}
	if err := s.cfg.Repo.SetInstanceEnabled(ctx, enabled); err != nil {
		return err
	}
	_ = s.cfg.Audit.Record(ctx, actorEvent(actor, audit.Event{Action: "instance.self_registration_updated", Outcome: "success",
		SubjectType: "instance", Metadata: map[string]any{"enabled": enabled}}))
	return nil
}

func (s *RegistrationService) orgAdminOf(actor *domain.Principal, orgID uuid.UUID) error {
	if actor == nil || !actor.IsOrgAdminOnly() || actor.OrganizationID == uuid.Nil || actor.OrganizationID != orgID {
		return domain.ErrForbidden
	}
	return nil
}

// OrgSettings is an org_admin's view of its organization's policy.
func (s *RegistrationService) OrgSettings(ctx context.Context, actor *domain.Principal, orgID uuid.UUID) (*domain.OrgRegistrationSettings, error) {
	if err := s.orgAdminOf(actor, orgID); err != nil {
		return nil, err
	}
	return s.cfg.Repo.OrgSettings(ctx, orgID)
}

// UpdateOrgSettings sets an organization's policy (org_admin, own org).
func (s *RegistrationService) UpdateOrgSettings(ctx context.Context, actor *domain.Principal, orgID uuid.UUID, in domain.OrgRegistrationSettings) (*domain.OrgRegistrationSettings, error) {
	if err := s.orgAdminOf(actor, orgID); err != nil {
		return nil, err
	}
	domains := []string{}
	for _, d := range in.EmailDomains {
		d = strings.ToLower(strings.TrimSpace(d))
		if d == "" || len(d) > 253 || !strings.Contains(d, ".") || strings.ContainsAny(d, "@ /") {
			return nil, ErrRegistrationInvalidDomain
		}
		domains = append(domains, d)
	}
	in.EmailDomains = domains
	if in.Allow {
		on, err := s.cfg.Repo.InstanceEnabled(ctx)
		if err != nil {
			return nil, err
		}
		if !on {
			return nil, ErrRegistrationInstanceDisabled
		}
	}
	if in.VerifyEmail && !s.cfg.SMTPConfigured {
		return nil, ErrRegistrationSMTPNotConfigured
	}
	if err := s.cfg.Repo.UpdateOrgSettings(ctx, orgID, in); err != nil {
		return nil, err
	}
	_ = s.cfg.Audit.Record(ctx, actorEvent(actor, audit.Event{Action: "organization.registration_updated", Outcome: "success",
		SubjectID: orgID, SubjectType: "organization", OrganizationID: orgID,
		Metadata: map[string]any{"allow_public_registration": in.Allow, "require_registration_approval": in.RequireApproval,
			"verify_email": in.VerifyEmail, "email_domains": len(in.EmailDomains)}}))
	return &in, nil
}

// ── public ──────────────────────────────────────────────────────────────

// RegistrationPasswordPolicy is what the sign-up form needs to check a password.
type RegistrationPasswordPolicy struct {
	MinLength  int  `json:"min_length"`
	Complexity bool `json:"complexity"`
}

// RegistrationInfo is the public answer. A closed organization is exactly
// {"open":false}, whatever made it closed.
type RegistrationInfo struct {
	Open             bool                        `json:"open"`
	VerifyEmail      *bool                       `json:"verify_email,omitempty"`
	ApprovalRequired *bool                       `json:"approval_required,omitempty"`
	PasswordPolicy   *RegistrationPasswordPolicy `json:"password_policy,omitempty"`
}

// openOrg returns the organization and its policy when sign-up is open:
// instance on, organization operational, not idp_only, registration allowed.
func (s *RegistrationService) openOrg(ctx context.Context, slug string) (*domain.Organization, *domain.OrgRegistrationSettings) {
	if on, err := s.cfg.Repo.InstanceEnabled(ctx); err != nil || !on {
		return nil, nil
	}
	org, err := s.cfg.Orgs.GetBySlug(ctx, strings.ToLower(strings.TrimSpace(slug)))
	if err != nil || org == nil || !org.IsOperational() || org.AuthPolicy == domain.AuthPolicyIDPOnly {
		return nil, nil
	}
	set, err := s.cfg.Repo.OrgSettings(ctx, org.ID)
	if err != nil || !set.Allow {
		return nil, nil
	}
	return org, set
}

func (s *RegistrationService) Info(ctx context.Context, slug string) RegistrationInfo {
	org, set := s.openOrg(ctx, slug)
	if org == nil {
		return RegistrationInfo{Open: false}
	}
	verify, approval := set.VerifyEmail, set.RequireApproval
	return RegistrationInfo{Open: true, VerifyEmail: &verify, ApprovalRequired: &approval,
		PasswordPolicy: &RegistrationPasswordPolicy{MinLength: registrationMinPasswordLength, Complexity: org.PasswordComplexityEnabled}}
}

// RegisterInput is one public sign-up.
type RegisterInput struct {
	Email, Name, Password, IPAddress, UserAgent string
}

// Register signs a stranger up. It returns an error ONLY for a password the
// open organization's policy refuses; every other outcome is nil and the
// handler answers the same 202.
func (s *RegistrationService) Register(ctx context.Context, slug string, in RegisterInput) error {
	org, set := s.openOrg(ctx, slug)
	refused := func(reason string, orgID uuid.UUID) error {
		_ = s.cfg.Audit.Record(ctx, audit.Event{Action: "user.self_registration_refused", Outcome: "failure", ActorType: "anonymous",
			OrganizationID: orgID, IPAddress: in.IPAddress, UserAgent: in.UserAgent, Metadata: map[string]any{"reason": reason}})
		return nil
	}
	if org == nil {
		return refused("closed", uuid.Nil)
	}
	// Policy first: it is the only answer that differs, and it must not
	// depend on whether the address exists.
	if err := domain.ValidatePasswordPolicy(in.Password, registrationMinPasswordLength, org.PasswordComplexityEnabled); err != nil {
		return err
	}
	email := strings.ToLower(strings.TrimSpace(in.Email))
	if a, err := mail.ParseAddress(email); err != nil || a.Address != email {
		return refused("invalid_email", org.ID)
	}
	if len(set.EmailDomains) > 0 {
		at := email[strings.LastIndex(email, "@")+1:]
		allowed := false
		for _, d := range set.EmailDomains {
			allowed = allowed || at == d
		}
		if !allowed {
			return refused("email_domain", org.ID)
		}
	}
	existing, err := s.cfg.Users.FindUsersByEmail(ctx, email)
	if err != nil {
		return refused("lookup_failed", org.ID)
	}
	live := 0
	for _, u := range existing {
		if u != nil && u.DeletedAt == nil {
			live++
		}
	}
	if live > 0 {
		if s.cfg.Notifier != nil {
			if err := s.cfg.Notifier.SendRegistrationNoticeEmail(ctx, email, org.Name); err != nil && !errors.Is(err, ErrEmailDeliveryNotConfigured) {
				s.cfg.Logger.Warn("registration: notice email failed", zap.String("organization_id", org.ID.String()), zap.Error(err))
			}
		}
		return refused("existing_email", org.ID)
	}
	complexity := org.PasswordComplexityEnabled
	mustChange := false
	user, err := s.cfg.Creator.Create(ctx, CreateUserOptions{OrganizationID: org.ID, Email: email, Password: in.Password,
		Name: strings.TrimSpace(in.Name), Role: domain.RoleOrgUser, PasswordComplexityEnabled: &complexity,
		MinPasswordLength: registrationMinPasswordLength, MustChangePassword: &mustChange, Unverified: true})
	if err != nil {
		return refused("create_failed", org.ID)
	}
	state := domain.RegistrationStateActive
	if set.RequireApproval {
		state = domain.RegistrationStatePendingApproval
	}
	if err := s.cfg.Repo.SetUserState(ctx, user.ID, state); err != nil {
		// Unmarked, the account is an ordinary unverified user: the sign-in
		// gate refuses it, so it fails closed.
		s.cfg.Logger.Error("registration: state not recorded", zap.String("user_id", user.ID.String()), zap.Error(err))
		return refused("state_failed", org.ID)
	}
	if set.VerifyEmail && s.cfg.Verifier != nil {
		if _, err := s.cfg.Verifier.IssueInitialVerification(ctx, user); err != nil {
			s.cfg.Logger.Warn("registration: verification not issued", zap.String("user_id", user.ID.String()), zap.Error(err))
		}
	}
	_ = s.cfg.Audit.Record(ctx, audit.Event{Action: "user.self_registered", Outcome: "success", ActorID: user.ID, ActorType: "user",
		ActorEmail: email, ActorRole: string(domain.RoleOrgUser), SubjectID: user.ID, SubjectType: "user", SubjectEmail: email,
		OrganizationID: org.ID, IPAddress: in.IPAddress, UserAgent: in.UserAgent,
		Metadata: map[string]any{"registration_state": state, "verify_email": set.VerifyEmail}})
	return nil
}

// ── approval ────────────────────────────────────────────────────────────

func (s *RegistrationService) ListPending(ctx context.Context, actor *domain.Principal, orgID uuid.UUID) ([]domain.PendingRegistration, error) {
	if err := s.orgAdminOf(actor, orgID); err != nil {
		return nil, err
	}
	return s.cfg.Repo.ListPending(ctx, orgID)
}

// pendingOf loads a self-registrant pending approval in the actor's org;
// anything else is not found (G10: no cross-tenant oracle).
func (s *RegistrationService) pendingOf(ctx context.Context, actor *domain.Principal, userID uuid.UUID) (*domain.User, error) {
	if actor == nil || !actor.IsOrgAdminOnly() {
		return nil, domain.ErrForbidden
	}
	u, err := s.cfg.Users.GetByID(ctx, userID)
	if err != nil || u == nil || u.OrganizationID != actor.OrganizationID {
		return nil, domain.ErrUserNotFound
	}
	state, _, err := s.cfg.Repo.UserState(ctx, u.ID)
	if err != nil {
		return nil, err
	}
	if state != domain.RegistrationStatePendingApproval {
		return nil, ErrRegistrationNotPending
	}
	return u, nil
}

func (s *RegistrationService) decide(ctx context.Context, actor *domain.Principal, u *domain.User, action string) {
	_ = s.cfg.Audit.Record(ctx, actorEvent(actor, audit.Event{Action: action, Outcome: "success", SubjectID: u.ID,
		SubjectType: "user", SubjectEmail: u.Email, OrganizationID: u.OrganizationID}))
}

// Approve lets a held self-registrant sign in.
func (s *RegistrationService) Approve(ctx context.Context, actor *domain.Principal, userID uuid.UUID) (*domain.User, error) {
	u, err := s.pendingOf(ctx, actor, userID)
	if err != nil {
		return nil, err
	}
	if err := s.cfg.Repo.SetUserState(ctx, u.ID, domain.RegistrationStateActive); err != nil {
		return nil, err
	}
	s.decide(ctx, actor, u, "user.registration_approved")
	return u, nil
}

// Reject deletes a held self-registrant.
func (s *RegistrationService) Reject(ctx context.Context, actor *domain.Principal, userID uuid.UUID) error {
	u, err := s.pendingOf(ctx, actor, userID)
	if err != nil {
		return err
	}
	if err := s.cfg.Users.Delete(ctx, u.ID, u.OrganizationID); err != nil {
		return err
	}
	s.decide(ctx, actor, u, "user.registration_rejected")
	return nil
}
