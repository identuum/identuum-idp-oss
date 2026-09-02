// Package service — LocalLoginService implements the OSS local
// email/password (+ TOTP) login flow that the future /authorize
// handler will plug into. The service composes:
//
//   - repository.UserRepository.FindUsersByEmail (email-only
//     lookup; ambiguity = unauthorized for safety)
//   - internal/crypto.CompareHashAndPassword (Argon2id)
//   - MFAVerifierService.Verify (RFC 6238 TOTP)
//   - UserSessionService.CreateUserSession
//
// What the service WILL NOT do:
//
//   - Issue a JWT access token. Human-user token issuance is
//     deferred to the slice that lands the access-token-from-
//     session minting path.
//   - Set cookies. The future /authorize will own that.
//   - Surface "wrong password" vs "unknown user" distinct error
//     codes. Both → ErrLoginInvalidCredentials. The MFA-required
//     condition is the ONLY user-visible distinction the service
//     surfaces (ErrLoginMFARequired) so a UI can prompt for a
//     TOTP code.
package service

import (
	"context"
	"errors"
	"strings"

	"github.com/identuum/identuum-idp-oss/auth"
	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/crypto"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/lifecycle"
	"github.com/identuum/identuum-idp-oss/internal/metrics"
)

// LocalLoginUserLookup is the narrow seam LocalLoginService
// consumes. *PgxUserRepository (and the full
// repository.UserRepository interface) satisfies it. Tests
// embed this seam directly without having to satisfy the
// hundreds of unrelated UserRepository methods.
type LocalLoginUserLookup interface {
	FindUsersByEmail(ctx context.Context, email string) ([]*domain.User, error)
}

// LocalLoginService is the OSS-narrow login orchestrator. It
// owns the password / MFA / session triad and nothing else.
type LocalLoginService struct {
	users    LocalLoginUserLookup
	mfa      *MFAVerifierService
	sessions *UserSessionService
	risk     *LoginRiskService
	auditSvc audit.Service
}

// WithLoginRiskService composes the rate-limit / lockout helper.
// Without it wired, every Login proceeds unguarded. With it wired,
// Login consults Check before the password compare and Records the
// outcome after.
func (s *LocalLoginService) WithLoginRiskService(r *LoginRiskService) *LocalLoginService {
	s.risk = r
	return s
}

// WithAudit composes the OSS-safe audit-emission seam. When wired,
// the local-credential-policy enforcement path emits a bounded
// `local_login_blocked_by_role` event (no password, token, cookie,
// or DB-credential material) on each policy-denied login. When nil
// or absent, audit emission is a no-op and policy denial still
// returns the same generic ErrLoginInvalidCredentials shape.
func (s *LocalLoginService) WithAudit(a audit.Service) *LocalLoginService {
	s.auditSvc = a
	return s
}

// NewLocalLoginService constructs the service. users and
// sessions are required; mfa is optional (when nil, MFA is
// effectively disabled — even for users with MFAEnabled the
// login proceeds without a TOTP check; documented blocker, see
// README).
func NewLocalLoginService(report *lifecycle.StartupReport, users LocalLoginUserLookup, sessions *UserSessionService, mfa *MFAVerifierService) *LocalLoginService {
	if users == nil {
		report.Fatal("NewLocalLoginService", "service: NewLocalLoginService requires a non-nil LocalLoginUserLookup")
	}
	if sessions == nil {
		report.Fatal("NewLocalLoginService", "service: NewLocalLoginService requires a non-nil UserSessionService")
	}
	return &LocalLoginService{
		users:    users,
		mfa:      mfa,
		sessions: sessions,
	}
}

// LoginInput is the parameter object accepted by Login.
type LoginInput struct {
	Email      string
	Password   string
	TOTPCode   string // optional — required when the user has MFA enabled
	RememberMe bool
	IPAddress  *string
	UserAgent  *string
}

// LoginResult carries the persisted session and the one-time
// refresh token returned by UserSessionService.CreateUserSession.
// User is the resolved user row so callers (the future
// access-token issuer) can stamp email/role/org_id claims
// without an extra repository round-trip.
type LoginResult struct {
	UserID       string
	User         *domain.User
	Session      *domain.Session
	RefreshToken string
}

// Sentinel errors. The wire mapping is:
//
//   - ErrLoginInvalidCredentials       → 401 invalid_credentials.
//     Covers unknown user, wrong password, banned, deleted,
//     unverified.
//   - ErrLoginMFARequired              → 401 mfa_required.
//     Returned when the user has an MFA secret enrolled and
//     either supplied no TOTP code or whose code did not verify
//     in a way the service surfaces as "re-prompt".
//   - ErrLoginAccountUnverified        → 401 account_unverified.
//     Distinguished from the catch-all because the future UI
//     can prompt the user to verify their email.
//   - ErrLoginMFAEnrollmentRequired    → 401 mfa_enrollment_required.
//     Returned when MFA is REQUIRED for this user (role or org
//     policy) but the user has not yet enrolled a TOTP secret.
//     No session, no token, no cookie is created on this path —
//     the caller must drive the user through TOTP enrolment
//     before another login attempt can succeed.
var (
	ErrLoginInvalidCredentials    = errors.New("service: login invalid credentials")
	ErrLoginMFARequired           = errors.New("service: login mfa required")
	ErrLoginAccountUnverified     = errors.New("service: login account unverified")
	ErrLoginMFAEnrollmentRequired = errors.New("service: login mfa enrollment required")
)

// orgMFAPolicyRequired is the canonical string value the OSS
// organization schema uses to mean "every member of this org must
// have MFA enrolled". Mirrors the CHECK constraint in
// migrations/0001_identity_credentials.sql (mfa_policy ∈
// {"optional","required"}). Defined here so this file does not need
// to import the organization package just for a literal.
const orgMFAPolicyRequired = "required"

// IsMFARequiredForUser returns true when the supplied user MUST
// complete an MFA step before a session can be created. The rules
// are union: any rule that fires forces MFA.
//
//  1. user.Role == RoleSiteAdmin — site administrators MUST require
//     MFA in any deployment, regardless of organization policy.
//     Bootstrap-time MFA-disabled site_admin rows are acceptable for
//     the ONE-TIME local-demo bootstrap path only; this enforcement
//     forces the operator into the enrolment flow on the first
//     browser login.
//  2. user.Role == RoleOrgAdmin — organization administrators MUST
//     require MFA.
//  3. user.MFAPolicy != nil && *user.MFAPolicy == "required" — when
//     the user's organization sets mfa_policy=required, every member
//     of that organization MUST require MFA.
//
// IsMFARequiredForUser is exported so handler tests and the docs can
// reference the canonical rule list without re-deriving it.
func IsMFARequiredForUser(user *domain.User) bool {
	if user == nil {
		return false
	}
	switch user.Role {
	case domain.RoleSiteAdmin, domain.RoleOrgAdmin:
		return true
	}
	if user.MFAPolicy != nil && *user.MFAPolicy == orgMFAPolicyRequired {
		return true
	}
	return false
}

// Login runs the password / MFA / session triad. On success
// returns a LoginResult with the persisted session and the
// caller-visible refresh token (returned EXACTLY ONCE — neither
// the service nor the repository can recover it later).
//
// Failure semantics:
//
//   - Unknown email, bad password, deleted user, banned user,
//     ambiguous email → ErrLoginInvalidCredentials. All collapse
//     to one wire response so the caller cannot enumerate users.
//   - Email unverified → ErrLoginAccountUnverified. Distinguished
//     because the UI surface can prompt for resend.
//   - MFA enabled + missing/invalid TOTP →
//     ErrLoginMFARequired (the UI re-prompts).
//   - MFA enabled + secret-resolver failure → treated as
//     invalid_credentials (fail-closed — operator-side issue
//     should be opaque to the user).
func (s *LocalLoginService) Login(ctx context.Context, in LoginInput) (*LoginResult, error) {
	email := strings.TrimSpace(strings.ToLower(in.Email))
	if email == "" || strings.TrimSpace(in.Password) == "" {
		return nil, ErrLoginInvalidCredentials
	}
	ip := ""
	if in.IPAddress != nil {
		ip = *in.IPAddress
	}
	// Rate-limit gate (when wired). A locked-out caller gets the
	// same wire response as "wrong password" so the surface
	// cannot enumerate locked accounts.
	if s.risk != nil {
		if err := s.risk.Check(ctx, email, ip, LoginRiskPurposePassword); err != nil {
			// Backend unavailable → propagate the DISTINCT sentinel so
			// the handler returns 503 (fail-closed). A genuine lockout
			// (ErrLoginRateLimited) collapses to invalid_credentials so
			// a locked account is not enumerable.
			if errors.Is(err, ErrLoginRiskBackendUnavailable) {
				return nil, ErrLoginRiskBackendUnavailable
			}
			return nil, ErrLoginInvalidCredentials
		}
	}
	users, err := s.users.FindUsersByEmail(ctx, email)
	if err != nil {
		return nil, ErrLoginInvalidCredentials
	}
	// Single-org OSS path: exactly one active user with that email
	// is required. Multi-org ambiguity collapses to invalid
	// credentials so an attacker cannot enumerate which org the
	// email belongs to.
	user := pickSingleActiveUser(users)
	if user == nil {
		// Run a dummy password compare so the timing profile
		// matches the success path. The hash used here is a known
		// invalid Argon2id payload generated by GenerateHash for
		// a sentinel string at init time; comparison always
		// fails. We don't precompute it (no globals); a fresh
		// CompareHashAndPassword on a junk hash returns quickly
		// enough to mask the user-not-found path's timing
		// asymmetry. The wire response is the same either way.
		_ = crypto.CompareHashAndPassword([]byte("$argon2id$v=19$m=65536,t=3,p=2$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"), []byte(in.Password))
		s.recordLoginRisk(ctx, email, ip, LoginRiskPurposePassword, false)
		return nil, ErrLoginInvalidCredentials
	}
	if err := crypto.CompareHashAndPassword([]byte(user.PasswordHash), []byte(in.Password)); err != nil {
		s.recordLoginRisk(ctx, email, ip, LoginRiskPurposePassword, false)
		return nil, ErrLoginInvalidCredentials
	}
	if !user.EmailVerified {
		return nil, ErrLoginAccountUnverified
	}
	if user.RequiresPasswordChange {
		// Operator policy: force-password-change blocks login.
		// The UI will land on a dedicated reset flow once /authorize
		// + password reset routes ship; for OSS the safest stop
		// here is invalid_credentials. Documented in the slice
		// notice.
		return nil, ErrLoginInvalidCredentials
	}

	// ── Org auth_policy enforcement gate ──────────────────────────────
	//
	// Runs AFTER the password compare (so an unauthenticated caller
	// cannot enumerate which orgs are configured idp_only by probing
	// arbitrary emails) and BEFORE any MFA or session creation (so a
	// policy-denied login NEVER produces credentials a caller could
	// later replay).
	//
	// The decision delegates to domain-package IsLocalCredentialFlowAllowed
	// which encodes the locked admin-local invariant: site_admin and
	// org_admin retain local credential access regardless of the org's
	// auth_policy. Only RoleOrgUser (and unknown future roles, by
	// fail-closed) are blocked when the org is idp_only.
	//
	// nil OrgAuthPolicy is treated as the empty/permissive default by
	// the helper, preserving backward compatibility with pre-projection
	// rows and inline test fixtures.
	orgAuthPolicy := ""
	if user.OrgAuthPolicy != nil {
		orgAuthPolicy = *user.OrgAuthPolicy
	}
	if decision := IsLocalCredentialFlowAllowed(user, orgAuthPolicy); !decision.Allowed {
		s.recordLocalCredentialPolicyDenied(ctx, user, orgAuthPolicy, in.IPAddress, in.UserAgent)
		// Collapse to the SAME wire error as wrong-password / unknown-
		// user paths so the policy state of an org is not enumerable
		// from the response. The audit + metric give the operator
		// visibility; the response stays generic.
		return nil, ErrLoginInvalidCredentials
	}

	// ── MFA policy gate ───────────────────────────────────────────────
	//
	// MUST run after the password compare so an unauthenticated caller
	// cannot enumerate whether MFA is required for an arbitrary email,
	// and BEFORE any session/refresh-token creation so a policy-failed
	// login NEVER produces credentials the caller could later replay.
	//
	// Three outcomes from IsMFARequiredForUser(user):
	//
	//   - required && !user.MFAEnabled        → ErrLoginMFAEnrollmentRequired
	//     The handler MUST NOT issue an access token, MUST NOT issue
	//     a refresh token, MUST NOT set cookies, and MUST NOT call
	//     CreateUserSession on this path. The caller (UI) drives the
	//     user through TOTP enrolment before another login attempt.
	//
	//   - required && user.MFAEnabled && s.mfa == nil → ErrLoginInvalidCredentials
	//     Fail-closed: an operator-side wiring issue (MFA verifier
	//     missing) MUST NOT allow a privileged login to proceed
	//     without TOTP verification.
	//
	//   - required && user.MFAEnabled && s.mfa != nil → fall through
	//     to the existing TOTP-verify block below — same semantics as
	//     the previous user.MFAEnabled branch.
	//
	// When MFA is NOT required by policy, the existing optional path
	// is preserved: enrolled non-admins still go through TOTP-verify;
	// unenrolled non-admins in optional-MFA orgs complete login on
	// password alone (the legacy starter-tier behaviour).
	mfaRequired := IsMFARequiredForUser(user)
	if mfaRequired && !user.MFAEnabled {
		// Partial-result contract: User is populated so the
		// HTTP layer (HandleLocalLogin) can mint a pending-MFA
		// session_id keyed to this user via MFAEnrollmentService.
		// Session + RefreshToken remain unset — no session is
		// created on this path. The caller MUST NOT trust this
		// partial result as a successful login.
		return &LoginResult{User: user}, ErrLoginMFAEnrollmentRequired
	}
	if mfaRequired && user.MFAEnabled && s.mfa == nil {
		return nil, ErrLoginInvalidCredentials
	}

	if user.MFAEnabled && s.mfa != nil {
		if s.risk != nil {
			if err := s.risk.Check(ctx, email, ip, LoginRiskPurposeMFA); err != nil {
				// Backend unavailable → 503 (fail-closed). Genuine MFA
				// lockout collapses to invalid_credentials.
				if errors.Is(err, ErrLoginRiskBackendUnavailable) {
					return nil, ErrLoginRiskBackendUnavailable
				}
				return nil, ErrLoginInvalidCredentials
			}
		}
		if err := s.mfa.Verify(ctx, user, in.TOTPCode); err != nil {
			if errors.Is(err, ErrMFARequired) {
				// Partial-result contract: User is populated so the
				// HTTP layer can mint a pending verify-kind session_id
				// keyed to this user via MFAEnrollmentService. Session
				// + RefreshToken remain unset — no session is created
				// on this path.
				return &LoginResult{User: user}, ErrLoginMFARequired
			}
			s.recordLoginRisk(ctx, email, ip, LoginRiskPurposeMFA, false)
			// ErrMFAInvalid + ErrMFASecretUnavailable + any other
			// MFA failure → opaque invalid_credentials. We do
			// NOT surface a distinct "wrong code" sentinel —
			// "code wrong" vs "no MFA configured" must be
			// indistinguishable to the caller.
			return nil, ErrLoginInvalidCredentials
		}
		s.recordLoginRisk(ctx, email, ip, LoginRiskPurposeMFA, true)
	}
	s.recordLoginRisk(ctx, email, ip, LoginRiskPurposePassword, true)
	// MaxSessionsPerUser policy from the user's org row (projected via
	// scanUserWithOrg). Zero or negative ⇒ no cap. Admin role exemption
	// is enforced inside CreateUserSession so passing the value here is
	// safe regardless of role.
	maxSessions := 0
	if user.OrgMaxSessionsPerUser != nil {
		maxSessions = *user.OrgMaxSessionsPerUser
	}
	// THE-HONEST-ACR: stamp the context ACTUALLY performed. This point is
	// reached with the password verified and — when the user has TOTP
	// enrolled (the s.mfa.Verify branch above returned on any failure) —
	// the TOTP verified as well. Before this the session carried no acr and
	// the id_token could not honestly say how the user authenticated.
	acr, amr := auth.LoginContext(user.MFAEnabled && s.mfa != nil)
	issued, err := s.sessions.CreateUserSession(ctx, CreateUserSessionInput{
		UserID:             user.ID,
		IPAddress:          in.IPAddress,
		UserAgent:          in.UserAgent,
		RememberMe:         in.RememberMe,
		Acr:                acr,
		Amr:                amr,
		MaxSessionsPerUser: maxSessions,
		OrganizationID:     user.OrganizationID,
		Role:               string(user.Role),
	})
	if err != nil {
		return nil, err
	}
	return &LoginResult{
		UserID:       user.ID.String(),
		User:         user,
		Session:      issued.Session,
		RefreshToken: issued.RefreshToken,
	}, nil
}

// pickSingleActiveUser returns the single non-deleted /
// non-banned candidate from a result slice. Returns nil when the
// slice is empty OR when more than one candidate matches (the
// caller MUST treat that as invalid credentials — an attacker
// must not be able to enumerate which org an email is bound to
// via the wire response).
// recordLoginRisk persists an attempt row when the risk service
// is wired. Errors are swallowed because the wire path must NOT
// fail an otherwise-successful login on an audit-table issue.
func (s *LocalLoginService) recordLoginRisk(ctx context.Context, email, ip string, purpose LoginRiskPurpose, success bool) {
	if s.risk == nil {
		return
	}
	_ = s.risk.Record(ctx, email, ip, purpose, success)
}

// recordLocalCredentialPolicyDenied emits the metric + bounded audit
// event for a policy-denied local login. Both are best-effort: a
// failure on the audit pipeline MUST NOT influence the wire response
// (which is already ErrLoginInvalidCredentials by the calling site).
//
// The audit payload deliberately carries NO password, token, cookie,
// session, raw refresh token, DB URL, or hashed credential material.
// Only public identity attributes (user ID, org ID, role) plus the
// org's auth_policy value and the request-side IP/UA the caller
// already passed for risk recording are emitted.
func (s *LocalLoginService) recordLocalCredentialPolicyDenied(ctx context.Context, user *domain.User, orgAuthPolicy string, ip, ua *string) {
	// Metric is package-level; always-on regardless of audit wiring.
	// Shape matches the existing metrics.AuthPolicyViolation declaration:
	// labels are {"policy", "org_id"} — see internal/metrics/auth.go.
	metrics.AuthPolicyViolation.WithLabelValues(orgAuthPolicy, user.OrganizationID.String()).Inc()
	if s.auditSvc == nil {
		return
	}
	ipStr, uaStr := "", ""
	if ip != nil {
		ipStr = *ip
	}
	if ua != nil {
		uaStr = *ua
	}
	_ = s.auditSvc.Record(ctx, audit.Event{
		Action:         string(domain.AuditLocalLoginBlockedByRole),
		Outcome:        "denied",
		ActorID:        user.ID,
		ActorType:      "user",
		ActorEmail:     user.Email,
		ActorRole:      string(user.Role),
		SubjectID:      user.ID,
		SubjectType:    "user",
		SubjectEmail:   user.Email,
		OrganizationID: user.OrganizationID,
		IPAddress:      ipStr,
		UserAgent:      uaStr,
		Metadata: map[string]any{
			"reason":      "auth_policy_blocks_local_login",
			"auth_policy": orgAuthPolicy,
		},
	})
}

func pickSingleActiveUser(users []*domain.User) *domain.User {
	var pick *domain.User
	for _, u := range users {
		if u == nil {
			continue
		}
		if u.DeletedAt != nil {
			continue
		}
		if u.Banned {
			continue
		}
		if pick != nil {
			// Ambiguity → no choice.
			return nil
		}
		pick = u
	}
	return pick
}
