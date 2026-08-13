package service

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/crypto"
	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// inMemoryUserLookup satisfies LocalLoginUserLookup.
type inMemoryUserLookup struct {
	byEmail map[string][]*domain.User
}

func newUserLookup() *inMemoryUserLookup {
	return &inMemoryUserLookup{byEmail: map[string][]*domain.User{}}
}

func (r *inMemoryUserLookup) FindUsersByEmail(_ context.Context, email string) ([]*domain.User, error) {
	out, ok := r.byEmail[strings.ToLower(email)]
	if !ok {
		return nil, nil
	}
	return out, nil
}

func newLoginHarness(t *testing.T) (*LocalLoginService, *inMemoryUserLookup) {
	t.Helper()
	users := newUserLookup()
	sessions := NewUserSessionService(nil, newSessionRepo(), UserSessionServiceOptions{DefaultTTL: time.Hour})
	mfa := NewMFAVerifierService(nil, PlaintextTOTPSecretResolver{}, MFAVerifierOptions{})
	return NewLocalLoginService(nil, users, sessions, mfa), users
}

func hashPwd(t *testing.T, p string) string {
	t.Helper()
	h, err := crypto.GenerateHash([]byte(p))
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	return h
}

// ---------- Construction ----------

func TestNewLocalLoginService_NilDepsPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("nil deps did not panic")
		}
	}()
	_ = NewLocalLoginService(nil, nil, nil, nil)
}

// ---------- Login ----------

func TestLogin_UnknownEmailIsInvalidCredentials(t *testing.T) {
	svc, _ := newLoginHarness(t)
	_, err := svc.Login(context.Background(), LoginInput{Email: "nobody@example.com", Password: "pw"})
	if !errors.Is(err, ErrLoginInvalidCredentials) {
		t.Errorf("err = %v", err)
	}
}

func TestLogin_WrongPasswordIsInvalidCredentials(t *testing.T) {
	svc, users := newLoginHarness(t)
	uid := uuid.New()
	users.byEmail["alice@example.com"] = []*domain.User{{
		ID: uid, Email: "alice@example.com", PasswordHash: hashPwd(t, "correct"),
		EmailVerified: true,
	}}
	_, err := svc.Login(context.Background(), LoginInput{Email: "alice@example.com", Password: "wrong"})
	if !errors.Is(err, ErrLoginInvalidCredentials) {
		t.Errorf("err = %v", err)
	}
}

func TestLogin_UnverifiedEmail(t *testing.T) {
	svc, users := newLoginHarness(t)
	uid := uuid.New()
	users.byEmail["alice@example.com"] = []*domain.User{{
		ID: uid, Email: "alice@example.com", PasswordHash: hashPwd(t, "correct"),
		EmailVerified: false,
	}}
	_, err := svc.Login(context.Background(), LoginInput{Email: "alice@example.com", Password: "correct"})
	if !errors.Is(err, ErrLoginAccountUnverified) {
		t.Errorf("err = %v", err)
	}
}

// RULE: USER-BAN-LOGIN-1
func TestLogin_BannedUserCollapsesToInvalidCredentials(t *testing.T) {
	svc, users := newLoginHarness(t)
	uid := uuid.New()
	users.byEmail["banned@example.com"] = []*domain.User{{
		ID: uid, Email: "banned@example.com", PasswordHash: hashPwd(t, "correct"),
		EmailVerified: true, Banned: true,
	}}
	_, err := svc.Login(context.Background(), LoginInput{Email: "banned@example.com", Password: "correct"})
	if !errors.Is(err, ErrLoginInvalidCredentials) {
		t.Errorf("err = %v", err)
	}
}

func TestLogin_AmbiguousEmailCollapsesToInvalidCredentials(t *testing.T) {
	svc, users := newLoginHarness(t)
	users.byEmail["dup@example.com"] = []*domain.User{
		{ID: uuid.New(), Email: "dup@example.com", PasswordHash: hashPwd(t, "pw"), EmailVerified: true},
		{ID: uuid.New(), Email: "dup@example.com", PasswordHash: hashPwd(t, "pw"), EmailVerified: true},
	}
	_, err := svc.Login(context.Background(), LoginInput{Email: "dup@example.com", Password: "pw"})
	if !errors.Is(err, ErrLoginInvalidCredentials) {
		t.Errorf("err = %v", err)
	}
}

func TestLogin_NoMFASuccess(t *testing.T) {
	svc, users := newLoginHarness(t)
	uid := uuid.New()
	users.byEmail["alice@example.com"] = []*domain.User{{
		ID: uid, Email: "alice@example.com", PasswordHash: hashPwd(t, "correct"),
		EmailVerified: true,
	}}
	result, err := svc.Login(context.Background(), LoginInput{Email: "alice@example.com", Password: "correct"})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if result.RefreshToken == "" {
		t.Errorf("refresh token missing")
	}
	if result.UserID != uid.String() {
		t.Errorf("user_id = %s", result.UserID)
	}
}

func TestLogin_MFAEnabledMissingCodeReturnsMFARequired(t *testing.T) {
	svc, users := newLoginHarness(t)
	uid := uuid.New()
	secret := freshTOTPSecret(t)
	users.byEmail["alice@example.com"] = []*domain.User{{
		ID: uid, Email: "alice@example.com", PasswordHash: hashPwd(t, "correct"),
		EmailVerified: true, MFAEnabled: true, MFASecret: &secret,
	}}
	_, err := svc.Login(context.Background(), LoginInput{Email: "alice@example.com", Password: "correct"})
	if !errors.Is(err, ErrLoginMFARequired) {
		t.Errorf("err = %v", err)
	}
}

func TestLogin_MFAEnabledValidCodeSucceeds(t *testing.T) {
	svc, users := newLoginHarness(t)
	uid := uuid.New()
	secret := freshTOTPSecret(t)
	users.byEmail["alice@example.com"] = []*domain.User{{
		ID: uid, Email: "alice@example.com", PasswordHash: hashPwd(t, "correct"),
		EmailVerified: true, MFAEnabled: true, MFASecret: &secret,
	}}
	counter := uint64(time.Now().Unix()) / uint64(defaultTOTPPeriod)
	code, _ := computeHOTP(secret, counter, 6)
	result, err := svc.Login(context.Background(), LoginInput{
		Email: "alice@example.com", Password: "correct", TOTPCode: code,
	})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if result.RefreshToken == "" {
		t.Errorf("refresh token empty")
	}
}

func TestLogin_MFAEnabledInvalidCodeIsInvalidCredentials(t *testing.T) {
	svc, users := newLoginHarness(t)
	uid := uuid.New()
	secret := freshTOTPSecret(t)
	users.byEmail["alice@example.com"] = []*domain.User{{
		ID: uid, Email: "alice@example.com", PasswordHash: hashPwd(t, "correct"),
		EmailVerified: true, MFAEnabled: true, MFASecret: &secret,
	}}
	_, err := svc.Login(context.Background(), LoginInput{
		Email: "alice@example.com", Password: "correct", TOTPCode: wrongCodeForWindow(t, secret, time.Now()),
	})
	if !errors.Is(err, ErrLoginInvalidCredentials) {
		t.Errorf("err = %v (wrong code must collapse to invalid_credentials)", err)
	}
}

// ---------- FAIL-CLOSED risk backend propagation (P1-4) ----------

// TestLogin_RiskBackendUnavailable_PasswordGate: when the risk backend
// errors at the PASSWORD gate, Login propagates the DISTINCT
// ErrLoginRiskBackendUnavailable (→ 503) instead of collapsing to
// invalid_credentials. The gate runs before any user lookup, so the
// outcome is account-independent (no enumeration).
func TestLogin_RiskBackendUnavailable_PasswordGate(t *testing.T) {
	svc, users := newLoginHarness(t)
	svc = svc.WithLoginRiskService(NewLoginRiskService(nil, erroringLoginAttemptRepo{}, LoginRiskServiceOptions{}))
	// Seed a valid user to prove the result does NOT depend on account state.
	users.byEmail["alice@example.com"] = []*domain.User{{
		ID: uuid.New(), Email: "alice@example.com",
		PasswordHash: hashPwd(t, "correct"), EmailVerified: true,
	}}
	for _, email := range []string{"alice@example.com", "nobody@example.com"} {
		_, err := svc.Login(context.Background(), LoginInput{Email: email, Password: "correct"})
		if !errors.Is(err, ErrLoginRiskBackendUnavailable) {
			t.Fatalf("email=%s: err = %v; want ErrLoginRiskBackendUnavailable", email, err)
		}
		if errors.Is(err, ErrLoginInvalidCredentials) {
			t.Fatalf("email=%s: backend-unavailable must NOT collapse to invalid_credentials", email)
		}
	}
}

// TestLogin_RiskBackendUnavailable_MFAGate: the password gate passes
// (repo errors only on the "mfa" purpose) so control reaches the MFA
// gate, whose Check error must also propagate as the distinct
// ErrLoginRiskBackendUnavailable, not invalid_credentials.
func TestLogin_RiskBackendUnavailable_MFAGate(t *testing.T) {
	svc, users := newLoginHarness(t)
	svc = svc.WithLoginRiskService(NewLoginRiskService(nil, erroringLoginAttemptRepo{errOnPurpose: "mfa"}, LoginRiskServiceOptions{}))
	secret := freshTOTPSecret(t)
	users.byEmail["alice@example.com"] = []*domain.User{{
		ID: uuid.New(), Email: "alice@example.com", PasswordHash: hashPwd(t, "correct"),
		EmailVerified: true, MFAEnabled: true, MFASecret: &secret,
	}}
	code, _ := computeHOTP(secret, uint64(time.Now().Unix())/uint64(defaultTOTPPeriod), 6)
	_, err := svc.Login(context.Background(), LoginInput{
		Email: "alice@example.com", Password: "correct", TOTPCode: code,
	})
	if !errors.Is(err, ErrLoginRiskBackendUnavailable) {
		t.Fatalf("mfa gate: err = %v; want ErrLoginRiskBackendUnavailable", err)
	}
	if errors.Is(err, ErrLoginInvalidCredentials) {
		t.Fatal("mfa-gate backend-unavailable must NOT collapse to invalid_credentials")
	}
}

func TestLogin_DoesNotLeakPasswordInError(t *testing.T) {
	svc, users := newLoginHarness(t)
	const sentinel = "RAW-PASSWORD-MUST-NOT-LEAK"
	uid := uuid.New()
	users.byEmail["alice@example.com"] = []*domain.User{{
		ID: uid, Email: "alice@example.com", PasswordHash: hashPwd(t, "correct"),
		EmailVerified: true,
	}}
	_, err := svc.Login(context.Background(), LoginInput{Email: "alice@example.com", Password: sentinel})
	if err == nil {
		t.Fatalf("expected error")
	}
	if strings.Contains(err.Error(), sentinel) {
		t.Errorf("error leaked password: %v", err)
	}
}

// ---------- MFA policy enforcement ----------
//
// All tests below pin the post-fix contract from slice
// agent-a-identuum-idp-oss-mfa-policy-enforcement: site_admin and
// org_admin MUST require MFA, and any user whose organization has
// mfa_policy=required MUST require MFA. When MFA is required but the
// user has not enrolled, Login MUST return ErrLoginMFAEnrollmentRequired
// — NOT a successful LoginResult — so the wire path cannot issue
// access/refresh tokens or set cookies.

func policyRequired() *string { s := "required"; return &s }
func policyOptional() *string { s := "optional"; return &s }

func TestIsMFARequiredForUser(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		user *domain.User
		want bool
	}{
		{"nil user", nil, false},
		{"site_admin no policy → required", &domain.User{Role: domain.RoleSiteAdmin}, true},
		{"site_admin optional policy → required", &domain.User{Role: domain.RoleSiteAdmin, MFAPolicy: policyOptional()}, true},
		{"site_admin required policy → required", &domain.User{Role: domain.RoleSiteAdmin, MFAPolicy: policyRequired()}, true},
		{"org_admin no policy → required", &domain.User{Role: domain.RoleOrgAdmin}, true},
		{"org_admin optional policy → required", &domain.User{Role: domain.RoleOrgAdmin, MFAPolicy: policyOptional()}, true},
		{"org_admin required policy → required", &domain.User{Role: domain.RoleOrgAdmin, MFAPolicy: policyRequired()}, true},
		{"org_user no policy → optional", &domain.User{Role: domain.RoleOrgUser}, false},
		{"org_user optional policy → optional", &domain.User{Role: domain.RoleOrgUser, MFAPolicy: policyOptional()}, false},
		{"org_user required policy → required", &domain.User{Role: domain.RoleOrgUser, MFAPolicy: policyRequired()}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := IsMFARequiredForUser(tc.user); got != tc.want {
				t.Fatalf("IsMFARequiredForUser: want %v, got %v", tc.want, got)
			}
		})
	}
}

// Updated 2026-06-05: Login's contract on the MFA gate paths now
// returns a partial LoginResult (with User populated, Session +
// RefreshToken unset) so the HTTP layer can mint a pending-MFA
// session_id. The "no session token may be issued" invariant is
// pinned by checking Session == nil + RefreshToken == "".

func assertPartialMFAResult(t *testing.T, label string, result *LoginResult, wantUserID uuid.UUID) {
	t.Helper()
	if result == nil || result.User == nil {
		t.Fatalf("%s: Login must return partial LoginResult with User populated on MFA gate paths", label)
	}
	if result.User.ID != wantUserID {
		t.Fatalf("%s: partial result user_id mismatch", label)
	}
	if result.Session != nil {
		t.Fatalf("%s: Login MUST NOT create a Session on the MFA gate path", label)
	}
	if result.RefreshToken != "" {
		t.Fatalf("%s: Login MUST NOT issue a RefreshToken on the MFA gate path", label)
	}
}

func TestLogin_SiteAdminWithoutMFAEnrollmentReturnsMFAEnrollmentRequired(t *testing.T) {
	svc, users := newLoginHarness(t)
	uid := uuid.New()
	users.byEmail["admin@example.com"] = []*domain.User{{
		ID:            uid,
		Email:         "admin@example.com",
		PasswordHash:  hashPwd(t, "correct"),
		EmailVerified: true,
		Role:          domain.RoleSiteAdmin,
		MFAEnabled:    false,
	}}
	result, err := svc.Login(context.Background(), LoginInput{Email: "admin@example.com", Password: "correct"})
	if !errors.Is(err, ErrLoginMFAEnrollmentRequired) {
		t.Fatalf("want ErrLoginMFAEnrollmentRequired, got err=%v result=%v", err, result)
	}
	assertPartialMFAResult(t, "site_admin", result, uid)
}

func TestLogin_OrgAdminWithoutMFAEnrollmentReturnsMFAEnrollmentRequired(t *testing.T) {
	svc, users := newLoginHarness(t)
	uid := uuid.New()
	users.byEmail["admin@example.com"] = []*domain.User{{
		ID:            uid,
		Email:         "admin@example.com",
		PasswordHash:  hashPwd(t, "correct"),
		EmailVerified: true,
		Role:          domain.RoleOrgAdmin,
		MFAEnabled:    false,
	}}
	result, err := svc.Login(context.Background(), LoginInput{Email: "admin@example.com", Password: "correct"})
	if !errors.Is(err, ErrLoginMFAEnrollmentRequired) {
		t.Fatalf("want ErrLoginMFAEnrollmentRequired, got err=%v", err)
	}
	assertPartialMFAResult(t, "org_admin", result, uid)
}

func TestLogin_OrgUserInRequiredPolicyOrgWithoutMFAReturnsMFAEnrollmentRequired(t *testing.T) {
	svc, users := newLoginHarness(t)
	uid := uuid.New()
	users.byEmail["user@example.com"] = []*domain.User{{
		ID:            uid,
		Email:         "user@example.com",
		PasswordHash:  hashPwd(t, "correct"),
		EmailVerified: true,
		Role:          domain.RoleOrgUser,
		MFAPolicy:     policyRequired(),
		MFAEnabled:    false,
	}}
	result, err := svc.Login(context.Background(), LoginInput{Email: "user@example.com", Password: "correct"})
	if !errors.Is(err, ErrLoginMFAEnrollmentRequired) {
		t.Fatalf("want ErrLoginMFAEnrollmentRequired, got %v", err)
	}
	assertPartialMFAResult(t, "org_user (required policy)", result, uid)
}

func TestLogin_OrgUserInOptionalPolicyOrgWithoutMFASucceeds(t *testing.T) {
	// Preserved legacy behaviour: org_user in an optional-MFA org with
	// MFAEnabled=false completes password-only login. This is the
	// only non-admin success path — pinned so a future change does
	// not regress the existing starter-tier behaviour.
	svc, users := newLoginHarness(t)
	users.byEmail["user@example.com"] = []*domain.User{{
		ID:            uuid.New(),
		Email:         "user@example.com",
		PasswordHash:  hashPwd(t, "correct"),
		EmailVerified: true,
		Role:          domain.RoleOrgUser,
		MFAPolicy:     policyOptional(),
		MFAEnabled:    false,
	}}
	result, err := svc.Login(context.Background(), LoginInput{Email: "user@example.com", Password: "correct"})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if result == nil || result.RefreshToken == "" {
		t.Fatal("Login: optional-policy org_user must complete password-only login")
	}
}

func TestLogin_SiteAdminWithMFAEnabledMissingCodeReturnsMFARequired(t *testing.T) {
	svc, users := newLoginHarness(t)
	secret := freshTOTPSecret(t)
	users.byEmail["admin@example.com"] = []*domain.User{{
		ID:            uuid.New(),
		Email:         "admin@example.com",
		PasswordHash:  hashPwd(t, "correct"),
		EmailVerified: true,
		Role:          domain.RoleSiteAdmin,
		MFAEnabled:    true,
		MFASecret:     &secret,
	}}
	_, err := svc.Login(context.Background(), LoginInput{Email: "admin@example.com", Password: "correct"})
	if !errors.Is(err, ErrLoginMFARequired) {
		t.Fatalf("want ErrLoginMFARequired, got %v", err)
	}
}

func TestLogin_SiteAdminWithMFAEnabledInvalidCodeIsInvalidCredentials(t *testing.T) {
	svc, users := newLoginHarness(t)
	secret := freshTOTPSecret(t)
	users.byEmail["admin@example.com"] = []*domain.User{{
		ID:            uuid.New(),
		Email:         "admin@example.com",
		PasswordHash:  hashPwd(t, "correct"),
		EmailVerified: true,
		Role:          domain.RoleSiteAdmin,
		MFAEnabled:    true,
		MFASecret:     &secret,
	}}
	_, err := svc.Login(context.Background(), LoginInput{
		Email: "admin@example.com", Password: "correct", TOTPCode: wrongCodeForWindow(t, secret, time.Now()),
	})
	if !errors.Is(err, ErrLoginInvalidCredentials) {
		t.Fatalf("want ErrLoginInvalidCredentials, got %v", err)
	}
}

func TestLogin_SiteAdminWithMFAEnabledValidCodeSucceeds(t *testing.T) {
	svc, users := newLoginHarness(t)
	secret := freshTOTPSecret(t)
	users.byEmail["admin@example.com"] = []*domain.User{{
		ID:            uuid.New(),
		Email:         "admin@example.com",
		PasswordHash:  hashPwd(t, "correct"),
		EmailVerified: true,
		Role:          domain.RoleSiteAdmin,
		MFAEnabled:    true,
		MFASecret:     &secret,
	}}
	counter := uint64(time.Now().Unix()) / uint64(defaultTOTPPeriod)
	code, _ := computeHOTP(secret, counter, 6)
	result, err := svc.Login(context.Background(), LoginInput{
		Email: "admin@example.com", Password: "correct", TOTPCode: code,
	})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if result == nil || result.RefreshToken == "" {
		t.Fatal("Login: enrolled site_admin with valid TOTP must complete login")
	}
}

func TestLogin_AdminFailsClosedWhenMFAVerifierUnwired(t *testing.T) {
	// MFA required by role, MFAEnabled=true, but the service was
	// constructed with mfa=nil (an operator-side misconfiguration).
	// Must NOT allow login — fail closed.
	users := newUserLookup()
	sessions := NewUserSessionService(nil, newSessionRepo(), UserSessionServiceOptions{DefaultTTL: time.Hour})
	svc := NewLocalLoginService(nil, users, sessions, nil) // mfa intentionally nil
	secret := freshTOTPSecret(t)
	users.byEmail["admin@example.com"] = []*domain.User{{
		ID:            uuid.New(),
		Email:         "admin@example.com",
		PasswordHash:  hashPwd(t, "correct"),
		EmailVerified: true,
		Role:          domain.RoleSiteAdmin,
		MFAEnabled:    true,
		MFASecret:     &secret,
	}}
	_, err := svc.Login(context.Background(), LoginInput{Email: "admin@example.com", Password: "correct"})
	if !errors.Is(err, ErrLoginInvalidCredentials) {
		t.Fatalf("want ErrLoginInvalidCredentials (fail closed), got %v", err)
	}
}

func TestLogin_WrongPasswordPrecedesMFAGate(t *testing.T) {
	// Wrong password must continue to return invalid_credentials —
	// MFA-enforcement decisions MUST NOT leak whether MFA is required
	// for an arbitrary email.
	svc, users := newLoginHarness(t)
	users.byEmail["admin@example.com"] = []*domain.User{{
		ID:            uuid.New(),
		Email:         "admin@example.com",
		PasswordHash:  hashPwd(t, "correct"),
		EmailVerified: true,
		Role:          domain.RoleSiteAdmin,
		MFAEnabled:    false,
	}}
	_, err := svc.Login(context.Background(), LoginInput{Email: "admin@example.com", Password: "wrong"})
	if !errors.Is(err, ErrLoginInvalidCredentials) {
		t.Fatalf("wrong password must return ErrLoginInvalidCredentials, got %v", err)
	}
}

// ---------- Org auth_policy enforcement ----------
//
// Tests below pin the post-fix contract from slice
// agent-a-20260709-idp-oss-authpolicy-local-login-enforcement.
//
// Locked admin-local invariant: site_admin AND org_admin retain the
// local credential flow regardless of the org's auth_policy. The
// idp_only policy denies ONLY non-admin (RoleOrgUser + unknown future
// roles via fail-closed) local password login. Policy-denied paths
// MUST return the same generic ErrLoginInvalidCredentials sentinel
// that wrong-password / unknown-user return — the policy state of an
// org MUST NOT be enumerable from the wire response.

func policyPtr(s string) *string { return &s }

// captureAuditor satisfies the OSS audit.Service seam for the policy
// enforcement tests. It records every Record() invocation in-order so
// assertions can pin Action / Outcome / Subject / Metadata shape
// without depending on a real audit pipeline. NoopService is the
// runtime default; this fake replaces it only inside the tests below.
type captureAuditor struct {
	events []audit.Event
}

func (c *captureAuditor) Record(_ context.Context, e audit.Event) error {
	c.events = append(c.events, e)
	return nil
}

func authPolicyDeniedFixture(t *testing.T, role domain.UserRole, policy string) (*LocalLoginService, *captureAuditor, uuid.UUID, uuid.UUID) {
	t.Helper()
	svc, users := newLoginHarness(t)
	auditor := &captureAuditor{}
	svc = svc.WithAudit(auditor)
	uid := uuid.New()
	orgID := uuid.New()
	users.byEmail["user@example.com"] = []*domain.User{{
		ID:             uid,
		Email:          "user@example.com",
		PasswordHash:   hashPwd(t, "correct"),
		EmailVerified:  true,
		Role:           role,
		OrganizationID: orgID,
		OrgAuthPolicy:  policyPtr(policy),
	}}
	return svc, auditor, uid, orgID
}

func TestLogin_IDPOnly_OrgUser_DeniedAsInvalidCredentials(t *testing.T) {
	svc, auditor, _, _ := authPolicyDeniedFixture(t, domain.RoleOrgUser, domain.AuthPolicyIDPOnly)
	result, err := svc.Login(context.Background(), LoginInput{
		Email:    "user@example.com",
		Password: "correct",
	})
	if !errors.Is(err, ErrLoginInvalidCredentials) {
		t.Fatalf("idp_only + org_user MUST return ErrLoginInvalidCredentials (generic), got err=%v", err)
	}
	if result != nil {
		t.Fatalf("policy-denied login MUST NOT return a LoginResult, got %+v", result)
	}
	if len(auditor.events) != 1 {
		t.Fatalf("expected exactly 1 audit event on policy denial, got %d", len(auditor.events))
	}
	got := auditor.events[0]
	if got.Action != string(domain.AuditLocalLoginBlockedByRole) {
		t.Errorf("audit Action: want %q, got %q", string(domain.AuditLocalLoginBlockedByRole), got.Action)
	}
	if got.Outcome != "denied" {
		t.Errorf("audit Outcome: want 'denied', got %q", got.Outcome)
	}
}

func TestLogin_IDPOnly_OrgAdmin_AllowedByAdminLocalInvariant(t *testing.T) {
	svc, auditor, uid, _ := authPolicyDeniedFixture(t, domain.RoleOrgAdmin, domain.AuthPolicyIDPOnly)
	result, err := svc.Login(context.Background(), LoginInput{
		Email:    "user@example.com",
		Password: "correct",
	})
	// org_admin MUST succeed even in idp_only orgs (admin-local invariant).
	// Note: RoleOrgAdmin requires MFA via IsMFARequiredForUser, so an
	// org_admin without MFAEnabled hits the MFA-enrollment gate AFTER
	// the auth_policy gate. The pin is that auth_policy did NOT block
	// the flow — either ErrLoginMFAEnrollmentRequired (allowed past
	// auth_policy, blocked by MFA gate) or success.
	if errors.Is(err, ErrLoginInvalidCredentials) && result == nil {
		t.Fatalf("admin-local invariant violated: idp_only + org_admin must NOT collapse to invalid_credentials")
	}
	if !errors.Is(err, ErrLoginMFAEnrollmentRequired) {
		t.Fatalf("expected MFA-enrollment gate (admin past auth_policy), got err=%v", err)
	}
	if result == nil || result.User == nil || result.User.ID != uid {
		t.Fatalf("expected partial result with User populated past auth_policy gate, got %+v", result)
	}
	if len(auditor.events) != 0 {
		t.Errorf("admin-local path MUST NOT emit policy-denied audit, got %d events", len(auditor.events))
	}
}

func TestLogin_IDPOnly_SiteAdmin_AllowedByAdminLocalInvariant(t *testing.T) {
	svc, auditor, uid, _ := authPolicyDeniedFixture(t, domain.RoleSiteAdmin, domain.AuthPolicyIDPOnly)
	result, err := svc.Login(context.Background(), LoginInput{
		Email:    "user@example.com",
		Password: "correct",
	})
	// Same shape as org_admin: site_admin also requires MFA so we land
	// on the MFA-enrollment gate AFTER (not before) the auth_policy
	// gate. The pin is that auth_policy did NOT block.
	if errors.Is(err, ErrLoginInvalidCredentials) && result == nil {
		t.Fatalf("admin-local invariant violated: idp_only + site_admin must NOT collapse to invalid_credentials")
	}
	if !errors.Is(err, ErrLoginMFAEnrollmentRequired) {
		t.Fatalf("expected MFA-enrollment gate (site_admin past auth_policy), got err=%v", err)
	}
	if result == nil || result.User == nil || result.User.ID != uid {
		t.Fatalf("expected partial result with User populated past auth_policy gate, got %+v", result)
	}
	if len(auditor.events) != 0 {
		t.Errorf("site_admin admin-local path MUST NOT emit policy-denied audit, got %d events", len(auditor.events))
	}
}

func TestLogin_Mixed_OrgUser_AllowedAsPreFix(t *testing.T) {
	svc, _ := newLoginHarness(t)
	users := svc.users.(*inMemoryUserLookup)
	uid := uuid.New()
	users.byEmail["mixed@example.com"] = []*domain.User{{
		ID:             uid,
		Email:          "mixed@example.com",
		PasswordHash:   hashPwd(t, "correct"),
		EmailVerified:  true,
		Role:           domain.RoleOrgUser,
		OrganizationID: uuid.New(),
		OrgAuthPolicy:  policyPtr(domain.AuthPolicyMixed),
	}}
	result, err := svc.Login(context.Background(), LoginInput{Email: "mixed@example.com", Password: "correct"})
	if err != nil {
		t.Fatalf("mixed + org_user must succeed, got err=%v", err)
	}
	if result == nil || result.RefreshToken == "" {
		t.Fatalf("mixed + org_user must mint a session, got %+v", result)
	}
}

func TestLogin_LocalOnly_OrgUser_AllowedAsPreFix(t *testing.T) {
	svc, _ := newLoginHarness(t)
	users := svc.users.(*inMemoryUserLookup)
	uid := uuid.New()
	users.byEmail["local@example.com"] = []*domain.User{{
		ID:             uid,
		Email:          "local@example.com",
		PasswordHash:   hashPwd(t, "correct"),
		EmailVerified:  true,
		Role:           domain.RoleOrgUser,
		OrganizationID: uuid.New(),
		OrgAuthPolicy:  policyPtr(domain.AuthPolicyLocalOnly),
	}}
	result, err := svc.Login(context.Background(), LoginInput{Email: "local@example.com", Password: "correct"})
	if err != nil {
		t.Fatalf("local_only + org_user must succeed, got err=%v", err)
	}
	if result == nil || result.RefreshToken == "" {
		t.Fatalf("local_only + org_user must mint a session, got %+v", result)
	}
}

func TestLogin_PermissiveEmpty_OrgUser_AllowedAsPreFix(t *testing.T) {
	// nil OrgAuthPolicy mirrors backward-compatibility with rows
	// loaded before the auth_policy projection landed.
	svc, _ := newLoginHarness(t)
	users := svc.users.(*inMemoryUserLookup)
	uid := uuid.New()
	users.byEmail["permissive@example.com"] = []*domain.User{{
		ID:             uid,
		Email:          "permissive@example.com",
		PasswordHash:   hashPwd(t, "correct"),
		EmailVerified:  true,
		Role:           domain.RoleOrgUser,
		OrganizationID: uuid.New(),
		// OrgAuthPolicy: nil (backward-compat default).
	}}
	result, err := svc.Login(context.Background(), LoginInput{Email: "permissive@example.com", Password: "correct"})
	if err != nil {
		t.Fatalf("nil OrgAuthPolicy + org_user must succeed (backward compat), got err=%v", err)
	}
	if result == nil || result.RefreshToken == "" {
		t.Fatalf("nil OrgAuthPolicy + org_user must mint a session, got %+v", result)
	}
}

func TestLogin_PolicyDenied_DoesNotLeakPolicyInError(t *testing.T) {
	// Regression test for the enumeration-safe error shape: the
	// returned error MUST be the exact ErrLoginInvalidCredentials
	// sentinel (errors.Is true) AND its rendered message MUST NOT
	// contain any policy-state substring an attacker could probe for.
	svc, _, _, _ := authPolicyDeniedFixture(t, domain.RoleOrgUser, domain.AuthPolicyIDPOnly)
	_, err := svc.Login(context.Background(), LoginInput{Email: "user@example.com", Password: "correct"})
	if !errors.Is(err, ErrLoginInvalidCredentials) {
		t.Fatalf("policy denial MUST surface ErrLoginInvalidCredentials sentinel, got %v", err)
	}
	msg := err.Error()
	for _, leak := range []string{"idp_only", "auth_policy", "policy", "blocked_by", "denied"} {
		if strings.Contains(strings.ToLower(msg), leak) {
			t.Errorf("policy-denied error MUST NOT contain %q (enumeration leak): %v", leak, err)
		}
	}
}

func TestLogin_PolicyDenied_BoundedAuditPayload(t *testing.T) {
	// Sensitive-data invariant: the audit payload MUST NOT carry the
	// raw password, raw TOTP code, refresh token, cookie, or any
	// other credential the request slice can see.
	//
	// The password MUST be correct so the request reaches the
	// auth_policy gate AFTER the password compare; a wrong password
	// would short-circuit to ErrLoginInvalidCredentials before the
	// policy gate ever runs. We inject a separately-recognisable
	// sentinel via the TOTPCode field instead — TOTPCode is also
	// privileged data that MUST NOT leak into audit.
	svc, auditor, _, _ := authPolicyDeniedFixture(t, domain.RoleOrgUser, domain.AuthPolicyIDPOnly)
	const totpLeak = "MUST-NOT-APPEAR-IN-AUDIT-TOTP"
	_, _ = svc.Login(context.Background(), LoginInput{
		Email:    "user@example.com",
		Password: "correct",
		TOTPCode: totpLeak,
	})
	if len(auditor.events) != 1 {
		t.Fatalf("want 1 audit event, got %d", len(auditor.events))
	}
	ev := auditor.events[0]
	// Sweep every string field + every metadata value for any of the
	// raw inputs the test injected. None of them are policy-relevant
	// — if any appears, the audit payload is leaking.
	for _, leak := range []string{totpLeak} {
		for _, field := range []string{ev.Action, ev.Outcome, ev.ActorEmail, ev.SubjectEmail, ev.IPAddress, ev.UserAgent} {
			if strings.Contains(field, leak) {
				t.Errorf("audit event field leaked %q: %s", leak, field)
			}
		}
		for k, v := range ev.Metadata {
			if s, ok := v.(string); ok {
				if strings.Contains(s, leak) {
					t.Errorf("audit metadata[%q] leaked %q: %s", k, leak, s)
				}
			}
		}
	}
}

func TestLogin_PolicyDenied_NoAuditServiceStillEnforces(t *testing.T) {
	// Wire the policy-denied path WITHOUT calling WithAudit: the
	// enforcement MUST still fire (metric still increments, the error
	// is still generic invalid_credentials, no session minted).
	svc, users := newLoginHarness(t)
	uid := uuid.New()
	users.byEmail["user@example.com"] = []*domain.User{{
		ID:             uid,
		Email:          "user@example.com",
		PasswordHash:   hashPwd(t, "correct"),
		EmailVerified:  true,
		Role:           domain.RoleOrgUser,
		OrganizationID: uuid.New(),
		OrgAuthPolicy:  policyPtr(domain.AuthPolicyIDPOnly),
	}}
	result, err := svc.Login(context.Background(), LoginInput{Email: "user@example.com", Password: "correct"})
	if !errors.Is(err, ErrLoginInvalidCredentials) {
		t.Fatalf("unaudited deployment MUST still enforce auth_policy, got err=%v", err)
	}
	if result != nil {
		t.Fatalf("unaudited policy-denied path MUST NOT return LoginResult, got %+v", result)
	}
}

func TestLogin_PolicyDenied_NoSessionMintedOnIDPOnly(t *testing.T) {
	// Cross-check that no session is minted on the denied path —
	// the User row's LastLoginAt is unchanged, no UserSession exists
	// for the user, no refresh token was returned.
	svc, _, _, _ := authPolicyDeniedFixture(t, domain.RoleOrgUser, domain.AuthPolicyIDPOnly)
	result, err := svc.Login(context.Background(), LoginInput{Email: "user@example.com", Password: "correct"})
	if !errors.Is(err, ErrLoginInvalidCredentials) {
		t.Fatalf("policy denial MUST collapse to invalid_credentials, got %v", err)
	}
	if result != nil {
		t.Fatalf("policy-denied path MUST return nil LoginResult, got %+v", result)
	}
}
