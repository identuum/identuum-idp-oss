package handlers

// OSS-G8-PASSKEY-MFA-CARRYOVER (owner decision 2026-10-16): a passkey sign-in
// whose assertion the authenticator user-verified, and which meets a required
// password change (D-017), keeps that proof through the change step. The change
// then finishes the sign-in at the phishing-resistant rung, as the direct
// passkey sign-in does, and does not ask a passkey-only member to enrol TOTP.
// The proof is the server's own record on the one-time handle: bound to the
// user, single-use, and expiring with the handle. A password sign-in, or a
// presence-only assertion, still meets the MFA policy after the change.
//
// No password, handle, token or code value is printed by these tests.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/repository"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

const g8Chosen = "Chosen-by-member-42!"

// g8PendingRepo is a map-backed MFAPendingLoginSessionRepository whose
// MarkConsumed is atomic (one winner), as the PostgreSQL one is.
type g8PendingRepo struct {
	recoveryPendingRepoStub
	mu   sync.Mutex
	rows map[uuid.UUID]*domain.MFAPendingLoginSession
}

func (r *g8PendingRepo) Create(_ context.Context, row *domain.MFAPendingLoginSession) (*domain.MFAPendingLoginSession, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	cp := *row
	cp.CreatedAt = time.Now()
	r.rows[cp.ID] = &cp
	out := cp
	return &out, nil
}

func (r *g8PendingRepo) GetByID(_ context.Context, id uuid.UUID) (*domain.MFAPendingLoginSession, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	row, ok := r.rows[id]
	if !ok {
		return nil, repository.ErrMFAPendingSessionNotFound
	}
	cp := *row
	return &cp, nil
}

func (r *g8PendingRepo) MarkConsumed(_ context.Context, id uuid.UUID, now time.Time) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	row, ok := r.rows[id]
	if !ok || row.ConsumedAt != nil || !row.ExpiresAt.After(now) {
		return false, nil
	}
	row.ConsumedAt = &now
	return true, nil
}

func (r *g8PendingRepo) row(id string) domain.MFAPendingLoginSession {
	r.mu.Lock()
	defer r.mu.Unlock()
	return *r.rows[uuid.MustParse(id)]
}

func (r *g8PendingRepo) expire(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rows[uuid.MustParse(id)].ExpiresAt = time.Now().Add(-time.Second)
}

// g8UserRepo stores the user for the change step: a password write clears the
// requirement once (the single winner, as the PostgreSQL update's
// RequirePasswordChangePending predicate does).
type g8UserRepo struct {
	*recoveryStubUserRepo
}

func (r g8UserRepo) HashPassword(_ context.Context, p string) (string, error) {
	return "HASH:" + p, nil
}

func (r g8UserRepo) VerifyPassword(_ context.Context, p, hash string) error {
	if hash == "HASH:"+p {
		return nil
	}
	return errInvalidG8Password
}

var errInvalidG8Password = errors.New("password mismatch")

func g8HasCookie(rec *httptest.ResponseRecorder, name string) bool {
	for _, c := range rec.Result().Cookies() {
		if c.Name == name && c.Value != "" {
			return true
		}
	}
	return false
}

func (r g8UserRepo) Update(_ context.Context, id uuid.UUID, _ uuid.UUID, opts repository.UpdateUserOptions) (*domain.User, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	u, ok := r.byID[id]
	if !ok {
		return nil, nil
	}
	if opts.RequirePasswordChangePending && !u.RequiresPasswordChange {
		return nil, nil
	}
	if opts.Password != nil {
		u.PasswordHash = *opts.Password
	}
	if opts.RequiresPasswordChange != nil {
		u.RequiresPasswordChange = *opts.RequiresPasswordChange
	}
	cp := *u
	return &cp, nil
}

func (r g8UserRepo) user(id uuid.UUID) domain.User {
	r.mu.Lock()
	defer r.mu.Unlock()
	return *r.byID[id]
}

func (r g8UserRepo) setAuthPolicy(id uuid.UUID, policy string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.byID[id].OrgAuthPolicy = &policy
}

type g8World struct {
	user     *domain.User
	users    g8UserRepo
	pending  *g8PendingRepo
	sessions *inMemorySessionRepoForHandlers
	sessMu   *sync.Mutex
	rec      *audit.Recorder
	mfa      *service.MFAEnrollmentService
	change   *service.ChangePasswordService
	engine   *gin.Engine
}

// g8Member is a local org_user with a passkey, an admin-set password it must
// change, and no TOTP, in an organization that requires MFA.
func g8Member() *domain.User {
	required := "required"
	set := time.Now().Add(-time.Hour)
	return &domain.User{
		ID: uuid.New(), OrganizationID: uuid.New(), Role: domain.RoleOrgUser, Email: "member@g8.test",
		AuthSource: domain.AuthSourceLocal, PasswordHash: "HASH:Admin-set-0001!", RequiresPasswordChange: true,
		AdminPasswordSetAt: &set, MFAPolicy: &required, EmailVerified: true,
	}
}

func newG8World(t *testing.T, user *domain.User) *g8World {
	t.Helper()
	gin.SetMode(gin.ReleaseMode)
	users := g8UserRepo{newRecoveryStubUserRepo()}
	users.byID[user.ID] = user
	pending := &g8PendingRepo{rows: map[uuid.UUID]*domain.MFAPendingLoginSession{}}
	mfa := service.NewMFAEnrollmentService(nil, service.MFAEnrollmentRepoOptions{
		Pending: pending, Users: users, Issuer: "Identuum", Cipher: identityMFACipher{}, Replay: testReplayGuardForHandlers(),
	}, service.MFAEnrollmentServiceOptions{})
	sessions := newSessionRepoForHandlers()
	w := &g8World{
		user: user, users: users, pending: pending, sessions: sessions, sessMu: &sync.Mutex{}, rec: &audit.Recorder{}, mfa: mfa,
		change: service.NewChangePasswordService(users, 8),
	}
	w.engine = gin.New()
	RegisterAuthSessionRoutes(w.engine, AuthSessionsHandlerDeps{
		MFAEnrollment:  mfa,
		ChangePassword: w.change,
		UserSession:    service.NewUserSessionService(nil, &g8LockedSessions{sessions, w.sessMu}, service.UserSessionServiceOptions{}),
		Audit:          w.rec,
	})
	return w
}

// passkeyFinish runs the passkey finish handler with the assertion's UV flag
// as the validator would report it, and returns the status and body.
func (w *g8World) passkeyFinish(t *testing.T, uv bool) (int, map[string]any) {
	t.Helper()
	snap := w.users.user(w.user.ID)
	deps := WebAuthnHandlerDeps{
		Audit:         w.rec,
		UserSession:   service.NewUserSessionService(nil, &g8LockedSessions{w.sessions, w.sessMu}, service.UserSessionServiceOptions{}),
		LoginFinisher: r2StubLoginFinisher{user: &snap, uv: uv},
		UserOrgLookup: r2StubUserOrgLookup{user: &snap},
		MFAEnrollment: w.mfa,
	}
	r := gin.New()
	r.POST("/finish", HandleWebAuthnLoginFinish(deps))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/finish?session_id=abc", nil))
	var m map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &m)
	return rec.Code, m
}

func (w *g8World) changeStep(t *testing.T, handle, password string, stepStatus bool) (int, map[string]any, *httptest.ResponseRecorder) {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"session_id": handle, "new_password": password})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login/password-change", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	if stepStatus {
		req.Header.Set(LoginStepStatusHeader, LoginStepStatusOK)
	}
	rec := httptest.NewRecorder()
	w.engine.ServeHTTP(rec, req)
	var m map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &m)
	return rec.Code, m, rec
}

func (w *g8World) liveSessions() []*domain.Session {
	w.sessMu.Lock()
	defer w.sessMu.Unlock()
	var out []*domain.Session
	for _, s := range w.sessions.byID {
		if s.UserID == w.user.ID && s.RevokedAt == nil {
			out = append(out, s)
		}
	}
	return out
}

func (w *g8World) auditRow(action string) *audit.Event {
	for _, ev := range w.rec.Events() {
		if ev.Action == action {
			e := ev
			return &e
		}
	}
	return nil
}

// g8LockedSessions serializes session creation in the in-memory store so the
// concurrent redemption case runs under -race.
type g8LockedSessions struct {
	*inMemorySessionRepoForHandlers
	mu *sync.Mutex
}

func (s *g8LockedSessions) Create(ctx context.Context, sess *domain.Session) (*domain.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.inMemorySessionRepoForHandlers.Create(ctx, sess)
}

// The passkey member's first two steps: the UV assertion meets the change step
// with a handle and no credential.
func g8PasskeyHandle(t *testing.T, w *g8World) string {
	t.Helper()
	code, m := w.passkeyFinish(t, true)
	handle, _ := m["session_id"].(string)
	if code != http.StatusUnauthorized || m["error"] != "password_change_required" || handle == "" {
		t.Fatalf("passkey finish = %d %v; want 401 password_change_required with a handle", code, m["error"])
	}
	if m["refresh_token"] != nil || m["access_token"] != nil || len(w.liveSessions()) != 0 {
		t.Fatalf("passkey finish before the change issued a credential or a session")
	}
	return handle
}

// RULE: PASSKEY-MFA-CARRYOVER-1
// S1/S4: a UV passkey member with no TOTP, in an MFA-required organization,
// chooses a password and is signed in at the phishing-resistant rung; no TOTP
// enrolment, the TOTP state untouched, the handle spent, the audit row naming
// the passkey. Both status contracts finish the same way.
func TestPasskeyCarryover_UVProofFinishesTheChange(t *testing.T) {
	for _, stepStatus := range []bool{false, true} {
		t.Run(map[bool]string{false: "401-steps", true: "step-status-header"}[stepStatus], func(t *testing.T) {
			w := newG8World(t, g8Member())
			handle := g8PasskeyHandle(t, w)
			code, m, rec := w.changeStep(t, handle, g8Chosen, stepStatus)
			if code != http.StatusOK || m["session_id"] == nil || m["mfa_enrollment_required"] != nil || m["mfa_required"] != nil {
				t.Fatalf("change step after a UV passkey = %d %v; want 200 with a session and no MFA continuation", code, m["error"])
			}
			if !g8HasCookie(rec, "refresh_token") {
				t.Errorf("change step set no refresh cookie; want the sign-in's cookies")
			}
			live := w.liveSessions()
			if len(live) != 1 {
				t.Fatalf("live sessions = %d; want 1", len(live))
			}
			if live[0].Acr != service.ACRPhishingResistant || len(live[0].Amr) != 0 {
				t.Errorf("session acr=%q amr=%v; want %q and no amr, as the direct passkey sign-in", live[0].Acr, live[0].Amr, service.ACRPhishingResistant)
			}
			after := w.users.user(w.user.ID)
			if after.MFAEnabled || after.MFASecret != nil || len(after.MFARecoveryCodes) != 0 || after.RequiresPasswordChange {
				t.Errorf("user after = mfa_enabled %v, secret set %v, %d recovery codes, change owed %v; want TOTP untouched and the change done",
					after.MFAEnabled, after.MFASecret != nil, len(after.MFARecoveryCodes), after.RequiresPasswordChange)
			}
			if row := w.pending.row(handle); row.ConsumedAt == nil {
				t.Errorf("the change handle is not consumed")
			}
			if ev := w.auditRow("user_session.login.success"); ev == nil || ev.Metadata["method"] != "passkey" {
				t.Errorf("sign-in audit row = %v; want user_session.login.success with method passkey", ev)
			}
			if w.auditRow("user_session.login.mfa_enrollment_required") != nil {
				t.Errorf("an MFA enrolment step was recorded; want none")
			}
		})
	}
}

// S2: a member who also has TOTP is not asked for a code after a UV passkey.
func TestPasskeyCarryover_TOTPEnrolledIsNotChallengedAgain(t *testing.T) {
	u := g8Member()
	secret := "enc:JBSWY3DPEHPK3PXP"
	u.MFAEnabled, u.MFASecret, u.MFARecoveryCodes = true, &secret, []string{"h1", "h2"}
	w := newG8World(t, u)
	handle := g8PasskeyHandle(t, w)
	code, m, _ := w.changeStep(t, handle, g8Chosen, false)
	if code != http.StatusOK || m["session_id"] == nil {
		t.Fatalf("change step = %d %v; want 200 with a session (the UV passkey is the second factor)", code, m["error"])
	}
	if live := w.liveSessions(); len(live) != 1 || live[0].Acr != service.ACRPhishingResistant {
		t.Fatalf("sessions = %d; want one at the phishing-resistant rung", len(live))
	}
	if after := w.users.user(w.user.ID); !after.MFAEnabled || after.MFASecret == nil || len(after.MFARecoveryCodes) != 2 {
		t.Errorf("TOTP state changed; want it untouched")
	}
}

// S2 controls: a presence-only assertion, and a password sign-in of a member
// who has a passkey, still meet the MFA policy after the change.
func TestPasskeyCarryover_NoProofStillMeetsMFA(t *testing.T) {
	t.Run("presence-only assertion", func(t *testing.T) {
		w := newG8World(t, g8Member())
		code, m := w.passkeyFinish(t, false)
		handle, _ := m["session_id"].(string)
		if code != http.StatusUnauthorized || m["error"] != "password_change_required" || handle == "" {
			t.Fatalf("finish = %d %v; want 401 password_change_required", code, m["error"])
		}
		if row := w.pending.row(handle); row.Kind != domain.MFAPendingKindPasswordChange {
			t.Errorf("a presence-only assertion minted kind %q; want the ordinary %q", row.Kind, domain.MFAPendingKindPasswordChange)
		}
		code, m, _ = w.changeStep(t, handle, g8Chosen, false)
		if code != http.StatusUnauthorized || m["error"] != "mfa_enrollment_required" {
			t.Errorf("change step = %d %v; want 401 mfa_enrollment_required", code, m["error"])
		}
		if n := len(w.liveSessions()); n != 0 {
			t.Errorf("live sessions = %d; want 0", n)
		}
	})
	t.Run("password sign-in", func(t *testing.T) {
		w := newG8World(t, g8Member())
		row, err := w.mfa.CreatePending(context.Background(), w.user, domain.MFAPendingKindPasswordChange, false)
		if err != nil {
			t.Fatal(err)
		}
		code, m, _ := w.changeStep(t, row.ID.String(), g8Chosen, false)
		if code != http.StatusUnauthorized || m["error"] != "mfa_enrollment_required" {
			t.Errorf("change step = %d %v; want 401 mfa_enrollment_required", code, m["error"])
		}
		if n := len(w.liveSessions()); n != 0 {
			t.Errorf("live sessions = %d; want 0", n)
		}
	})
}

// S3: the proof is single-use and expires with its handle; a replay or an
// expired handle issues nothing.
func TestPasskeyCarryover_ProofIsOneUseAndExpires(t *testing.T) {
	t.Run("replay", func(t *testing.T) {
		w := newG8World(t, g8Member())
		handle := g8PasskeyHandle(t, w)
		if code, m, _ := w.changeStep(t, handle, g8Chosen, false); code != http.StatusOK {
			t.Fatalf("first change = %d %v; want 200", code, m["error"])
		}
		code, m, _ := w.changeStep(t, handle, g8Chosen+"x", false)
		if code != http.StatusUnauthorized || m["error"] != "invalid_session" || m["session_id"] != nil {
			t.Errorf("replayed change = %d %v; want 401 invalid_session and no session", code, m["error"])
		}
		if n := len(w.liveSessions()); n != 1 {
			t.Errorf("live sessions = %d; want 1", n)
		}
	})
	t.Run("expired", func(t *testing.T) {
		w := newG8World(t, g8Member())
		handle := g8PasskeyHandle(t, w)
		w.pending.expire(handle)
		code, m, _ := w.changeStep(t, handle, g8Chosen, false)
		if code != http.StatusUnauthorized || m["session_id"] != nil {
			t.Errorf("expired change = %d %v; want 401 and no session", code, m["error"])
		}
		if n := len(w.liveSessions()); n != 0 {
			t.Errorf("live sessions = %d; want 0", n)
		}
		if after := w.users.user(w.user.ID); !after.RequiresPasswordChange {
			t.Errorf("an expired handle changed the password")
		}
	})
	t.Run("concurrent", func(t *testing.T) {
		w := newG8World(t, g8Member())
		handle := g8PasskeyHandle(t, w)
		var wg sync.WaitGroup
		codes := make([]int, 8)
		for i := range codes {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				codes[i], _, _ = w.changeStep(t, handle, g8Chosen, false)
			}(i)
		}
		wg.Wait()
		ok := 0
		for _, c := range codes {
			if c == http.StatusOK {
				ok++
			}
		}
		if ok != 1 || len(w.liveSessions()) != 1 {
			t.Errorf("concurrent redemptions: %d answered 200, %d live sessions; want exactly 1 and 1", ok, len(w.liveSessions()))
		}
	})
}

// S3: an organization that turned idp_only between the assertion and the
// change gains no local sign-in through the proof.
func TestPasskeyCarryover_PolicyRecheckedAtCompletion(t *testing.T) {
	w := newG8World(t, g8Member())
	handle := g8PasskeyHandle(t, w)
	w.users.setAuthPolicy(w.user.ID, domain.AuthPolicyIDPOnly)
	code, m, _ := w.changeStep(t, handle, g8Chosen, false)
	if code != http.StatusUnauthorized || m["error"] != "invalid_credentials" || m["session_id"] != nil {
		t.Errorf("change after the org turned idp_only = %d %v; want 401 invalid_credentials and no handle", code, m["error"])
	}
	if n := len(w.liveSessions()); n != 0 {
		t.Errorf("live sessions = %d; want 0", n)
	}
}

// S3 / brief item 5: the browser sign-in's change step serves only handles of
// a password sign-in. A passkey handle is refused there before the password
// changes, never finished at a lower rung or stamped as OTP.
func TestPasskeyCarryover_BrowserChangeRefusesThePasskeyHandle(t *testing.T) {
	w := newG8World(t, g8Member())
	handle := g8PasskeyHandle(t, w)
	deps := BrowserLoginHandlerDeps{
		Audit: w.rec, MFAEnrollment: w.mfa, ChangePassword: w.change,
		UserSession: service.NewUserSessionService(nil, &g8LockedSessions{w.sessions, w.sessMu}, service.UserSessionServiceOptions{}),
	}
	form := url.Values{"new_password": {g8Chosen}, "confirm_password": {g8Chosen}}
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/auth/browser-login", strings.NewReader(form.Encode()))
	c.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	handleBrowserPasswordChange(c, deps, handle, "")
	if c.Writer.Status() != http.StatusSeeOther || !strings.Contains(rec.Header().Get("Location"), "error=invalid_credentials") {
		t.Errorf("browser change with a passkey handle = %d to %q; want 303 to error=invalid_credentials", c.Writer.Status(), rec.Header().Get("Location"))
	}
	if n := len(w.liveSessions()); n != 0 {
		t.Errorf("live sessions = %d; want 0", n)
	}
	if after := w.users.user(w.user.ID); !after.RequiresPasswordChange {
		t.Errorf("the browser step changed the password with a passkey handle; want it unchanged")
	}
	if row := w.pending.row(handle); row.ConsumedAt != nil {
		t.Errorf("the browser step consumed the passkey handle; want it left to the console step")
	}
}
