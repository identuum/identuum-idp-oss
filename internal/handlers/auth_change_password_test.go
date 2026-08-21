package handlers

// Unit coverage for POST /api/v1/auth/change-password
// (THE-V036-PASSWORD / CHANGE-PASSWORD-1 + THE-R2-REVOCATION / PW-REVOKE-1).
// Hermetic: gin + the in-package user-repo stub + the in-memory session
// repo; no Postgres, no network.
//
// R2 — RULED 2026-08-21: a successful password change revokes all the
// user's OTHER sessions and ALL OAuth refresh tokens; the session making
// the change stays valid. PW-REVOKE-1 pins exactly that; the refusal
// paths still revoke NOTHING.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/mw"
	"github.com/identuum/identuum-idp-oss/internal/repository"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// changePwStubRepo reuses the in-package panic-by-default stub and overrides
// exactly the surface ChangePasswordService touches: GetByIDWithOrg,
// VerifyPassword, HashPassword, Update.
type changePwStubRepo struct {
	*recoveryStubUserRepo
	user    *domain.User
	updates []repository.UpdateUserOptions
}

func (r *changePwStubRepo) GetByIDWithOrg(_ context.Context, id uuid.UUID) (*domain.User, error) {
	if r.user == nil || r.user.ID != id {
		return nil, nil
	}
	cp := *r.user
	return &cp, nil
}

func (r *changePwStubRepo) VerifyPassword(_ context.Context, password, hash string) error {
	if password == "correct-current-password" && hash == "HASH-CURRENT-PASSWORD" {
		return nil
	}
	return domain.ErrInvalidCredentials
}

func (r *changePwStubRepo) HashPassword(pw string) (string, error) {
	return "$argon2id$hashed:" + pw, nil
}

func (r *changePwStubRepo) Update(_ context.Context, id uuid.UUID, _ uuid.UUID, opts repository.UpdateUserOptions) (*domain.User, error) {
	r.updates = append(r.updates, opts)
	if r.user == nil || r.user.ID != id {
		return nil, nil
	}
	if opts.Password != nil {
		r.user.PasswordHash = *opts.Password
	}
	cp := *r.user
	return &cp, nil
}

// spyAllSessionsRevoker guards the SESSION-LESS branch: when the principal
// carries a session id, the all-sessions seam must never fire (the current
// session would die with the rest).
type spyAllSessionsRevoker struct {
	t     *testing.T
	calls int
	deny  bool
}

func (s *spyAllSessionsRevoker) RevokeUserSessions(context.Context, uuid.UUID, string, map[string]any) error {
	s.calls++
	if s.deny {
		s.t.Error("the all-sessions seam must NOT fire when the principal has a session (the current session must survive)")
	}
	return nil
}

// countingRefreshRevoker records the R2 refresh fan-out.
type countingRefreshRevoker struct{ calls int }

func (s *countingRefreshRevoker) RevokeAllForUser(context.Context, uuid.UUID) (int64, error) {
	s.calls++
	return 2, nil
}

type changePwHarness struct {
	router      *gin.Engine
	repo        *changePwStubRepo
	sessionRepo *inMemorySessionRepoForHandlers
	allRevoker  *spyAllSessionsRevoker
	refresh     *countingRefreshRevoker
}

// seedSession inserts an ACTIVE session for uid and returns its id.
func seedSession(repo *inMemorySessionRepoForHandlers, uid uuid.UUID) uuid.UUID {
	id := uuid.New()
	sel := uuid.New()
	repo.byID[id] = &domain.Session{
		ID:            id,
		UserID:        uid,
		TokenSelector: &sel,
		IsValid:       true,
		ExpiresAt:     time.Now().Add(time.Hour),
	}
	return id
}

func newChangePwHarness(t *testing.T, principal *domain.Principal, user *domain.User) *changePwHarness {
	t.Helper()
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	if principal != nil {
		r.Use(mw.InjectPrincipalForTest(principal))
	}
	repo := &changePwStubRepo{recoveryStubUserRepo: newRecoveryStubUserRepo(), user: user}
	sessionRepo := newSessionRepoForHandlers()
	all := &spyAllSessionsRevoker{t: t, deny: principal != nil && principal.SessionID != uuid.Nil}
	refresh := &countingRefreshRevoker{}
	RegisterAuthSessionRoutes(r, AuthSessionsHandlerDeps{
		ChangePassword:      service.NewChangePasswordService(repo, 0),
		UserSession:         service.NewUserSessionService(nil, sessionRepo, service.UserSessionServiceOptions{DefaultTTL: time.Hour}),
		SessionRevoker:      all,
		RefreshTokenRevoker: refresh,
	})
	return &changePwHarness{router: r, repo: repo, sessionRepo: sessionRepo, allRevoker: all, refresh: refresh}
}

func postChangePassword(r *gin.Engine, body map[string]string) *httptest.ResponseRecorder {
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/change-password", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func changePwUser(id uuid.UUID) *domain.User {
	return &domain.User{
		ID:             id,
		OrganizationID: uuid.New(),
		Email:          "self@example.invalid",
		PasswordHash:   "HASH-CURRENT-PASSWORD",
		Role:           domain.RoleOrgUser,
		AuthSource:     domain.AuthSourceLocal,
	}
}

// RULE: CHANGE-PASSWORD-1
func TestChangePassword_ContractAndRefusals(t *testing.T) {
	uid := uuid.New()

	t.Run("wrong current password → 403 opaque, hash untouched, nothing revoked", func(t *testing.T) {
		h := newChangePwHarness(t, &domain.Principal{UserID: uid, SessionID: uuid.New()}, changePwUser(uid))
		w := postChangePassword(h.router, map[string]string{
			"current_password": "WRONG-password-1!",
			"new_password":     "Perfectly-Fine-New-Pw-1!",
		})
		if w.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403; body %s", w.Code, w.Body.String())
		}
		// Wire keys pinned: exactly {"error":"invalid_current_password"}.
		var body map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if len(body) != 1 || body["error"] != "invalid_current_password" {
			t.Fatalf("403 envelope must be exactly {error: invalid_current_password}; got %v", body)
		}
		if len(h.repo.updates) != 0 || h.repo.user.PasswordHash != "HASH-CURRENT-PASSWORD" {
			t.Fatal("a refused change must not touch the stored hash")
		}
		if h.refresh.calls != 0 {
			t.Fatal("a REFUSED change must revoke nothing")
		}
	})

	t.Run("policy violation → 400 weak_password with displayable message, hash untouched", func(t *testing.T) {
		h := newChangePwHarness(t, &domain.Principal{UserID: uid, SessionID: uuid.New()}, changePwUser(uid))
		w := postChangePassword(h.router, map[string]string{
			"current_password": "correct-current-password",
			"new_password":     "zq9",
		})
		if w.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400; body %s", w.Code, w.Body.String())
		}
		var body map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		// Wire keys pinned: {"error":"weak_password","message":<policy text>}.
		if body["error"] != "weak_password" {
			t.Fatalf("400 envelope must carry error=weak_password; got %v", body)
		}
		msg, _ := body["message"].(string)
		if strings.TrimSpace(msg) == "" {
			t.Fatalf("400 envelope must carry a displayable policy message; got %v", body)
		}
		if strings.Contains(msg, "zq9") || strings.Contains(msg, "correct-current-password") {
			t.Fatalf("the policy message must never echo a password value; got %q", msg)
		}
		if len(h.repo.updates) != 0 {
			t.Fatal("a refused change must not touch the stored hash")
		}
		if h.refresh.calls != 0 {
			t.Fatal("a REFUSED change must revoke nothing")
		}
	})

	t.Run("federated (non-local) account → the SAME opaque 403", func(t *testing.T) {
		u := changePwUser(uid)
		u.AuthSource = "oidc"
		h := newChangePwHarness(t, &domain.Principal{UserID: uid, SessionID: uuid.New()}, u)
		w := postChangePassword(h.router, map[string]string{
			"current_password": "correct-current-password",
			"new_password":     "Perfectly-Fine-New-Pw-1!",
		})
		if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "invalid_current_password") {
			t.Fatalf("federated accounts must collapse into the opaque 403; got %d %s", w.Code, w.Body.String())
		}
		if len(h.repo.updates) != 0 {
			t.Fatal("a refused change must not touch the stored hash")
		}
	})

	t.Run("no principal → 401 (RequireAuthenticated)", func(t *testing.T) {
		h := newChangePwHarness(t, nil, changePwUser(uid))
		w := postChangePassword(h.router, map[string]string{
			"current_password": "correct-current-password",
			"new_password":     "Perfectly-Fine-New-Pw-1!",
		})
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", w.Code)
		}
	})

	t.Run("success → 204 empty body, hash rotated, only the password on the update", func(t *testing.T) {
		principal := &domain.Principal{UserID: uid, OrganizationID: uuid.New()}
		h := newChangePwHarness(t, principal, changePwUser(uid))
		principal.SessionID = seedSession(h.sessionRepo, uid)
		h.allRevoker.deny = true
		w := postChangePassword(h.router, map[string]string{
			"current_password": "correct-current-password",
			"new_password":     "Perfectly-Fine-New-Pw-1!",
		})
		if w.Code != http.StatusNoContent {
			t.Fatalf("status = %d, want 204; body %s", w.Code, w.Body.String())
		}
		if w.Body.Len() != 0 {
			t.Fatalf("success body must be empty; got %q", w.Body.String())
		}
		if len(h.repo.updates) != 1 || h.repo.updates[0].Password == nil {
			t.Fatalf("exactly one hash update expected; got %+v", h.repo.updates)
		}
		if h.repo.user.PasswordHash != "$argon2id$hashed:Perfectly-Fine-New-Pw-1!" {
			t.Fatalf("stored hash must be the NEW hash; got %q", h.repo.user.PasswordHash)
		}
		// Only Password may be set on the update — no role/email/MFA side
		// effects can ride along on a password change.
		u := h.repo.updates[0]
		if u.Email != nil || u.Role != nil || u.Banned != nil || u.MFAEnabled != nil || u.MFASecret != nil {
			t.Fatalf("the update must carry ONLY the password hash; got %+v", u)
		}
	})
}

// RULE: PW-REVOKE-1
func TestPWRevoke_OtherSessionsDieCurrentSurvives(t *testing.T) {
	uid := uuid.New()

	t.Run("R2: the OTHER pre-existing session is DEAD, the changing session works, refresh tokens revoked", func(t *testing.T) {
		principal := &domain.Principal{UserID: uid, OrganizationID: uuid.New()}
		h := newChangePwHarness(t, principal, changePwUser(uid))
		current := seedSession(h.sessionRepo, uid)
		other := seedSession(h.sessionRepo, uid) // the would-be hijacked session
		principal.SessionID = current
		h.allRevoker.deny = true // current must survive → the all-sessions seam may never fire

		w := postChangePassword(h.router, map[string]string{
			"current_password": "correct-current-password",
			"new_password":     "Perfectly-Fine-New-Pw-1!",
		})
		if w.Code != http.StatusNoContent {
			t.Fatalf("status = %d, want 204; body %s", w.Code, w.Body.String())
		}
		// The hijacked session must be DEAD, with the R2 reason stamped.
		o := h.sessionRepo.byID[other]
		if o.IsValid || o.RevokedAt == nil {
			t.Fatal("R2: the OTHER pre-existing session must be revoked after a password change")
		}
		if o.RevokedReason == nil || *o.RevokedReason != "password_changed" {
			t.Fatalf("the other session must carry the password_changed revocation reason; got %v", o.RevokedReason)
		}
		// The CHANGING session must still work.
		cur := h.sessionRepo.byID[current]
		if !cur.IsValid || cur.RevokedAt != nil {
			t.Fatal("R2: the session making the change must STAY VALID")
		}
		// OAuth refresh tokens: the fan-out must fire exactly once.
		if h.refresh.calls != 1 {
			t.Fatalf("refresh-token revocation must fire exactly once; got %d", h.refresh.calls)
		}
	})

	t.Run("session-less principal (pure token) revokes ALL sessions via the seam", func(t *testing.T) {
		principal := &domain.Principal{UserID: uid, OrganizationID: uuid.New()} // SessionID == Nil
		h := newChangePwHarness(t, principal, changePwUser(uid))
		h.allRevoker.deny = false
		w := postChangePassword(h.router, map[string]string{
			"current_password": "correct-current-password",
			"new_password":     "Perfectly-Fine-New-Pw-1!",
		})
		if w.Code != http.StatusNoContent {
			t.Fatalf("status = %d, want 204; body %s", w.Code, w.Body.String())
		}
		if h.allRevoker.calls != 1 {
			t.Fatalf("a session-less principal must revoke ALL sessions via the seam; calls=%d", h.allRevoker.calls)
		}
		if h.refresh.calls != 1 {
			t.Fatalf("refresh-token revocation must fire exactly once; got %d", h.refresh.calls)
		}
	})
}
