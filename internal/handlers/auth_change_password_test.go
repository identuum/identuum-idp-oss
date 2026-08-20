package handlers

// Unit coverage for POST /api/v1/auth/change-password
// (THE-V036-PASSWORD / CHANGE-PASSWORD-1). Hermetic: gin + the in-package
// user-repo stub; no Postgres, no network.
//
// R2 NOTE (owner ruling DECIDE-LATER, 2026-08-20): a password change
// deliberately revokes NOTHING — no sessions, no refresh tokens. The
// success case below asserts that structurally with spy revokers that
// fail the test if the handler ever calls them. When R2 is decided, its
// revocation behavior (and rule) lands as its own slice.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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

// spyRevoker fails the test if the change-password path ever revokes —
// the structural R2 assertion.
type spyRevoker struct{ t *testing.T }

func (s spyRevoker) RevokeUserSessions(context.Context, uuid.UUID, string, map[string]any) error {
	s.t.Error("R2 is PARKED: change-password must NOT revoke sessions")
	return nil
}

type spyRefreshRevoker struct{ t *testing.T }

func (s spyRefreshRevoker) RevokeAllForUser(context.Context, uuid.UUID) (int64, error) {
	s.t.Error("R2 is PARKED: change-password must NOT revoke refresh tokens")
	return 0, nil
}

func newChangePwHarness(t *testing.T, principal *domain.Principal, user *domain.User) (*gin.Engine, *changePwStubRepo) {
	t.Helper()
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	if principal != nil {
		r.Use(mw.InjectPrincipalForTest(principal))
	}
	repo := &changePwStubRepo{recoveryStubUserRepo: newRecoveryStubUserRepo(), user: user}
	RegisterAuthSessionRoutes(r, AuthSessionsHandlerDeps{
		ChangePassword:      service.NewChangePasswordService(repo, 0),
		SessionRevoker:      spyRevoker{t},
		RefreshTokenRevoker: spyRefreshRevoker{t},
	})
	return r, repo
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

	t.Run("wrong current password → 403 opaque, hash untouched", func(t *testing.T) {
		r, repo := newChangePwHarness(t, &domain.Principal{UserID: uid}, changePwUser(uid))
		w := postChangePassword(r, map[string]string{
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
		if len(repo.updates) != 0 || repo.user.PasswordHash != "HASH-CURRENT-PASSWORD" {
			t.Fatal("a refused change must not touch the stored hash")
		}
	})

	t.Run("policy violation → 400 weak_password with displayable message, hash untouched", func(t *testing.T) {
		r, repo := newChangePwHarness(t, &domain.Principal{UserID: uid}, changePwUser(uid))
		w := postChangePassword(r, map[string]string{
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
		if len(repo.updates) != 0 {
			t.Fatal("a refused change must not touch the stored hash")
		}
	})

	t.Run("federated (non-local) account → the SAME opaque 403", func(t *testing.T) {
		u := changePwUser(uid)
		u.AuthSource = "oidc"
		r, repo := newChangePwHarness(t, &domain.Principal{UserID: uid}, u)
		w := postChangePassword(r, map[string]string{
			"current_password": "correct-current-password",
			"new_password":     "Perfectly-Fine-New-Pw-1!",
		})
		if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "invalid_current_password") {
			t.Fatalf("federated accounts must collapse into the opaque 403; got %d %s", w.Code, w.Body.String())
		}
		if len(repo.updates) != 0 {
			t.Fatal("a refused change must not touch the stored hash")
		}
	})

	t.Run("no principal → 401 (RequireAuthenticated)", func(t *testing.T) {
		r, _ := newChangePwHarness(t, nil, changePwUser(uid))
		w := postChangePassword(r, map[string]string{
			"current_password": "correct-current-password",
			"new_password":     "Perfectly-Fine-New-Pw-1!",
		})
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", w.Code)
		}
	})

	t.Run("success → 204 empty body, hash rotated, NO revocation (R2 parked)", func(t *testing.T) {
		r, repo := newChangePwHarness(t, &domain.Principal{UserID: uid, OrganizationID: uuid.New()}, changePwUser(uid))
		w := postChangePassword(r, map[string]string{
			"current_password": "correct-current-password",
			"new_password":     "Perfectly-Fine-New-Pw-1!",
		})
		if w.Code != http.StatusNoContent {
			t.Fatalf("status = %d, want 204; body %s", w.Code, w.Body.String())
		}
		if w.Body.Len() != 0 {
			t.Fatalf("success body must be empty; got %q", w.Body.String())
		}
		if len(repo.updates) != 1 || repo.updates[0].Password == nil {
			t.Fatalf("exactly one hash update expected; got %+v", repo.updates)
		}
		if repo.user.PasswordHash != "$argon2id$hashed:Perfectly-Fine-New-Pw-1!" {
			t.Fatalf("stored hash must be the NEW hash; got %q", repo.user.PasswordHash)
		}
		// Only Password may be set on the update — no role/email/MFA side
		// effects can ride along on a password change.
		u := repo.updates[0]
		if u.Email != nil || u.Role != nil || u.Banned != nil || u.MFAEnabled != nil || u.MFASecret != nil {
			t.Fatalf("the update must carry ONLY the password hash; got %+v", u)
		}
		// The spy revokers fail the test on any call — reaching here with a
		// 204 proves neither sessions nor refresh tokens were touched (R2).
	})
}
