package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/mw"
	"github.com/identuum/identuum-idp-oss/internal/repository"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// recoveryStubUserRepo is the minimal UserRepository the
// MFAEnrollmentService touches on the regenerate path
// (GetByID + Update). Unused methods panic so accidental
// dispatch surfaces as a test failure.
type recoveryStubUserRepo struct {
	mu                  sync.Mutex
	byID                map[uuid.UUID]*domain.User
	calls               int
	verifyPasswordCalls int
}

func newRecoveryStubUserRepo() *recoveryStubUserRepo {
	return &recoveryStubUserRepo{byID: map[uuid.UUID]*domain.User{}}
}

func (r *recoveryStubUserRepo) GetByID(_ context.Context, id uuid.UUID) (*domain.User, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	u, ok := r.byID[id]
	if !ok {
		return nil, nil
	}
	cp := *u
	if u.MFASecret != nil {
		s := *u.MFASecret
		cp.MFASecret = &s
	}
	if len(u.MFARecoveryCodes) > 0 {
		cp.MFARecoveryCodes = append([]string(nil), u.MFARecoveryCodes...)
	}
	return &cp, nil
}

func (r *recoveryStubUserRepo) Update(_ context.Context, id uuid.UUID, _ uuid.UUID, opts repository.UpdateUserOptions) (*domain.User, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	u, ok := r.byID[id]
	if !ok {
		return nil, nil
	}
	if opts.MFAEnabled != nil {
		u.MFAEnabled = *opts.MFAEnabled
	}
	if opts.MFASecret != nil {
		s := *opts.MFASecret
		u.MFASecret = &s
	}
	if opts.MFARecoveryCodes != nil {
		u.MFARecoveryCodes = append([]string(nil), opts.MFARecoveryCodes...)
	}
	cp := *u
	return &cp, nil
}

func (r *recoveryStubUserRepo) ConsumeRecoveryCode(_ context.Context, id uuid.UUID, codeHash string) (*domain.User, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	u, ok := r.byID[id]
	if !ok {
		return nil, false, nil
	}
	for i, h := range u.MFARecoveryCodes {
		if h == codeHash {
			u.MFARecoveryCodes = append(u.MFARecoveryCodes[:i], u.MFARecoveryCodes[i+1:]...)
			cp := *u
			return &cp, true, nil
		}
	}
	return nil, false, nil
}

func (r *recoveryStubUserRepo) Create(context.Context, *domain.User) (*domain.User, error) {
	panic("recoveryStubUserRepo.Create not expected")
}
func (r *recoveryStubUserRepo) FindUsersByEmail(context.Context, string) ([]*domain.User, error) {
	panic("recoveryStubUserRepo.FindUsersByEmail not expected")
}
func (r *recoveryStubUserRepo) GetByEmailAndOrgID(context.Context, uuid.UUID, string) (*domain.User, error) {
	panic("recoveryStubUserRepo.GetByEmailAndOrgID not expected")
}
func (r *recoveryStubUserRepo) GetByExternalID(context.Context, uuid.UUID, string) (*domain.User, error) {
	panic("recoveryStubUserRepo.GetByExternalID not expected")
}
func (r *recoveryStubUserRepo) GetByIDWithOrg(context.Context, uuid.UUID) (*domain.User, error) {
	panic("recoveryStubUserRepo.GetByIDWithOrg not expected")
}
func (r *recoveryStubUserRepo) Delete(context.Context, uuid.UUID, uuid.UUID) error {
	panic("recoveryStubUserRepo.Delete not expected")
}
func (r *recoveryStubUserRepo) Undelete(context.Context, uuid.UUID, uuid.UUID) error {
	panic("recoveryStubUserRepo.Undelete not expected")
}
func (r *recoveryStubUserRepo) List(context.Context, repository.ListUserOptions) ([]*domain.User, int, error) {
	panic("recoveryStubUserRepo.List not expected")
}
func (r *recoveryStubUserRepo) ListByOrganization(context.Context, uuid.UUID, repository.ListUserOptions) ([]*domain.User, int, error) {
	panic("recoveryStubUserRepo.ListByOrganization not expected")
}
func (r *recoveryStubUserRepo) UpdateLastLogin(context.Context, uuid.UUID) error {
	panic("recoveryStubUserRepo.UpdateLastLogin not expected")
}
func (r *recoveryStubUserRepo) CountByOrganization(context.Context, uuid.UUID) (int, error) {
	panic("recoveryStubUserRepo.CountByOrganization not expected")
}
func (r *recoveryStubUserRepo) CountOrgAdminsByOrganization(context.Context, uuid.UUID) (int, error) {
	panic("recoveryStubUserRepo.CountOrgAdminsByOrganization not expected")
}
func (r *recoveryStubUserRepo) CountOrgAdminsByOrganizations(context.Context, []uuid.UUID) (map[uuid.UUID]int, error) {
	panic("recoveryStubUserRepo.CountOrgAdminsByOrganizations not expected")
}
func (r *recoveryStubUserRepo) CountVerifiedOrgAdminsByOrganization(context.Context, uuid.UUID) (int, error) {
	panic("recoveryStubUserRepo.CountVerifiedOrgAdminsByOrganization not expected")
}
func (r *recoveryStubUserRepo) CountVerifiedOrgAdminsByOrganizations(context.Context, []uuid.UUID) (map[uuid.UUID]int, error) {
	panic("recoveryStubUserRepo.CountVerifiedOrgAdminsByOrganizations not expected")
}
func (r *recoveryStubUserRepo) VerifyPassword(_ context.Context, password, hash string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.verifyPasswordCalls++
	if password == "correct-current-password" && hash == "HASH-CURRENT-PASSWORD" {
		return nil
	}
	return errors.New("invalid password")
}
func (r *recoveryStubUserRepo) HashPassword(string) (string, error) {
	panic("recoveryStubUserRepo.HashPassword not expected")
}
func (r *recoveryStubUserRepo) GetUserOrganization(context.Context, uuid.UUID) (*domain.Organization, error) {
	panic("recoveryStubUserRepo.GetUserOrganization not expected")
}
func (r *recoveryStubUserRepo) UpdateOrganizationID(context.Context, uuid.UUID, uuid.UUID) error {
	panic("recoveryStubUserRepo.UpdateOrganizationID not expected")
}

var _ repository.UserRepository = (*recoveryStubUserRepo)(nil)

// recoveryPendingRepoStub stubs the MFAPendingLoginSessionRepository
// dependency required by NewMFAEnrollmentService. The regenerate
// flow never touches it.
type recoveryPendingRepoStub struct{}

func (recoveryPendingRepoStub) Create(_ context.Context, row *domain.MFAPendingLoginSession) (*domain.MFAPendingLoginSession, error) {
	cp := *row
	return &cp, nil
}
func (recoveryPendingRepoStub) GetByID(context.Context, uuid.UUID) (*domain.MFAPendingLoginSession, error) {
	return nil, repository.ErrMFAPendingSessionNotFound
}
func (recoveryPendingRepoStub) UpdateSecret(context.Context, uuid.UUID, string, []string) error {
	return nil
}
func (recoveryPendingRepoStub) MarkConsumed(context.Context, uuid.UUID, time.Time) (bool, error) {
	return false, nil
}
func (recoveryPendingRepoStub) RecordFailedVerifyAttempt(context.Context, uuid.UUID, int, time.Time) (bool, error) {
	return false, nil
}
func (recoveryPendingRepoStub) DeleteExpired(context.Context) (int64, error) {
	return 0, nil
}

// recoveryTestEngine wires the smallest deps needed to mount the
// new POST /api/v1/me/mfa/recovery-codes/regenerate route. The
// principal (when non-nil) is injected BEFORE the route group's
// RequireAuthenticated middleware so unauthenticated cases can
// still be exercised.
type recoveryTestEngine struct {
	r        *gin.Engine
	userRepo *recoveryStubUserRepo
	rec      *audit.Recorder
}

func newRecoveryEngine(t *testing.T, principal *domain.Principal) recoveryTestEngine {
	t.Helper()
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	if principal != nil {
		r.Use(mw.InjectPrincipalForTest(principal))
	}
	userRepo := newRecoveryStubUserRepo()
	mfaSvc := service.NewMFAEnrollmentService(nil, service.MFAEnrollmentRepoOptions{
		Pending: recoveryPendingRepoStub{},
		Users:   userRepo,
		Issuer:  "Identuum",
		Cipher:  identityMFACipher{},
	}, service.MFAEnrollmentServiceOptions{})
	rec := &audit.Recorder{}
	RegisterAuthSessionRoutes(r, AuthSessionsHandlerDeps{
		MFAEnrollment: mfaSvc,
		Audit:         rec,
	})
	return recoveryTestEngine{r: r, userRepo: userRepo, rec: rec}
}

func recoveryReq(t *testing.T, eng recoveryTestEngine) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/me/mfa/recovery-codes/regenerate", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	eng.r.ServeHTTP(w, req)
	return w
}

func seedRecoveryUser(eng recoveryTestEngine, id uuid.UUID, mfaEnabled bool) *domain.User {
	secret := "PRESERVED-SECRET-LITERAL"
	u := &domain.User{
		ID:               id,
		OrganizationID:   uuid.New(),
		Email:            "self@example.com",
		Role:             domain.RoleOrgUser,
		AuthSource:       domain.AuthSourceLocal,
		EmailVerified:    true,
		MFAEnabled:       mfaEnabled,
		MFASecret:        &secret,
		MFARecoveryCodes: []string{"OLD-CODE-A", "OLD-CODE-B", "OLD-CODE-C"},
	}
	eng.userRepo.byID[id] = u
	return u
}

// ---------- Tests ----------

func TestMFARecoveryCodesRegenerate_Unauthenticated401(t *testing.T) {
	eng := newRecoveryEngine(t, nil)
	w := recoveryReq(t, eng)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d; want 401", w.Code)
	}
}

func TestMFARecoveryCodesRegenerate_NotEnrolledReturns400(t *testing.T) {
	uid := uuid.New()
	eng := newRecoveryEngine(t, &domain.Principal{UserID: uid, Role: domain.RoleOrgUser})
	seedRecoveryUser(eng, uid, false /* MFAEnabled */)
	w := recoveryReq(t, eng)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d; want 400", w.Code)
	}
	if want := `"error":"mfa_not_enrolled"`; !strings.Contains(w.Body.String(), want) {
		t.Errorf("body = %q; want %q", w.Body.String(), want)
	}
	if eng.userRepo.calls != 0 {
		t.Errorf("repo Update called %d times; want 0 (rejection must not mutate)", eng.userRepo.calls)
	}
}

func TestMFARecoveryCodesRegenerate_HappyPath(t *testing.T) {
	uid := uuid.New()
	eng := newRecoveryEngine(t, &domain.Principal{UserID: uid, Role: domain.RoleOrgUser})
	original := seedRecoveryUser(eng, uid, true /* MFAEnabled */)
	w := recoveryReq(t, eng)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%q", w.Code, w.Body.String())
	}
	// Cache-Control header must steer intermediaries away from
	// retaining the body.
	if got := w.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q; want no-store", got)
	}
	if got := w.Header().Get("Pragma"); got != "no-cache" {
		t.Errorf("Pragma = %q; want no-cache", got)
	}
	var resp struct {
		RecoveryCodes []string `json:"recovery_codes"`
		Count         int      `json:"count"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Count != len(resp.RecoveryCodes) {
		t.Errorf("count = %d; want %d (matches slice length)", resp.Count, len(resp.RecoveryCodes))
	}
	if resp.Count != 10 {
		t.Errorf("count = %d; want 10 (default enrolment count)", resp.Count)
	}
	for i, c := range resp.RecoveryCodes {
		if c == "" {
			t.Errorf("returned code %d is empty", i)
		}
	}
	// Persisted row carries the same codes as returned.
	stored := eng.userRepo.byID[uid]
	if len(stored.MFARecoveryCodes) != len(resp.RecoveryCodes) {
		t.Errorf("persisted count = %d; want %d", len(stored.MFARecoveryCodes), len(resp.RecoveryCodes))
	}
	wantHashes := hashCodesForTest(resp.RecoveryCodes)
	for i := range resp.RecoveryCodes {
		// Persisted codes are SHA-256 hashes of the returned plaintext.
		if stored.MFARecoveryCodes[i] != wantHashes[i] {
			t.Errorf("persisted[%d] is not the hash of the returned code", i)
		}
	}
	// Old codes must NOT survive.
	for _, old := range []string{"OLD-CODE-A", "OLD-CODE-B", "OLD-CODE-C"} {
		if strings.Contains(w.Body.String(), old) {
			t.Errorf("response leaked old code %q", old)
		}
		for _, c := range stored.MFARecoveryCodes {
			if c == old {
				t.Errorf("old code %q survived regeneration", old)
			}
		}
	}
	// MFAEnabled + MFASecret preserved.
	if !stored.MFAEnabled {
		t.Error("MFAEnabled flipped off by regeneration")
	}
	if stored.MFASecret == nil || *stored.MFASecret != "PRESERVED-SECRET-LITERAL" {
		t.Errorf("MFASecret mutated by regeneration: %v", stored.MFASecret)
	}
	// Response body MUST NOT carry MFASecret or the literal field
	// name.
	body := w.Body.String()
	if strings.Contains(body, "PRESERVED-SECRET-LITERAL") {
		t.Errorf("response leaked MFASecret: %q", body)
	}
	if strings.Contains(body, "mfa_secret") {
		t.Errorf("response leaked mfa_secret field name: %q", body)
	}
	// Audit event must fire with count only.
	var matched int
	for _, e := range eng.rec.Events() {
		if e.Action != "user_session.mfa.recovery_codes_regenerated" {
			continue
		}
		matched++
		if got, _ := e.Metadata["user_id"].(string); got != uid.String() {
			t.Errorf("audit user_id = %q; want %q", got, uid.String())
		}
		gotCount, _ := e.Metadata["recovery_codes_count"].(int)
		if gotCount != resp.Count {
			t.Errorf("audit count = %d; want %d", gotCount, resp.Count)
		}
		// Audit must NOT carry any returned code.
		for _, code := range resp.RecoveryCodes {
			for _, v := range e.Metadata {
				if s, ok := v.(string); ok && strings.Contains(s, code) {
					t.Errorf("audit metadata leaked recovery code: %q", s)
				}
			}
		}
		// Audit must NOT carry old codes either.
		for _, old := range original.MFARecoveryCodes {
			for _, v := range e.Metadata {
				if s, ok := v.(string); ok && strings.Contains(s, old) {
					t.Errorf("audit metadata leaked old code: %q", s)
				}
			}
		}
	}
	if matched == 0 {
		t.Errorf("missing user_session.mfa.recovery_codes_regenerated audit event")
	}
}

func TestMFARecoveryCodesRegenerate_OnlyAuthenticatedUserCodesAffected(t *testing.T) {
	uid := uuid.New()
	other := uuid.New()
	eng := newRecoveryEngine(t, &domain.Principal{UserID: uid, Role: domain.RoleOrgUser})
	seedRecoveryUser(eng, uid, true)
	otherSecret := "OTHER-SECRET"
	otherCodes := []string{"OTHER-1", "OTHER-2"}
	eng.userRepo.byID[other] = &domain.User{
		ID:               other,
		OrganizationID:   uuid.New(),
		Email:            "other@example.com",
		MFAEnabled:       true,
		MFASecret:        &otherSecret,
		MFARecoveryCodes: append([]string(nil), otherCodes...),
	}
	w := recoveryReq(t, eng)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	// Other user's row is completely unchanged — proves the route
	// cannot be steered at another principal's codes.
	stored := eng.userRepo.byID[other]
	if !stored.MFAEnabled {
		t.Error("other user MFAEnabled mutated")
	}
	if stored.MFASecret == nil || *stored.MFASecret != "OTHER-SECRET" {
		t.Errorf("other user MFASecret mutated: %v", stored.MFASecret)
	}
	if len(stored.MFARecoveryCodes) != len(otherCodes) {
		t.Errorf("other user code count changed: %d → %d", len(otherCodes), len(stored.MFARecoveryCodes))
	}
	for i, want := range otherCodes {
		if stored.MFARecoveryCodes[i] != want {
			t.Errorf("other user code[%d] = %q; want %q", i, stored.MFARecoveryCodes[i], want)
		}
	}
}

func TestMFARecoveryCodesRegenerate_SecondCallReplacesFirst(t *testing.T) {
	uid := uuid.New()
	eng := newRecoveryEngine(t, &domain.Principal{UserID: uid, Role: domain.RoleOrgUser})
	seedRecoveryUser(eng, uid, true)
	first := recoveryReq(t, eng)
	if first.Code != http.StatusOK {
		t.Fatalf("first status = %d", first.Code)
	}
	var firstResp struct {
		RecoveryCodes []string `json:"recovery_codes"`
	}
	_ = json.Unmarshal(first.Body.Bytes(), &firstResp)

	second := recoveryReq(t, eng)
	if second.Code != http.StatusOK {
		t.Fatalf("second status = %d", second.Code)
	}
	// First-set codes must be entirely absent from persisted
	// state after the second regenerate.
	stored := eng.userRepo.byID[uid]
	for _, old := range firstResp.RecoveryCodes {
		for _, c := range stored.MFARecoveryCodes {
			if c == old {
				t.Errorf("first-set code %q survived second regenerate", old)
			}
		}
	}
}

func TestMFARecoveryCodesRegenerate_BannedUserRejected(t *testing.T) {
	uid := uuid.New()
	eng := newRecoveryEngine(t, &domain.Principal{UserID: uid, Role: domain.RoleOrgUser})
	u := seedRecoveryUser(eng, uid, true)
	u.Banned = true
	eng.userRepo.byID[uid] = u
	w := recoveryReq(t, eng)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d; want 401 (banned principal collapses to opaque)", w.Code)
	}
	if eng.userRepo.calls != 0 {
		t.Errorf("repo Update called %d times despite banned; want 0", eng.userRepo.calls)
	}
}

func TestMFARecoveryCodesRegenerate_StalePrincipalRejected(t *testing.T) {
	// Principal references a UUID that has no user row; the
	// service collapses this to ErrMFAEnrollmentInvalid and the
	// handler maps it to 401.
	eng := newRecoveryEngine(t, &domain.Principal{UserID: uuid.New(), Role: domain.RoleOrgUser})
	w := recoveryReq(t, eng)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d; want 401 (stale principal)", w.Code)
	}
	if eng.userRepo.calls != 0 {
		t.Errorf("repo Update called %d times on stale principal; want 0", eng.userRepo.calls)
	}
}
