package handlers

import (
	"bytes"
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

// memUserRepo
type memUserRepo struct {
	mu   sync.Mutex
	rows map[uuid.UUID]*domain.User
}

func newMemUserRepo() *memUserRepo { return &memUserRepo{rows: map[uuid.UUID]*domain.User{}} }

func (r *memUserRepo) Create(_ context.Context, u *domain.User) (*domain.User, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rows[u.ID] = u
	return u, nil
}
func (r *memUserRepo) GetByID(_ context.Context, id uuid.UUID) (*domain.User, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.rows[id], nil
}
func (r *memUserRepo) FindUsersByEmail(_ context.Context, _ string) ([]*domain.User, error) {
	panic("not used")
}
func (r *memUserRepo) GetByEmailAndOrgID(_ context.Context, _ uuid.UUID, _ string) (*domain.User, error) {
	panic("not used")
}
func (r *memUserRepo) GetByExternalID(_ context.Context, _ uuid.UUID, _ string) (*domain.User, error) {
	panic("not used")
}
func (r *memUserRepo) GetByIDWithOrg(_ context.Context, _ uuid.UUID) (*domain.User, error) {
	panic("not used")
}
func (r *memUserRepo) Update(_ context.Context, id, _ uuid.UUID, opts repository.UpdateUserOptions) (*domain.User, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	u, ok := r.rows[id]
	if !ok {
		return nil, nil
	}
	if opts.Banned != nil {
		u.Banned = *opts.Banned
	}
	if opts.Password != nil {
		u.PasswordHash = *opts.Password
	}
	if opts.Email != nil {
		u.Email = *opts.Email
	}
	if opts.Name != nil {
		n := *opts.Name
		u.Name = &n
	}
	if opts.Role != nil {
		u.Role = *opts.Role
	}
	if opts.EmailVerified != nil {
		u.EmailVerified = *opts.EmailVerified
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
	return u, nil
}
func (r *memUserRepo) Delete(_ context.Context, id, _ uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.rows, id)
	return nil
}
func (r *memUserRepo) Undelete(_ context.Context, _, _ uuid.UUID) error { return nil }
func (r *memUserRepo) List(_ context.Context, _ repository.ListUserOptions) ([]*domain.User, int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*domain.User, 0, len(r.rows))
	for _, v := range r.rows {
		out = append(out, v)
	}
	return out, len(out), nil
}
func (r *memUserRepo) ListByOrganization(_ context.Context, orgID uuid.UUID, _ repository.ListUserOptions) ([]*domain.User, int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*domain.User, 0, len(r.rows))
	for _, v := range r.rows {
		if v.OrganizationID == orgID {
			out = append(out, v)
		}
	}
	return out, len(out), nil
}
func (r *memUserRepo) UpdateLastLogin(_ context.Context, _ uuid.UUID) error { return nil }
func (r *memUserRepo) ConsumeRecoveryCode(context.Context, uuid.UUID, string) (*domain.User, bool, error) {
	return nil, false, nil
}
func (r *memUserRepo) CountByOrganization(_ context.Context, _ uuid.UUID) (int, error) {
	return 0, nil
}
func (r *memUserRepo) CountOrgAdminsByOrganization(_ context.Context, _ uuid.UUID) (int, error) {
	return 0, nil
}
func (r *memUserRepo) CountOrgAdminsByOrganizations(_ context.Context, _ []uuid.UUID) (map[uuid.UUID]int, error) {
	return map[uuid.UUID]int{}, nil
}
func (r *memUserRepo) CountVerifiedOrgAdminsByOrganization(_ context.Context, _ uuid.UUID) (int, error) {
	return 0, nil
}
func (r *memUserRepo) CountVerifiedOrgAdminsByOrganizations(_ context.Context, _ []uuid.UUID) (map[uuid.UUID]int, error) {
	return map[uuid.UUID]int{}, nil
}
func (r *memUserRepo) VerifyPassword(_ context.Context, _, _ string) error { return nil }
func (r *memUserRepo) HashPassword(p string) (string, error)               { return "hashed:" + p, nil }
func (r *memUserRepo) GetUserOrganization(_ context.Context, _ uuid.UUID) (*domain.Organization, error) {
	panic("not used")
}
func (r *memUserRepo) UpdateOrganizationID(_ context.Context, _, _ uuid.UUID) error { return nil }

// memOrgRepo
type memOrgRepo struct {
	mu   sync.Mutex
	rows map[uuid.UUID]*domain.Organization
}

func newMemOrgRepo() *memOrgRepo { return &memOrgRepo{rows: map[uuid.UUID]*domain.Organization{}} }

func (r *memOrgRepo) Create(_ context.Context, o *domain.Organization) (*domain.Organization, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rows[o.ID] = o
	return o, nil
}
func (r *memOrgRepo) CreateWithAdmin(_ context.Context, _ *domain.Organization, _ *domain.User) (*domain.Organization, *domain.User, error) {
	panic("not used")
}
func (r *memOrgRepo) GetByID(_ context.Context, id uuid.UUID) (*domain.Organization, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if o := r.rows[id]; o != nil && o.DeletedAt == nil {
		return o, nil
	}
	return nil, nil
}
func (r *memOrgRepo) GetByDomain(_ context.Context, _ string) (*domain.Organization, error) {
	panic("not used")
}
func (r *memOrgRepo) GetBySlug(_ context.Context, _ string) (*domain.Organization, error) {
	panic("not used")
}
func (r *memOrgRepo) Update(_ context.Context, id uuid.UUID, opts repository.UpdateOrganizationOptions) (*domain.Organization, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	o, ok := r.rows[id]
	if !ok {
		return nil, nil
	}
	if opts.Name != nil {
		o.Name = *opts.Name
	}
	if opts.Active != nil {
		o.Active = *opts.Active
	}
	return o, nil
}

// Delete/Undelete mirror the REAL repository's soft-delete semantics: the
// row survives with DeletedAt set (reads filter it), and Undelete clears the
// marker. The previous fake hard-deleted and no-op'd Undelete, which made
// the restore path untestable through this engine.
func (r *memOrgRepo) Delete(_ context.Context, id uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if o, ok := r.rows[id]; ok {
		now := time.Now()
		o.DeletedAt = &now
	}
	return nil
}
func (r *memOrgRepo) Undelete(_ context.Context, id uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if o, ok := r.rows[id]; ok {
		o.DeletedAt = nil
	}
	return nil
}
func (r *memOrgRepo) List(_ context.Context, _ repository.OrganizationFilter, _ repository.Pagination, _ repository.Sort) ([]*domain.Organization, int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*domain.Organization, 0, len(r.rows))
	for _, v := range r.rows {
		out = append(out, v)
	}
	return out, len(out), nil
}
func (r *memOrgRepo) CountUsers(_ context.Context, _ uuid.UUID) (int, error)    { return 0, nil }
func (r *memOrgRepo) CountSessions(_ context.Context, _ uuid.UUID) (int, error) { return 0, nil }
func (r *memOrgRepo) GetDetails(_ context.Context, _ uuid.UUID) (*domain.Organization, map[string]int, error) {
	return nil, nil, nil
}

// memOrgDomainRepo
type memOrgDomainRepo struct {
	mu   sync.Mutex
	rows map[uuid.UUID]*domain.OrganizationDomain
}

func newMemOrgDomainRepo() *memOrgDomainRepo {
	return &memOrgDomainRepo{rows: map[uuid.UUID]*domain.OrganizationDomain{}}
}

func (r *memOrgDomainRepo) CreateOrganizationDomain(_ context.Context, d *domain.OrganizationDomain) (*domain.OrganizationDomain, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rows[d.ID] = d
	return d, nil
}
func (r *memOrgDomainRepo) GetOrganizationDomainByID(_ context.Context, id uuid.UUID) (*domain.OrganizationDomain, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.rows[id], nil
}
func (r *memOrgDomainRepo) ListOrganizationDomainsByOrganization(_ context.Context, orgID uuid.UUID) ([]*domain.OrganizationDomain, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*domain.OrganizationDomain, 0)
	for _, v := range r.rows {
		if v.OrganizationID == orgID {
			out = append(out, v)
		}
	}
	return out, nil
}
func (r *memOrgDomainRepo) GetVerifiedOrganizationDomainByDomain(_ context.Context, _ string) (*domain.OrganizationDomain, error) {
	return nil, nil
}
func (r *memOrgDomainRepo) SetOrganizationDomainVerified(_ context.Context, id uuid.UUID, at time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if v, ok := r.rows[id]; ok {
		v.VerifiedAt = &at
		v.VerificationTokenHash = nil
		v.VerificationTokenExpiresAt = nil
	}
	return nil
}
func (r *memOrgDomainRepo) IncrementOrganizationDomainVerificationAttempts(_ context.Context, _, _ uuid.UUID) error {
	return nil
}
func (r *memOrgDomainRepo) DeleteOrganizationDomain(_ context.Context, id, _ uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.rows, id)
	return nil
}
func (r *memOrgDomainRepo) SetPrimaryOrganizationDomain(_ context.Context, id, _ uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, v := range r.rows {
		v.IsPrimary = false
	}
	if v, ok := r.rows[id]; ok {
		v.IsPrimary = true
	}
	return nil
}

type stubVerifier struct{ err error }

func (s stubVerifier) Verify(_ context.Context, _, _ string) error { return s.err }

// identityEngine wires the three identity-admin groups with services.
type identityEngine struct {
	r              *gin.Engine
	userRepo       *memUserRepo
	orgRepo        *memOrgRepo
	domainRepo     *memOrgDomainRepo
	rec            *audit.Recorder
	revoker        *service.RecorderSessionRevoker
	refreshRevoker *service.RecorderRefreshTokenRevoker
}

func newIdentityEngine(t *testing.T, principal *domain.Principal, verifier service.DomainProofVerifier) identityEngine {
	t.Helper()
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	if principal != nil {
		r.Use(mw.InjectPrincipalForTest(principal))
	}
	userRepo := newMemUserRepo()
	orgRepo := newMemOrgRepo()
	domainRepo := newMemOrgDomainRepo()
	rec := &audit.Recorder{}
	revoker := &service.RecorderSessionRevoker{}
	refreshRevoker := &service.RecorderRefreshTokenRevoker{}
	RegisterUsersRoutes(r, UsersHandlerDeps{
		UserService:         service.NewUserService(nil, userRepo),
		Audit:               rec,
		SessionRevoker:      revoker,
		RefreshTokenRevoker: refreshRevoker,
	})
	RegisterOrganizationsRoutes(r, OrganizationsHandlerDeps{
		OrganizationService: service.NewOrganizationService(nil, orgRepo),
		Audit:               rec,
	})
	RegisterOrganizationDomainsRoutes(r, OrganizationDomainsHandlerDeps{
		OrganizationDomainService: service.NewOrganizationDomainService(nil, domainRepo, verifier),
		Audit:                     rec,
	})
	return identityEngine{r: r, userRepo: userRepo, orgRepo: orgRepo, domainRepo: domainRepo, rec: rec, revoker: revoker, refreshRevoker: refreshRevoker}
}

func doIdentityJSON(t *testing.T, eng identityEngine, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatalf("encode: %v", err)
		}
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	eng.r.ServeHTTP(rec, req)
	return rec
}

// ---------- Users ----------

func TestUsers_RoutesAbsentWithoutDeps(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	// No RegisterUsersRoutes call.
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/users", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

func TestUsers_Unauthenticated401(t *testing.T) {
	eng := newIdentityEngine(t, nil, nil)
	rec := doIdentityJSON(t, eng, http.MethodGet, "/api/v1/users", nil)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestUsers_NonSiteAdmin403(t *testing.T) {
	eng := newIdentityEngine(t, &domain.Principal{
		UserID: uuid.New(),
		Role:   domain.RoleOrgAdmin,
	}, nil)
	rec := doIdentityJSON(t, eng, http.MethodGet, "/api/v1/users", nil)
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
}

func TestUsers_CreateAndListOmitSensitive(t *testing.T) {
	eng := newIdentityEngine(t, siteAdminPrincipal(), nil)
	// role org_admin, not org_user: SITE-ADMIN-TENANT-WRITE forbids site_admin
	// creating a plain org_user inside a tenant. This test is about the SAFE
	// PROJECTION (no plaintext password, no hash in the body), which the
	// permitted first-org_admin delegation exercises identically.
	rec := doIdentityJSON(t, eng, http.MethodPost, "/api/v1/users", map[string]any{
		"organization_id": uuid.New().String(),
		"email":           "u@example.com",
		"password":        "Password-Sentinel-Must-Not-Leak-1!",
		"role":            "org_admin",
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status = %d; body=%q", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "Password-Sentinel-Must-Not-Leak-1!") {
		t.Errorf("response leaked plaintext password")
	}
	if strings.Contains(rec.Body.String(), "password_hash") {
		t.Errorf("response leaked password_hash field name")
	}
	// LIST
	list := doIdentityJSON(t, eng, http.MethodGet, "/api/v1/users", nil)
	if list.Code != http.StatusOK {
		t.Fatalf("list status = %d", list.Code)
	}
	if strings.Contains(list.Body.String(), "password_hash") || strings.Contains(list.Body.String(), "mfa_secret") || strings.Contains(list.Body.String(), "activation_token") {
		t.Errorf("list leaked sensitive field name: %q", list.Body.String())
	}
	// AUDIT
	var found bool
	for _, e := range eng.rec.Events() {
		if e.Action == "user.created" {
			found = true
			for _, v := range e.Metadata {
				if s, ok := v.(string); ok && s == "Password-Sentinel-Must-Not-Leak-1!" {
					t.Errorf("audit metadata contains plaintext password")
				}
			}
		}
	}
	if !found {
		t.Errorf("missing user.created audit event")
	}
}

// TestUsers_NoDeferredRoutesRemain pins that OSS no longer has any
// deferred (501) user route. bulk-create — the last one — was implemented
// (synchronous best-effort; see user_bulk_create.go +
// user_bulk_create_test.go), and approve was implemented earlier. A
// site_admin POST /users/bulk with an empty body is now HANDLED (400 from
// the batch-size guard), never the old 501 stub.
func TestUsers_NoDeferredRoutesRemain(t *testing.T) {
	eng := newIdentityEngine(t, siteAdminPrincipal(), nil)
	rec := doIdentityJSON(t, eng, http.MethodPost, "/api/v1/users/bulk", nil)
	if rec.Code == http.StatusNotImplemented {
		t.Errorf("POST /api/v1/users/bulk = 501, want a handled response (bulk was implemented; must not be deferred)")
	}
}

// ---------- Reset MFA ----------

// seedMFAEnrolledUser seeds a user with full MFA state so the reset
// path has something concrete to clear. The TOTP secret literal is
// long enough that any string match in the response body is a clear
// leak signal.
func seedMFAEnrolledUser(eng identityEngine, role domain.UserRole, orgID uuid.UUID, email string) *domain.User {
	now := time.Now().UTC()
	secret := "TOTP-SECRET-MUST-NOT-LEAK-ABCDEFG"
	u := &domain.User{
		ID:               uuid.New(),
		OrganizationID:   orgID,
		Email:            email,
		Role:             role,
		PasswordHash:     "PRESERVED-PASSWORD-HASH",
		AuthSource:       domain.AuthSourceLocal,
		EmailVerified:    true,
		MFAEnabled:       true,
		MFASecret:        &secret,
		MFARecoveryCodes: []string{"CODE-1-MUST-NOT-LEAK", "CODE-2-MUST-NOT-LEAK"},
		CreatedAt:        now,
		UpdatedAt:        now,
	}
	_, _ = eng.userRepo.Create(context.Background(), u)
	return u
}

func TestUsers_ResetMFA_SiteAdminClearsState(t *testing.T) {
	eng := newIdentityEngine(t, siteAdminPrincipal(), nil)
	target := seedMFAEnrolledUser(eng, domain.RoleOrgUser, uuid.New(), "mfa@example.com")
	rec := doIdentityJSON(t, eng, http.MethodPost, "/api/v1/users/"+target.ID.String()+"/recovery/reset-mfa", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%q", rec.Code, rec.Body.String())
	}
	stored, _ := eng.userRepo.GetByID(context.Background(), target.ID)
	if stored == nil {
		t.Fatal("user vanished after reset")
	}
	if stored.MFAEnabled {
		t.Errorf("MFAEnabled = true after reset; want false")
	}
	if stored.MFASecret == nil || *stored.MFASecret != "" {
		t.Errorf("MFASecret = %v after reset; want pointer to empty string", stored.MFASecret)
	}
	if len(stored.MFARecoveryCodes) != 0 {
		t.Errorf("MFARecoveryCodes = %v after reset; want empty", stored.MFARecoveryCodes)
	}
	calls := eng.revoker.Calls()
	if len(calls) != 1 {
		t.Fatalf("revoker called %d times; want 1", len(calls))
	}
	if calls[0].UserID != target.ID {
		t.Errorf("revoker user_id = %v; want %v", calls[0].UserID, target.ID)
	}
	if calls[0].Reason != "mfa_reset_by_admin" {
		t.Errorf("revoker reason = %q; want %q", calls[0].Reason, "mfa_reset_by_admin")
	}
	refreshCalls := eng.refreshRevoker.Calls()
	if len(refreshCalls) != 1 {
		t.Fatalf("refresh revoker called %d times; want 1", len(refreshCalls))
	}
	if refreshCalls[0].UserID != target.ID {
		t.Errorf("refresh revoker user_id = %v; want %v", refreshCalls[0].UserID, target.ID)
	}
}

func TestUsers_ResetMFA_RefreshTokenRevokerErrorIsBestEffort(t *testing.T) {
	eng := newIdentityEngine(t, siteAdminPrincipal(), nil)
	eng.refreshRevoker.Err = errors.New("simulated refresh-token store outage")
	target := seedMFAEnrolledUser(eng, domain.RoleOrgUser, uuid.New(), "rtbest@example.com")
	rec := doIdentityJSON(t, eng, http.MethodPost, "/api/v1/users/"+target.ID.String()+"/recovery/reset-mfa", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; want 200 (best-effort refresh-token revoke); body=%q", rec.Code, rec.Body.String())
	}
	stored, _ := eng.userRepo.GetByID(context.Background(), target.ID)
	if stored == nil || stored.MFAEnabled {
		t.Errorf("MFA still enabled after best-effort reset")
	}
	if calls := eng.refreshRevoker.Calls(); len(calls) != 1 {
		t.Errorf("refresh revoker called %d times; want 1 (single attempt even on failure)", len(calls))
	}
	// On revoker error the count field must be ABSENT from the
	// audit metadata — partial-success claims would be misleading.
	var foundEvent bool
	for _, e := range eng.rec.Events() {
		if e.Action != string(domain.AuditOrgAdminMFAReset) {
			continue
		}
		foundEvent = true
		if _, ok := e.Metadata["refresh_tokens_revoked_count"]; ok {
			t.Errorf("audit metadata includes refresh_tokens_revoked_count after revoker error: %v", e.Metadata)
		}
	}
	if !foundEvent {
		t.Errorf("audit event missing after best-effort revoker failure")
	}
}

func TestUsers_ResetMFA_AuditCarriesRefreshTokenCountWhenAvailable(t *testing.T) {
	eng := newIdentityEngine(t, siteAdminPrincipal(), nil)
	eng.refreshRevoker.CountToReturn = 4
	target := seedMFAEnrolledUser(eng, domain.RoleOrgUser, uuid.New(), "count@example.com")
	rec := doIdentityJSON(t, eng, http.MethodPost, "/api/v1/users/"+target.ID.String()+"/recovery/reset-mfa", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	body := rec.Body.String()
	if strings.Contains(body, "refresh_tokens_revoked_count") {
		t.Errorf("response leaked refresh_tokens_revoked_count: %q", body)
	}
	var foundEvent bool
	for _, e := range eng.rec.Events() {
		if e.Action != string(domain.AuditOrgAdminMFAReset) {
			continue
		}
		foundEvent = true
		got, ok := e.Metadata["refresh_tokens_revoked_count"].(int64)
		if !ok {
			t.Errorf("refresh_tokens_revoked_count missing or wrong type: %v", e.Metadata["refresh_tokens_revoked_count"])
		} else if got != 4 {
			t.Errorf("refresh_tokens_revoked_count = %d; want 4", got)
		}
	}
	if !foundEvent {
		t.Errorf("audit event missing")
	}
}

func TestUsers_ResetMFA_RevokerErrorIsBestEffort(t *testing.T) {
	eng := newIdentityEngine(t, siteAdminPrincipal(), nil)
	eng.revoker.Err = errors.New("simulated session store outage")
	target := seedMFAEnrolledUser(eng, domain.RoleOrgUser, uuid.New(), "besteffort@example.com")
	rec := doIdentityJSON(t, eng, http.MethodPost, "/api/v1/users/"+target.ID.String()+"/recovery/reset-mfa", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; want 200 (best-effort revoke); body=%q", rec.Code, rec.Body.String())
	}
	stored, _ := eng.userRepo.GetByID(context.Background(), target.ID)
	if stored == nil || stored.MFAEnabled {
		t.Errorf("MFA still enabled after best-effort reset; stored=%+v", stored)
	}
	if stored.MFASecret == nil || *stored.MFASecret != "" {
		t.Errorf("MFASecret not cleared on best-effort reset: %v", stored.MFASecret)
	}
	if len(stored.MFARecoveryCodes) != 0 {
		t.Errorf("MFARecoveryCodes not cleared on best-effort reset: %v", stored.MFARecoveryCodes)
	}
	if calls := eng.revoker.Calls(); len(calls) != 1 {
		t.Errorf("revoker called %d times; want 1 (single attempt even on failure)", len(calls))
	}
	// Audit must still fire even when the revoker failed: the
	// reset itself succeeded, and the seam contract is best-effort.
	var auditFound bool
	for _, e := range eng.rec.Events() {
		if e.Action == string(domain.AuditOrgAdminMFAReset) {
			auditFound = true
			break
		}
	}
	if !auditFound {
		t.Errorf("audit event missing after best-effort revoke")
	}
}

func TestUsers_ResetMFA_NoRevokerWhenLookupFails(t *testing.T) {
	eng := newIdentityEngine(t, siteAdminPrincipal(), nil)
	rec := doIdentityJSON(t, eng, http.MethodPost, "/api/v1/users/"+uuid.NewString()+"/recovery/reset-mfa", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d; want 404", rec.Code)
	}
	if calls := eng.revoker.Calls(); len(calls) != 0 {
		t.Errorf("session revoker fired %d times for unknown user; want 0", len(calls))
	}
	if calls := eng.refreshRevoker.Calls(); len(calls) != 0 {
		t.Errorf("refresh-token revoker fired %d times for unknown user; want 0", len(calls))
	}
}

func TestUsers_ResetMFA_PreservesUnrelatedFields(t *testing.T) {
	eng := newIdentityEngine(t, siteAdminPrincipal(), nil)
	orgID := uuid.New()
	target := seedMFAEnrolledUser(eng, domain.RoleOrgAdmin, orgID, "admin@example.com")
	rec := doIdentityJSON(t, eng, http.MethodPost, "/api/v1/users/"+target.ID.String()+"/recovery/reset-mfa", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	stored, _ := eng.userRepo.GetByID(context.Background(), target.ID)
	if stored == nil {
		t.Fatal("user vanished after reset")
	}
	if stored.PasswordHash != "PRESERVED-PASSWORD-HASH" {
		t.Errorf("password hash mutated: %q", stored.PasswordHash)
	}
	if stored.Role != domain.RoleOrgAdmin {
		t.Errorf("role mutated: %q", stored.Role)
	}
	if stored.OrganizationID != orgID {
		t.Errorf("organization_id mutated: %s", stored.OrganizationID)
	}
	if stored.Email != "admin@example.com" {
		t.Errorf("email mutated: %q", stored.Email)
	}
	if !stored.EmailVerified {
		t.Errorf("email_verified flipped off; reset must not touch verification state")
	}
	if stored.Banned {
		t.Errorf("banned flipped on; reset must not touch ban state")
	}
	if stored.DeletedAt != nil {
		t.Errorf("deleted_at set by reset")
	}
	if stored.RequiresPasswordChange {
		t.Errorf("requires_password_change flipped on; reset must not touch password-reset state")
	}
}

func TestUsers_ResetMFA_DoesNotLeakSecretOrCodes(t *testing.T) {
	eng := newIdentityEngine(t, siteAdminPrincipal(), nil)
	target := seedMFAEnrolledUser(eng, domain.RoleOrgUser, uuid.New(), "leak@example.com")
	rec := doIdentityJSON(t, eng, http.MethodPost, "/api/v1/users/"+target.ID.String()+"/recovery/reset-mfa", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	body := rec.Body.String()
	if strings.Contains(body, "TOTP-SECRET-MUST-NOT-LEAK-ABCDEFG") {
		t.Errorf("response leaked mfa secret: %q", body)
	}
	if strings.Contains(body, "CODE-1-MUST-NOT-LEAK") || strings.Contains(body, "CODE-2-MUST-NOT-LEAK") {
		t.Errorf("response leaked mfa recovery codes: %q", body)
	}
	if strings.Contains(body, "mfa_secret") || strings.Contains(body, "mfa_recovery_codes") {
		t.Errorf("response leaked sensitive field name: %q", body)
	}
}

func TestUsers_ResetMFA_NonSiteAdminForbidden(t *testing.T) {
	eng := newIdentityEngine(t, &domain.Principal{
		UserID: uuid.New(),
		Role:   domain.RoleOrgAdmin,
	}, nil)
	rec := doIdentityJSON(t, eng, http.MethodPost, "/api/v1/users/"+uuid.NewString()+"/recovery/reset-mfa", nil)
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
}

func TestUsers_ResetMFA_Unauthenticated401(t *testing.T) {
	eng := newIdentityEngine(t, nil, nil)
	rec := doIdentityJSON(t, eng, http.MethodPost, "/api/v1/users/"+uuid.NewString()+"/recovery/reset-mfa", nil)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestUsers_ResetMFA_NotFound(t *testing.T) {
	eng := newIdentityEngine(t, siteAdminPrincipal(), nil)
	rec := doIdentityJSON(t, eng, http.MethodPost, "/api/v1/users/"+uuid.NewString()+"/recovery/reset-mfa", nil)
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

func TestUsers_ResetMFA_InvalidID(t *testing.T) {
	eng := newIdentityEngine(t, siteAdminPrincipal(), nil)
	rec := doIdentityJSON(t, eng, http.MethodPost, "/api/v1/users/not-a-uuid/recovery/reset-mfa", nil)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestUsers_ResetMFA_IdempotentWhenMFAAlreadyClear(t *testing.T) {
	eng := newIdentityEngine(t, siteAdminPrincipal(), nil)
	now := time.Now().UTC()
	target := &domain.User{
		ID:             uuid.New(),
		OrganizationID: uuid.New(),
		Email:          "nomfa@example.com",
		Role:           domain.RoleOrgUser,
		PasswordHash:   "PRESERVED-PASSWORD-HASH",
		AuthSource:     domain.AuthSourceLocal,
		MFAEnabled:     false,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	_, _ = eng.userRepo.Create(context.Background(), target)
	rec := doIdentityJSON(t, eng, http.MethodPost, "/api/v1/users/"+target.ID.String()+"/recovery/reset-mfa", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("idempotent reset status = %d; body=%q", rec.Code, rec.Body.String())
	}
	stored, _ := eng.userRepo.GetByID(context.Background(), target.ID)
	if stored == nil || stored.MFAEnabled {
		t.Errorf("idempotent reset left bad state: %+v", stored)
	}
	if stored.PasswordHash != "PRESERVED-PASSWORD-HASH" {
		t.Errorf("idempotent reset mutated password hash: %q", stored.PasswordHash)
	}
	// Second call: still idempotent.
	rec2 := doIdentityJSON(t, eng, http.MethodPost, "/api/v1/users/"+target.ID.String()+"/recovery/reset-mfa", nil)
	if rec2.Code != http.StatusOK {
		t.Errorf("second reset status = %d, want 200", rec2.Code)
	}
}

func TestUsers_ResetMFA_AuditEventEmitted(t *testing.T) {
	eng := newIdentityEngine(t, siteAdminPrincipal(), nil)
	orgID := uuid.New()
	target := seedMFAEnrolledUser(eng, domain.RoleOrgUser, orgID, "audit@example.com")
	rec := doIdentityJSON(t, eng, http.MethodPost, "/api/v1/users/"+target.ID.String()+"/recovery/reset-mfa", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var found bool
	for _, e := range eng.rec.Events() {
		if e.Action != string(domain.AuditOrgAdminMFAReset) {
			continue
		}
		found = true
		if got, _ := e.Metadata["user_id"].(uuid.UUID); got != target.ID {
			t.Errorf("audit user_id = %v, want %v", got, target.ID)
		}
		if got, _ := e.Metadata["organization_id"].(uuid.UUID); got != orgID {
			t.Errorf("audit organization_id = %v, want %v", got, orgID)
		}
		for _, v := range e.Metadata {
			if s, ok := v.(string); ok {
				if strings.Contains(s, "TOTP-SECRET-MUST-NOT-LEAK") || strings.Contains(s, "CODE-1-MUST-NOT-LEAK") {
					t.Errorf("audit metadata leaked cleared mfa material: %q", s)
				}
			}
		}
	}
	if !found {
		t.Errorf("missing %q audit event", domain.AuditOrgAdminMFAReset)
	}
}

// ---------- Reset MFA — org_admin authority ----------

// orgAdminWithMFARevokeScope builds an org_admin principal bound
// to ownOrg with the users:mfa:revoke scope so the
// RequireSiteAdminOrOrgAdminWithScopesAudit middleware lets the
// request through. The service-layer tenant guard then makes the
// final allow/deny decision.
func orgAdminWithMFARevokeScope(ownOrg uuid.UUID) *domain.Principal {
	return &domain.Principal{
		UserID:         uuid.New(),
		OrganizationID: ownOrg,
		Role:           domain.RoleOrgAdmin,
		Scope:          domain.ScopeUsersMFARevoke,
	}
}

func TestUsers_ResetMFA_OrgAdminSameOrgWithScopeSucceeds(t *testing.T) {
	ownOrg := uuid.New()
	eng := newIdentityEngine(t, orgAdminWithMFARevokeScope(ownOrg), nil)
	target := seedMFAEnrolledUser(eng, domain.RoleOrgUser, ownOrg, "tenant@example.com")
	rec := doIdentityJSON(t, eng, http.MethodPost, "/api/v1/users/"+target.ID.String()+"/recovery/reset-mfa", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%q", rec.Code, rec.Body.String())
	}
	stored, _ := eng.userRepo.GetByID(context.Background(), target.ID)
	if stored == nil {
		t.Fatal("user vanished after org_admin reset")
	}
	if stored.MFAEnabled {
		t.Errorf("MFAEnabled still true after org_admin reset")
	}
	if stored.MFASecret == nil || *stored.MFASecret != "" {
		t.Errorf("MFASecret not cleared after org_admin reset: %v", stored.MFASecret)
	}
	if len(stored.MFARecoveryCodes) != 0 {
		t.Errorf("MFARecoveryCodes not cleared after org_admin reset: %v", stored.MFARecoveryCodes)
	}
	// Same-org reset must still drive both revoker seams.
	if calls := eng.revoker.Calls(); len(calls) != 1 || calls[0].UserID != target.ID {
		t.Errorf("session revoker calls = %v, want one call against target", calls)
	}
	if calls := eng.refreshRevoker.Calls(); len(calls) != 1 || calls[0].UserID != target.ID {
		t.Errorf("refresh revoker calls = %v, want one call against target", calls)
	}
	// Response body must NEVER carry MFA secret / recovery codes.
	body := rec.Body.String()
	if strings.Contains(body, "TOTP-SECRET-MUST-NOT-LEAK") || strings.Contains(body, "CODE-1-MUST-NOT-LEAK") ||
		strings.Contains(body, "mfa_secret") || strings.Contains(body, "mfa_recovery_codes") {
		t.Errorf("response leaked sensitive material: %q", body)
	}
}

// RENAMED from …CrossOrgForbidden. The verdict changed, so the name had to:
// 403 confirmed the target EXISTS in another tenant, which made this route an
// enumeration oracle (G10). It answers 404 now, exactly as the read path beside
// it always did.
func TestUsers_ResetMFA_OrgAdminCrossOrgIs404(t *testing.T) {
	ownOrg := uuid.New()
	otherOrg := uuid.New()
	eng := newIdentityEngine(t, orgAdminWithMFARevokeScope(ownOrg), nil)
	target := seedMFAEnrolledUser(eng, domain.RoleOrgUser, otherOrg, "cross@example.com")
	rec := doIdentityJSON(t, eng, http.MethodPost, "/api/v1/users/"+target.ID.String()+"/recovery/reset-mfa", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d; want 403 (cross-org)", rec.Code)
	}
	stored, _ := eng.userRepo.GetByID(context.Background(), target.ID)
	if stored == nil {
		t.Fatal("user vanished on cross-org probe")
	}
	if !stored.MFAEnabled {
		t.Errorf("cross-org probe MUTATED target MFAEnabled: now false; want unchanged")
	}
	if stored.MFASecret == nil || *stored.MFASecret == "" {
		t.Errorf("cross-org probe MUTATED target MFASecret: %v", stored.MFASecret)
	}
	if len(stored.MFARecoveryCodes) != 2 {
		t.Errorf("cross-org probe MUTATED target MFARecoveryCodes: %v", stored.MFARecoveryCodes)
	}
	if calls := eng.revoker.Calls(); len(calls) != 0 {
		t.Errorf("session revoker fired on forbidden cross-org reset: %v", calls)
	}
	if calls := eng.refreshRevoker.Calls(); len(calls) != 0 {
		t.Errorf("refresh revoker fired on forbidden cross-org reset: %v", calls)
	}
}

// RENAMED for the same reason: an org_admin probing the site_admin's id must
// not be able to tell it apart from an id that does not exist.
func TestUsers_ResetMFA_OrgAdminTargetingSiteAdminIs404(t *testing.T) {
	ownOrg := uuid.New()
	eng := newIdentityEngine(t, orgAdminWithMFARevokeScope(ownOrg), nil)
	// Even when the site_admin shares the same org_id (typical
	// platform-bootstrap shape), org_admin must NOT be able to
	// reset their MFA.
	target := seedMFAEnrolledUser(eng, domain.RoleSiteAdmin, ownOrg, "siteadmin@example.com")
	rec := doIdentityJSON(t, eng, http.MethodPost, "/api/v1/users/"+target.ID.String()+"/recovery/reset-mfa", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d; want 403 (org_admin targeting site_admin)", rec.Code)
	}
	stored, _ := eng.userRepo.GetByID(context.Background(), target.ID)
	if stored == nil || !stored.MFAEnabled {
		t.Errorf("site_admin target MFA mutated by forbidden org_admin reset")
	}
	if calls := eng.revoker.Calls(); len(calls) != 0 {
		t.Errorf("session revoker fired on forbidden site_admin reset: %v", calls)
	}
	if calls := eng.refreshRevoker.Calls(); len(calls) != 0 {
		t.Errorf("refresh revoker fired on forbidden site_admin reset: %v", calls)
	}
}

func TestUsers_ResetMFA_OrgAdminWithoutScopeForbidden(t *testing.T) {
	ownOrg := uuid.New()
	noScope := &domain.Principal{
		UserID:         uuid.New(),
		OrganizationID: ownOrg,
		Role:           domain.RoleOrgAdmin,
		// Deliberately no users:mfa:revoke scope.
		Scope: "users:read users:update",
	}
	eng := newIdentityEngine(t, noScope, nil)
	target := seedMFAEnrolledUser(eng, domain.RoleOrgUser, ownOrg, "noscope@example.com")
	rec := doIdentityJSON(t, eng, http.MethodPost, "/api/v1/users/"+target.ID.String()+"/recovery/reset-mfa", nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d; want 403 (org_admin without users:mfa:revoke)", rec.Code)
	}
	if calls := eng.revoker.Calls(); len(calls) != 0 {
		t.Errorf("session revoker fired on scope-less org_admin reset: %v", calls)
	}
	if calls := eng.refreshRevoker.Calls(); len(calls) != 0 {
		t.Errorf("refresh revoker fired on scope-less org_admin reset: %v", calls)
	}
	stored, _ := eng.userRepo.GetByID(context.Background(), target.ID)
	if stored == nil || !stored.MFAEnabled {
		t.Errorf("MFA mutated despite scope-less denial")
	}
}

func TestUsers_ResetMFA_OrgUserForbidden(t *testing.T) {
	ownOrg := uuid.New()
	// org_user even with the scope is rejected by the middleware:
	// RequireSiteAdminOrOrgAdminWithScopesAudit admits only
	// site_admin OR org_admin.
	orgUserWithScope := &domain.Principal{
		UserID:         uuid.New(),
		OrganizationID: ownOrg,
		Role:           domain.RoleOrgUser,
		Scope:          domain.ScopeUsersMFARevoke,
	}
	eng := newIdentityEngine(t, orgUserWithScope, nil)
	target := seedMFAEnrolledUser(eng, domain.RoleOrgUser, ownOrg, "user@example.com")
	rec := doIdentityJSON(t, eng, http.MethodPost, "/api/v1/users/"+target.ID.String()+"/recovery/reset-mfa", nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d; want 403 (org_user MUST NOT reset MFA even with scope)", rec.Code)
	}
}

func TestUsers_ResetMFA_AuditCarriesActorRoleAndOrg(t *testing.T) {
	ownOrg := uuid.New()
	actor := orgAdminWithMFARevokeScope(ownOrg)
	eng := newIdentityEngine(t, actor, nil)
	target := seedMFAEnrolledUser(eng, domain.RoleOrgUser, ownOrg, "audit-actor@example.com")
	rec := doIdentityJSON(t, eng, http.MethodPost, "/api/v1/users/"+target.ID.String()+"/recovery/reset-mfa", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var matched int
	for _, e := range eng.rec.Events() {
		if e.Action != string(domain.AuditOrgAdminMFAReset) {
			continue
		}
		matched++
		if got, _ := e.Metadata["actor_role"].(string); got != string(domain.RoleOrgAdmin) {
			t.Errorf("audit actor_role = %q, want %q", got, domain.RoleOrgAdmin)
		}
		if got, _ := e.Metadata["actor_user_id"].(uuid.UUID); got != actor.UserID {
			t.Errorf("audit actor_user_id = %v, want %v", got, actor.UserID)
		}
		if got, _ := e.Metadata["actor_organization_id"].(uuid.UUID); got != ownOrg {
			t.Errorf("audit actor_organization_id = %v, want %v", got, ownOrg)
		}
		// No MFA material leak.
		for _, v := range e.Metadata {
			if s, ok := v.(string); ok {
				if strings.Contains(s, "TOTP-SECRET-MUST-NOT-LEAK") || strings.Contains(s, "CODE-1-MUST-NOT-LEAK") {
					t.Errorf("audit metadata leaked cleared mfa material: %q", s)
				}
			}
		}
	}
	if matched == 0 {
		t.Errorf("missing audit row for org_admin reset")
	}
}

// ---------- Organizations ----------

func TestOrganizations_Unauthenticated401(t *testing.T) {
	eng := newIdentityEngine(t, nil, nil)
	rec := doIdentityJSON(t, eng, http.MethodGet, "/api/v1/organizations", nil)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

// RULE: ORG-LIFECYCLE-1
func TestOrganizations_NonSiteAdmin403(t *testing.T) {
	eng := newIdentityEngine(t, &domain.Principal{UserID: uuid.New(), Role: domain.RoleOrgAdmin}, nil)
	rec := doIdentityJSON(t, eng, http.MethodGet, "/api/v1/organizations", nil)
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
}

func TestOrganizations_CreateGetUpdateDelete(t *testing.T) {
	eng := newIdentityEngine(t, siteAdminPrincipal(), nil)
	create := doIdentityJSON(t, eng, http.MethodPost, "/api/v1/organizations", map[string]any{
		"name":   "Acme",
		"domain": "acme.com",
		"active": true,
	})
	if create.Code != http.StatusCreated {
		t.Fatalf("create status = %d; body=%q", create.Code, create.Body.String())
	}
	var created safeOrganization
	if err := json.Unmarshal(create.Body.Bytes(), &created); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if created.OrgSlug != "acme" {
		t.Errorf("slug = %q", created.OrgSlug)
	}
	id := created.ID.String()
	get := doIdentityJSON(t, eng, http.MethodGet, "/api/v1/organizations/"+id, nil)
	if get.Code != http.StatusOK {
		t.Fatalf("get status = %d", get.Code)
	}
	upd := doIdentityJSON(t, eng, http.MethodPut, "/api/v1/organizations/"+id, map[string]any{
		"name": "Acme Renamed",
	})
	if upd.Code != http.StatusOK {
		t.Fatalf("update status = %d; body=%q", upd.Code, upd.Body.String())
	}
	del := doIdentityJSON(t, eng, http.MethodDelete, "/api/v1/organizations/"+id, nil)
	if del.Code != http.StatusOK {
		t.Fatalf("delete status = %d", del.Code)
	}
	var sawCreate, sawUpd, sawDel bool
	for _, e := range eng.rec.Events() {
		switch e.Action {
		case "organization.created":
			sawCreate = true
		case "organization.updated":
			sawUpd = true
		case "organization.deleted":
			sawDel = true
		}
	}
	if !sawCreate || !sawUpd || !sawDel {
		t.Errorf("audit missing: create=%v update=%v delete=%v", sawCreate, sawUpd, sawDel)
	}
}

// TestOrganizations_ActivateRouteRetired pins that the dead site_admin
// POST /api/v1/organizations/activate route was RETIRED (Option A —
// docs/audit/release-readiness/org-activate-retire-decision.md). It is no
// longer registered, so the path returns 404 (route absent) — NOT the old
// 501 deferred stub, and NOT 200. The capability it never provided is
// served by the invitations flow (POST /api/v1/organizations/:id/invitations).
// Mirrors the ...RoutesAbsent sibling guards.
//
// The DISTINCT public route POST /api/v1/auth/organizations/activate is a
// different surface (RegisterAccountLifecycleRoutes) and is unaffected —
// it is exercised by auth_lifecycle_test.go, not here.
//
// (This test was previously TestOrganizations_DeferredRoutesReturn501;
// activate was its last remaining entry — admin-recovery-candidates,
// export-candidates, and resend-activation were all implemented in prior
// slices — so it is repurposed into this absence guard.)
func TestOrganizations_ActivateRouteRetired(t *testing.T) {
	eng := newIdentityEngine(t, siteAdminPrincipal(), nil)
	rec := doIdentityJSON(t, eng, http.MethodPost, "/api/v1/organizations/activate", nil)
	if rec.Code != http.StatusNotFound {
		t.Errorf("POST /api/v1/organizations/activate = %d, want 404 (route retired via non-registration; see org-activate-retire-decision.md). It must NOT return 501 (old stub) or 200.", rec.Code)
	}
}

// ---------- Organization Domains ----------

func TestOrganizationDomains_Unauthenticated401(t *testing.T) {
	eng := newIdentityEngine(t, nil, stubVerifier{err: nil})
	rec := doIdentityJSON(t, eng, http.MethodGet, "/api/v1/organizations/"+uuid.NewString()+"/domains", nil)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestOrganizationDomains_NonSiteAdmin403(t *testing.T) {
	eng := newIdentityEngine(t, &domain.Principal{UserID: uuid.New(), Role: domain.RoleOrgAdmin}, stubVerifier{err: nil})
	rec := doIdentityJSON(t, eng, http.MethodGet, "/api/v1/organizations/"+uuid.NewString()+"/domains", nil)
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
}

func TestOrganizationDomains_AddListVerifyDelete(t *testing.T) {
	// THE-REMAINING-FOUR: domains answer to the org's own org_admin now.
	orgIDU := uuid.New()
	eng := newIdentityEngine(t, &domain.Principal{
		UserID: uuid.New(), OrganizationID: orgIDU, Role: domain.RoleOrgAdmin,
	}, stubVerifier{err: nil})
	orgID := orgIDU.String()
	add := doIdentityJSON(t, eng, http.MethodPost, "/api/v1/organizations/"+orgID+"/domains", map[string]any{
		"domain": "Example.COM",
	})
	if add.Code != http.StatusCreated {
		t.Fatalf("add status = %d; body=%q", add.Code, add.Body.String())
	}
	var addBody struct {
		OrganizationDomain safeOrganizationDomain `json:"organization_domain"`
		VerificationToken  string                 `json:"verification_token"`
		TXTRecordName      string                 `json:"txt_record_name"`
		TXTRecordValue     string                 `json:"txt_record_value"`
	}
	if err := json.Unmarshal(add.Body.Bytes(), &addBody); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if addBody.VerificationToken == "" {
		t.Errorf("add must return raw verification_token once")
	}
	if !strings.Contains(addBody.TXTRecordValue, addBody.VerificationToken) {
		t.Errorf("txt_record_value must embed the raw token")
	}
	if strings.Contains(add.Body.String(), `"verification_token_hash"`) {
		t.Errorf("response leaked verification_token_hash field")
	}
	if addBody.OrganizationDomain.Domain != "example.com" {
		t.Errorf("domain not normalized in response: %q", addBody.OrganizationDomain.Domain)
	}

	list := doIdentityJSON(t, eng, http.MethodGet, "/api/v1/organizations/"+orgID+"/domains", nil)
	if list.Code != http.StatusOK {
		t.Fatalf("list status = %d", list.Code)
	}
	if strings.Contains(list.Body.String(), `"verification_token_hash"`) {
		t.Errorf("list leaked verification_token_hash field")
	}

	domainID := addBody.OrganizationDomain.ID.String()
	verify := doIdentityJSON(t, eng, http.MethodPost, "/api/v1/organizations/"+orgID+"/domains/"+domainID+"/verify", nil)
	if verify.Code != http.StatusOK {
		t.Fatalf("verify status = %d; body=%q", verify.Code, verify.Body.String())
	}

	prim := doIdentityJSON(t, eng, http.MethodPost, "/api/v1/organizations/"+orgID+"/domains/"+domainID+"/primary", nil)
	if prim.Code != http.StatusOK {
		t.Fatalf("set-primary status = %d", prim.Code)
	}

	del := doIdentityJSON(t, eng, http.MethodDelete, "/api/v1/organizations/"+orgID+"/domains/"+domainID, nil)
	if del.Code != http.StatusOK {
		t.Fatalf("delete status = %d", del.Code)
	}

	var seen = map[string]bool{}
	for _, e := range eng.rec.Events() {
		seen[e.Action] = true
	}
	for _, want := range []string{
		"organization_domain.created",
		"organization_domain.verified",
		"organization_domain.set_primary",
		"organization_domain.deleted",
	} {
		if !seen[want] {
			t.Errorf("missing audit event: %s", want)
		}
	}
}

func TestOrganizationDomains_VerifyWithoutVerifierReturns501(t *testing.T) {
	orgIDU := uuid.New()
	eng := newIdentityEngine(t, &domain.Principal{
		UserID: uuid.New(), OrganizationID: orgIDU, Role: domain.RoleOrgAdmin,
	}, nil)
	orgID := orgIDU.String()
	add := doIdentityJSON(t, eng, http.MethodPost, "/api/v1/organizations/"+orgID+"/domains", map[string]any{
		"domain": "example.com",
	})
	if add.Code != http.StatusCreated {
		t.Fatalf("add status = %d", add.Code)
	}
	var addBody struct {
		OrganizationDomain safeOrganizationDomain `json:"organization_domain"`
	}
	_ = json.Unmarshal(add.Body.Bytes(), &addBody)
	domainID := addBody.OrganizationDomain.ID.String()
	verify := doIdentityJSON(t, eng, http.MethodPost, "/api/v1/organizations/"+orgID+"/domains/"+domainID+"/verify", nil)
	if verify.Code != http.StatusNotImplemented {
		t.Errorf("verify without verifier = %d, want 501", verify.Code)
	}
}

// Organization creation is infrastructure authority: an org_user probing the
// create route gets the same 403 the rest of the site-only surface answers.
// RULE: ORG-CREATE-403-1
func TestOrganizations_OrgUserCreate403(t *testing.T) {
	eng := newIdentityEngine(t, &domain.Principal{UserID: uuid.New(), Role: domain.RoleOrgUser}, nil)
	rec := doIdentityJSON(t, eng, http.MethodPost, "/api/v1/organizations", map[string]any{
		"name":   "Rogue Org",
		"domain": "rogue.test",
		"active": true,
	})
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
}

// A soft-deleted organization is gone from reads (404) yet stays restorable
// to a usable state via PUT active:true — deletion is reversible lifecycle,
// not destruction.
// RULE: ORG-RESTORE-1
func TestOrganizations_SoftDeleteThenRestore(t *testing.T) {
	eng := newIdentityEngine(t, siteAdminPrincipal(), nil)
	create := doIdentityJSON(t, eng, http.MethodPost, "/api/v1/organizations", map[string]any{
		"name":   "Phoenix",
		"domain": "phoenix.test",
		"active": true,
	})
	if create.Code != http.StatusCreated {
		t.Fatalf("create status = %d; body=%q", create.Code, create.Body.String())
	}
	var created safeOrganization
	if err := json.Unmarshal(create.Body.Bytes(), &created); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	id := created.ID.String()
	if del := doIdentityJSON(t, eng, http.MethodDelete, "/api/v1/organizations/"+id, nil); del.Code != http.StatusOK {
		t.Fatalf("delete status = %d", del.Code)
	}
	if get := doIdentityJSON(t, eng, http.MethodGet, "/api/v1/organizations/"+id, nil); get.Code != http.StatusNotFound {
		t.Fatalf("get after soft-delete = %d, want 404", get.Code)
	}
	restore := doIdentityJSON(t, eng, http.MethodPost, "/api/v1/organizations/"+id+"/restore", nil)
	if restore.Code != http.StatusOK {
		t.Fatalf("restore status = %d; body=%q", restore.Code, restore.Body.String())
	}
	if get := doIdentityJSON(t, eng, http.MethodGet, "/api/v1/organizations/"+id, nil); get.Code != http.StatusOK {
		t.Fatalf("get after restore = %d, want 200", get.Code)
	}
}
