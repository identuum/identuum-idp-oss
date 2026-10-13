package api

// D9 (owner answer Q3 (b), D-016 Consequence): an administrator gets a
// one-time password reset link for a member and hands it over; there is no
// mail. The issue route answers 200 {reset_url, expires_at} (plus email) with
// Cache-Control no-store, and the member chooses their own password at the
// page the link opens.
//
// CONTRACT (owner Q-D9 (a), 2026-10-12): the console's existing contract
// (identuum-ui CE-UI-2b, idp-admin-client.ts createPasswordResetLink,
// app/reset-link): POST /api/v1/users/:id/recovery/reset-link -> 200
// {reset_url, expires_at}, link to <UI>/reset-link, GET
// /api/v1/auth/reset-link/validate?token= -> {"valid":bool}, POST
// /api/v1/auth/reset-link {token,new_password} -> {"success":true}, 400
// weak_password / invalid_token. Admin link TTL 24 h (self-service stays 1 h).
// capabilities.admin_reset_link true only when the routes are mounted AND the
// UI public base URL is set. 404 {"error":"not_found"} outside visibility (G3).
// 409 local_password_not_allowed for an idp_only org_user target. Endpoint
// count +3.
//
// Driven through the REAL router (NewOSSEngine) on deps that already exist in
// OSSRouterDeps (UserService, PasswordResetService, UIPublicBaseURL, Audit),
// with in-memory stores. The reset store carries the one method the slice is
// expected to add (CreateRetiringOthers: insert the new row and mark the
// user's other unused rows used, in one transaction). If the slice names it
// differently the embedded nil interface panics: rename it here.
//
// Error codes below are the PROPOSED contract (PREP.md D9); the writer may
// rename a code, and then changes it here and in the UI contract together.
// Until the route exists every test except the premise test is RED on the
// router's own 404 ("404 page not found", not the handler's JSON).
//
// Tokens and passwords are never printed by these tests.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
	"github.com/identuum/identuum-idp-oss/internal/crypto"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/lifecycle"
	"github.com/identuum/identuum-idp-oss/internal/repository"
	"github.com/identuum/identuum-idp-oss/internal/server"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// The console contract (Q-D9 (a)), a constant.
type d9ContractSpec struct {
	issueSuffix, page, consumePath, invalidCode string
}

var d9Contract = d9ContractSpec{
	issueSuffix: "/recovery/reset-link",
	page:        "/reset-link",
	consumePath: "/api/v1/auth/reset-link",
	invalidCode: "invalid_token",
}

func d9Spec() d9ContractSpec { return d9Contract }

// d9AdminLinkTTL is the admin link lifetime (Q-D9 (a)): 24 hours. The
// self-service link keeps service.DefaultPasswordResetTTL (1 hour).
const d9AdminLinkTTL = 24 * time.Hour

// ---------- in-memory stores ----------

// d9Users is the users table. It serves UserService (repository.UserRepository)
// and PasswordResetService (FindUsersByEmail / GetByIDWithOrg / Update).
type d9Users struct {
	repository.UserRepository
	mu      sync.Mutex
	byID    map[uuid.UUID]*domain.User
	events  *[]string // shared order log with the revoker
	lastOpt *repository.UpdateUserOptions
}

func (r *d9Users) get(id uuid.UUID) (*domain.User, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	u, ok := r.byID[id]
	if !ok || u.DeletedAt != nil {
		return nil, domain.ErrUserNotFound
	}
	cp := *u
	return &cp, nil
}

func (r *d9Users) GetByID(_ context.Context, id uuid.UUID) (*domain.User, error) { return r.get(id) }
func (r *d9Users) GetByIDWithOrg(_ context.Context, id uuid.UUID) (*domain.User, error) {
	return r.get(id)
}

func (r *d9Users) FindUsersByEmail(_ context.Context, email string) ([]*domain.User, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []*domain.User
	for _, u := range r.byID {
		if strings.EqualFold(u.Email, email) {
			cp := *u
			out = append(out, &cp)
		}
	}
	return out, nil
}

func (r *d9Users) HashPassword(_ context.Context, pw string) (string, error) { return "h:" + pw, nil }
func (r *d9Users) VerifyPassword(_ context.Context, pw, hash string) error {
	if hash != "h:"+pw {
		return errors.New("mismatch")
	}
	return nil
}

// Update applies the fields the user paths write and records the options so a
// test can read what reached the repository.
func (r *d9Users) Update(_ context.Context, id, orgID uuid.UUID, o repository.UpdateUserOptions) (*domain.User, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	u, ok := r.byID[id]
	if !ok || u.DeletedAt != nil || u.OrganizationID != orgID {
		return nil, nil
	}
	if r.events != nil {
		*r.events = append(*r.events, "update")
	}
	cp := o
	r.lastOpt = &cp
	if o.Password != nil {
		u.PasswordHash = *o.Password
	}
	if o.Name != nil {
		u.Name = o.Name
	}
	if o.Banned != nil {
		u.Banned = *o.Banned
	}
	if o.RequiresPasswordChange != nil {
		u.RequiresPasswordChange = *o.RequiresPasswordChange
	}
	out := *u
	return &out, nil
}

// d9Resets is the password_resets table, keyed by token hash, on the test
// clock (the SQL compares expires_at > NOW()).
type d9Resets struct {
	repository.PasswordResetRepository
	mu    sync.Mutex
	rows  map[string]*domain.PasswordReset
	users *d9Users
	now   func() time.Time
}

func (r *d9Resets) Create(_ context.Context, row *domain.PasswordReset) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	cp := *row
	r.rows[row.TokenHash] = &cp
	return nil
}

// CreateRetiringOthers is the method D9 is expected to add: one transaction
// that marks every unused row of the user used, then inserts the new row.
func (r *d9Resets) CreateRetiringOthers(_ context.Context, row *domain.PasswordReset) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	for _, old := range r.rows {
		if old.UserID == row.UserID && old.UsedAt == nil {
			t := now
			old.UsedAt = &t
		}
	}
	cp := *row
	r.rows[row.TokenHash] = &cp
	return nil
}

func (r *d9Resets) GetByTokenHash(_ context.Context, hash string) (*domain.PasswordReset, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	row, ok := r.rows[hash]
	if !ok {
		return nil, nil
	}
	cp := *row
	return &cp, nil
}

// ClaimPasswordReset mirrors the pgx transaction (password_reset_repository_pgx.go
// :111-149) plus the Q-B2 change: the flag is cleared with the password.
func (r *d9Resets) ClaimPasswordReset(_ context.Context, hash, newHash string) (uuid.UUID, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	row, ok := r.rows[hash]
	if !ok || row.UsedAt != nil || !row.ExpiresAt.After(now) {
		return uuid.Nil, false, nil
	}
	t := now
	row.UsedAt = &t
	for _, other := range r.rows {
		if other.UserID == row.UserID && other.UsedAt == nil {
			other.UsedAt = &t
		}
	}
	r.users.mu.Lock()
	if u := r.users.byID[row.UserID]; u != nil {
		u.PasswordHash = newHash
		u.RequiresPasswordChange = false
	}
	r.users.mu.Unlock()
	return row.UserID, true, nil
}

func (r *d9Resets) unused(user uuid.UUID) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, row := range r.rows {
		if row.UserID == user && row.UsedAt == nil {
			n++
		}
	}
	return n
}

type d9Verifier struct{ principals map[string]*domain.Principal }

func (v d9Verifier) VerifyBearerToken(_ context.Context, token string) (*domain.Principal, error) {
	if p, ok := v.principals[token]; ok {
		cp := *p
		return &cp, nil
	}
	return nil, errors.New("stub: unknown bearer token")
}

// d9SessionRepo records session revocations in the shared order log, so a
// test can see that an admin password set revokes BEFORE it writes.
type d9SessionRepo struct {
	repository.SessionRepository
	events *[]string
}

func (r *d9SessionRepo) RevokeByUserID(_ context.Context, _ uuid.UUID, reason string) error {
	*r.events = append(*r.events, "revoke:"+reason)
	return nil
}

// ---------- fixture ----------

const (
	d9UIBase      = "https://ui.example.test"
	d9AdminA      = "admin-a-bearer"
	d9AdminB      = "admin-b-bearer"
	d9SiteAdmin   = "site-admin-bearer"
	d9MemberToken = "member-a-bearer"
	d9NewPassword = "Member-Own-Pass-2026!x"
)

type d9World struct {
	engine *gin.Engine
	users  *d9Users
	resets *d9Resets
	svc    *service.PasswordResetService
	audit  *audit.Recorder
	clock  *time.Time
	ids    map[string]uuid.UUID
	order  *[]string // revoke and update calls, in order
}

func newD9World(t *testing.T, uiBase string) *d9World {
	t.Helper()
	gin.SetMode(gin.TestMode)
	orgA, orgB := uuid.New(), uuid.New()
	sysOrg := uuid.MustParse(domain.SystemOrgID)
	now := time.Date(2026, 10, 13, 9, 0, 0, 0, time.UTC)
	w := &d9World{clock: &now, ids: map[string]uuid.UUID{}}
	clock := func() time.Time { return *w.clock }

	mk := func(name string, org uuid.UUID, role domain.UserRole, mut func(*domain.User)) *domain.User {
		id := uuid.New()
		if name == "siteadmin" {
			id = uuid.MustParse(domain.SiteAdminID)
		}
		u := &domain.User{ID: id, OrganizationID: org, Email: name + "@example.test", Role: role,
			AuthSource: domain.AuthSourceLocal, EmailVerified: true, PasswordHash: "h:Old-Pass-2026!z"}
		if mut != nil {
			mut(u)
		}
		w.ids[name] = id
		return u
	}
	pendingHash := "pending-invite-hash"
	deletedAt := now.Add(-time.Hour)
	all := []*domain.User{
		mk("adminA", orgA, domain.RoleOrgAdmin, nil),
		mk("adminA2", orgA, domain.RoleOrgAdmin, nil),
		mk("member", orgA, domain.RoleOrgUser, nil),
		mk("disabled", orgA, domain.RoleOrgUser, func(u *domain.User) { u.Banned = true }),
		mk("invited", orgA, domain.RoleOrgUser, func(u *domain.User) { u.EmailVerified = false; u.ActivationTokenHash = &pendingHash }),
		mk("upstream", orgA, domain.RoleOrgUser, func(u *domain.User) { u.AuthSource = domain.AuthSourceIDJag; u.PasswordHash = "" }),
		mk("sentinel", orgA, domain.RoleOrgUser, func(u *domain.User) { u.PasswordHash = domain.NoPasswordSentinel }),
		mk("idponly", orgA, domain.RoleOrgUser, func(u *domain.User) { p := domain.AuthPolicyIDPOnly; u.OrgAuthPolicy = &p }),
		mk("deleted", orgA, domain.RoleOrgUser, func(u *domain.User) { u.DeletedAt = &deletedAt }),
		mk("adminB", orgB, domain.RoleOrgAdmin, nil),
		mk("memberB", orgB, domain.RoleOrgUser, nil),
		mk("siteadmin", sysOrg, domain.RoleSiteAdmin, nil),
	}
	var order []string
	w.order = &order
	w.users = &d9Users{byID: map[uuid.UUID]*domain.User{}, events: &order}
	for _, u := range all {
		w.users.byID[u.ID] = u
	}
	w.resets = &d9Resets{rows: map[string]*domain.PasswordReset{}, users: w.users, now: clock}
	w.audit = &audit.Recorder{}

	report := lifecycle.NewStartupReport()
	users := service.NewUserService(report, w.users)
	resets := service.NewPasswordResetService(service.PasswordResetServiceConfig{
		Users:              w.users,
		Resets:             w.resets,
		Audit:              w.audit,
		HumanFacingBaseURL: uiBase,
		Now:                clock,
	})
	w.svc = resets
	scopes := domain.ScopeUsersRead + " " + domain.ScopeUsersUpdate
	w.engine = NewOSSEngine(OSSRouterDeps{
		DiscoveryConfig: server.OIDCDiscoveryConfig{Issuer: "https://idp.test"},
		TokenVerifier: d9Verifier{principals: map[string]*domain.Principal{
			d9AdminA:      {UserID: w.ids["adminA"], Sub: w.ids["adminA"].String(), Role: domain.RoleOrgAdmin, OrganizationID: orgA, Scope: scopes},
			d9AdminB:      {UserID: w.ids["adminB"], Sub: w.ids["adminB"].String(), Role: domain.RoleOrgAdmin, OrganizationID: orgB, Scope: scopes},
			d9SiteAdmin:   {UserID: w.ids["siteadmin"], Sub: w.ids["siteadmin"].String(), Role: domain.RoleSiteAdmin, OrganizationID: sysOrg},
			d9MemberToken: {UserID: w.ids["member"], Sub: w.ids["member"].String(), Role: domain.RoleOrgUser, OrganizationID: orgA},
		}},
		UserLookup:           w.users,
		UserRepo:             w.users,
		UserService:          users,
		UserSessionService:   service.NewUserSessionService(nil, &d9SessionRepo{events: &order}, service.UserSessionServiceOptions{}),
		PasswordResetService: resets,
		UIPublicBaseURL:      uiBase,
		Audit:                w.audit,
	})
	return w
}

func (w *d9World) issue(bearer, who string) (*httptest.ResponseRecorder, map[string]any) {
	path := "/api/v1/users/" + w.ids[who].String() + d9Spec().issueSuffix
	req := httptest.NewRequest(http.MethodPost, path, nil)
	req.Header.Set("Authorization", "Bearer "+bearer)
	rec := httptest.NewRecorder()
	w.engine.ServeHTTP(rec, req)
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	return rec, body
}

// consumeSelfService spends a token at the existing self-service route.
func (w *d9World) consumeSelfService(token, pw string) (int, string) {
	return w.consumeAt("/api/v1/auth/password/reset", token, pw)
}

// consume spends a token where the contract's page posts it.
func (w *d9World) consume(token, pw string) (int, string) {
	return w.consumeAt(d9Spec().consumePath, token, pw)
}

func (w *d9World) consumeAt(path, token, pw string) (int, string) {
	b, _ := json.Marshal(map[string]string{"token": token, "new_password": pw})
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(string(b)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	w.engine.ServeHTTP(rec, req)
	var body struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	return rec.Code, body.Error
}

// tokenOf reads the token out of reset_url and checks the link's shape.
func tokenOf(t *testing.T, body map[string]any) string {
	t.Helper()
	raw, _ := body["reset_url"].(string)
	u, err := url.Parse(raw)
	if err != nil || raw == "" {
		t.Fatalf("reset_url missing or not a URL")
	}
	if u.Scheme+"://"+u.Host != d9UIBase || u.Path != d9Spec().page {
		t.Fatalf("reset_url is not <UI base>%s (scheme/host/path differ)", d9Spec().page)
	}
	tok := u.Query().Get("token")
	if len(tok) != 64 {
		t.Fatalf("reset token length = %d; want 64 hex characters (32 random bytes, generateToken)", len(tok))
	}
	return tok
}

func routeServed(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	if strings.HasPrefix(rec.Body.String(), "404 page not found") {
		t.Fatalf("POST /api/v1/users/:id%s is not served (router 404)", d9Spec().issueSuffix)
	}
}

// ---------- tests ----------

// Control (green before and after the slice): the self-service reset path the
// D9 link reuses works in this fixture, so a red below is the route's.
func TestD9_FixturePremises(t *testing.T) {
	w := newD9World(t, d9UIBase)
	if err := w.resets.Create(context.Background(), &domain.PasswordReset{UserID: w.ids["member"], TokenHash: hashForTest("premise"), ExpiresAt: w.clock.Add(time.Hour), CreatedAt: *w.clock}); err != nil {
		t.Fatal(err)
	}
	if st, code := w.consumeSelfService("premise", d9NewPassword); st != http.StatusOK {
		t.Fatalf("PREMISE: the existing reset consume = %d %s; want 200", st, code)
	}
	if rec, _ := w.issue(d9AdminA, "member"); rec.Code != http.StatusNotFound {
		t.Logf("route answers %d (the slice has landed)", rec.Code)
	}
}

// Control (green before and after): the self-service link keeps its 1 hour
// lifetime; the 24 hour admin TTL must not leak into it.
func TestD9_SelfServiceTTLStaysOneHour(t *testing.T) {
	if service.DefaultPasswordResetTTL != time.Hour {
		t.Fatalf("DefaultPasswordResetTTL = %s; want 1h (self-service, unchanged by D9)", service.DefaultPasswordResetTTL)
	}
	w := newD9World(t, d9UIBase)
	if err := w.svc.RequestPasswordReset(context.Background(), "member@example.test", "", ""); err != nil {
		t.Fatal(err)
	}
	w.resets.mu.Lock()
	defer w.resets.mu.Unlock()
	if len(w.resets.rows) != 1 {
		t.Fatalf("self-service request left %d rows; want 1", len(w.resets.rows))
	}
	for _, row := range w.resets.rows {
		if !row.ExpiresAt.Equal(w.clock.Add(time.Hour)) {
			t.Errorf("self-service expires_at = %s; want request time + 1h", row.ExpiresAt)
		}
	}
}

// An org_admin gets a one-time link for a member of its own organization. The
// answer is no-store, names the email and the expiry (the admin TTL, 24 hours,
// read on the service's injected clock), and the link is spent by the
// console's consume route exactly once.
func TestD9_OrgAdminIssuesLinkThatWorksOnce(t *testing.T) {
	w := newD9World(t, d9UIBase)
	rec, body := w.issue(d9AdminA, "member")
	routeServed(t, rec)
	if rec.Code != http.StatusOK {
		t.Fatalf("issue = %d %v; want 200", rec.Code, body["error"])
	}
	if cc := rec.Header().Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Errorf("Cache-Control = %q; want no-store", cc)
	}
	if body["email"] != "member@example.test" {
		t.Errorf("email = %v; want the member's address", body["email"])
	}
	exp, err := time.Parse(time.RFC3339, fmt.Sprint(body["expires_at"]))
	if err != nil || !exp.Equal(w.clock.Add(d9AdminLinkTTL)) {
		t.Errorf("expires_at = %v; want issue time + %s (RFC3339, injected clock)", body["expires_at"], d9AdminLinkTTL)
	}
	for k := range body {
		if k == "token" || k == "reset_token" || k == "invite_token" {
			t.Errorf("answer carries a bare %q; the link is the only carrier", k)
		}
	}
	tok := tokenOf(t, body)
	if st, code := w.consume(tok, d9NewPassword); st != http.StatusOK {
		t.Fatalf("first use = %d %s; want 200", st, code)
	}
	if st, code := w.consume(tok, "Another-Pass-2026!y"); st != http.StatusBadRequest || code != d9Spec().invalidCode {
		t.Errorf("second use = %d %s; want 400 %s", st, code, d9Spec().invalidCode)
	}
	if u, _ := w.users.get(w.ids["member"]); u.PasswordHash == "h:Old-Pass-2026!z" {
		t.Errorf("the member's password did not change")
	}
}

// A new link voids the earlier unused one; an expired link is refused.
// RULE: D9-LINK-ONCE-1
func TestD9_NewLinkVoidsEarlierAndExpiryHolds(t *testing.T) {
	w := newD9World(t, d9UIBase)
	rec, b1 := w.issue(d9AdminA, "member")
	routeServed(t, rec)
	first := tokenOf(t, b1)
	_, b2 := w.issue(d9AdminA, "member")
	second := tokenOf(t, b2)
	if n := w.resets.unused(w.ids["member"]); n != 1 {
		t.Errorf("%d unused links after the second issue; want 1", n)
	}
	if st, code := w.consume(first, d9NewPassword); st != http.StatusBadRequest || code != d9Spec().invalidCode {
		t.Errorf("earlier link after a new one = %d %s; want 400 %s", st, code, d9Spec().invalidCode)
	}
	// Past the self-service hour the admin link is still good (validate does
	// not spend it) ...
	*w.clock = w.clock.Add(2 * time.Hour)
	if v := w.validate(t, second); v != true {
		t.Errorf("admin link 2h after issue: valid = %v; want true (TTL 24h)", v)
	}
	// ... and past 24 hours it is refused.
	*w.clock = w.clock.Add(d9AdminLinkTTL - 2*time.Hour + time.Second)
	if st, code := w.consume(second, d9NewPassword); st != http.StatusBadRequest || code != d9Spec().invalidCode {
		t.Errorf("link past its expiry = %d %s; want 400 %s", st, code, d9Spec().invalidCode)
	}
}

// Authority: the same as an admin password set, plus no self target.
// RULE: D9-LINK-AUTHORITY-1
func TestD9_Authority(t *testing.T) {
	cases := []struct {
		name, bearer, target string
		status               int
		code                 string
	}{
		{"org_admin, other organization", d9AdminA, "memberB", http.StatusNotFound, "not_found"},
		{"org_admin, site_admin target", d9AdminA, "siteadmin", http.StatusNotFound, "not_found"},
		{"org_admin, deleted user", d9AdminA, "deleted", http.StatusNotFound, "not_found"},
		{"org_admin, itself", d9AdminA, "adminA", http.StatusForbidden, "cannot_reset_self"},
		{"site_admin, tenant user (D-025)", d9SiteAdmin, "member", http.StatusForbidden, "forbidden"},
		{"site_admin, itself", d9SiteAdmin, "siteadmin", http.StatusForbidden, "cannot_reset_self"},
		{"org_user", d9MemberToken, "member", http.StatusForbidden, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newD9World(t, d9UIBase)
			rec, body := w.issue(tc.bearer, tc.target)
			routeServed(t, rec)
			if rec.Code != tc.status || (tc.code != "" && body["error"] != tc.code) {
				t.Errorf("issue = %d %v; want %d %s", rec.Code, body["error"], tc.status, tc.code)
			}
			if w.resets.unused(w.ids[tc.target]) != 0 {
				t.Errorf("a refused request left a usable link")
			}
		})
	}
}

// Plain refusals for a target that must not get a link; nothing is minted.
// RULE: D9-LINK-TARGET-STATE-1
func TestD9_RefusedTargets(t *testing.T) {
	cases := []struct{ target, code string }{
		{"disabled", "user_disabled"},
		{"invited", "user_not_activated"},
		{"upstream", "no_local_password"},
		{"sentinel", "no_local_password"},
		{"idponly", "local_password_not_allowed"},
	}
	for _, tc := range cases {
		t.Run(tc.target, func(t *testing.T) {
			w := newD9World(t, d9UIBase)
			rec, body := w.issue(d9AdminA, tc.target)
			routeServed(t, rec)
			if rec.Code != http.StatusConflict || body["error"] != tc.code {
				t.Errorf("issue for %s = %d %v; want 409 %s", tc.target, rec.Code, body["error"], tc.code)
			}
			if w.resets.unused(w.ids[tc.target]) != 0 {
				t.Errorf("a refused request left a usable link")
			}
		})
	}
}

// With no UI base URL no link can open the reset page: refuse and mint nothing
// (the invite precedent names the setting; activation_link.go:27).
func TestD9_NoUIBaseURLIsRefused(t *testing.T) {
	w := newD9World(t, "")
	rec, body := w.issue(d9AdminA, "member")
	routeServed(t, rec)
	if rec.Code != http.StatusConflict || body["error"] != "reset_link_unavailable" ||
		!strings.Contains(fmt.Sprint(body["message"]), "IDENTUUM_IDP_UI_PUBLIC_BASE_URL") {
		t.Errorf("issue without a UI base = %d %v; want 409 reset_link_unavailable naming IDENTUUM_IDP_UI_PUBLIC_BASE_URL", rec.Code, body["error"])
	}
	if w.resets.unused(w.ids["member"]) != 0 {
		t.Errorf("a link was minted that no page can open")
	}
}

// The link never reaches an audit row; the issue is audited with actor, target
// and organization. (internal/api may not import zap: the log half is
// TestIssueLink_LogsNeitherTokenNorLink in internal/service.)
// RULE: D9-LINK-NO-LEAK-1
func TestD9_AuditedWithoutTheLink(t *testing.T) {
	w := newD9World(t, d9UIBase)
	rec, body := w.issue(d9AdminA, "member")
	routeServed(t, rec)
	tok := tokenOf(t, body)
	var found bool
	for _, ev := range w.audit.Events() {
		dump := fmt.Sprintf("%+v", ev)
		if strings.Contains(dump, tok) || strings.Contains(dump, d9Spec().page+"?") {
			t.Fatalf("audit event %q carries the link or token", ev.Action)
		}
		if ev.Action == "user.password_reset_link_issued" && ev.ActorID == w.ids["adminA"] &&
			ev.SubjectID == w.ids["member"] && ev.OrganizationID != uuid.Nil {
			found = true
		}
	}
	if !found {
		t.Errorf("no user.password_reset_link_issued event with actor, subject and organization")
	}
}

// validate asks GET /api/v1/auth/reset-link/validate?token= and returns the
// "valid" value; the answer must be no-store.
func (w *d9World) validate(t *testing.T, tok string) any {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/reset-link/validate?token="+url.QueryEscape(tok), nil)
	r := httptest.NewRecorder()
	w.engine.ServeHTTP(r, req)
	var out map[string]any
	_ = json.Unmarshal(r.Body.Bytes(), &out)
	if cc := r.Header().Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Errorf("validate Cache-Control = %q; want no-store", cc)
	}
	return out["valid"]
}

// The /reset-link page validates the token without spending it
// (GET /api/v1/auth/reset-link/validate → {"valid":bool}).
func TestD9_ValidateRouteDoesNotSpend(t *testing.T) {
	w := newD9World(t, d9UIBase)
	rec, body := w.issue(d9AdminA, "member")
	routeServed(t, rec)
	tok := tokenOf(t, body)
	valid := func() any { return w.validate(t, tok) }
	if v := valid(); v != true {
		t.Fatalf("validate before use = %v; want true", v)
	}
	if v := valid(); v != true {
		t.Fatalf("validate spent the link (second validate = %v)", v)
	}
	if st, code := w.consume(tok, d9NewPassword); st != http.StatusOK {
		t.Fatalf("use after validate = %d %s; want 200", st, code)
	}
	if v := valid(); v != false {
		t.Errorf("validate after use = %v; want false", v)
	}
}

// The discovery capability the UI reads (mail-capabilities.ts
// adminResetLinkAvailable): true only when the routes are mounted AND the UI
// public base URL is set (OSSRouterDeps.UIPublicBaseURL, wired from
// IDENTUUM_IDP_UI_PUBLIC_BASE_URL with no issuer fallback); otherwise the UI
// would show a button the route refuses with 409 reset_link_unavailable.
// The "empty" case is green at the base (false today) and must stay green.
// RULE: CAP-RESET-LINK-IFF-1
func TestD9_CapabilityFollowsTheUIBase(t *testing.T) {
	for _, tc := range []struct {
		name, base string
		want       bool
	}{
		{"UI base set", d9UIBase, true},
		{"UI base empty", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newD9World(t, tc.base)
			req := httptest.NewRequest(http.MethodGet, "/api/v1/component", nil)
			rec := httptest.NewRecorder()
			w.engine.ServeHTTP(rec, req)
			var body struct {
				Capabilities map[string]any `json:"capabilities"`
			}
			_ = json.Unmarshal(rec.Body.Bytes(), &body)
			if got, ok := body.Capabilities["admin_reset_link"].(bool); !ok || got != tc.want {
				t.Errorf("capabilities.admin_reset_link = %v; want %v (%s)", body.Capabilities["admin_reset_link"], tc.want, tc.name)
			}
		})
	}
	// No reset service: the issue route is not mounted and the capability is
	// false, even with the UI base set.
	t.Run("no reset service", func(t *testing.T) {
		w := newD9World(t, d9UIBase)
		w.engine = NewOSSEngine(OSSRouterDeps{
			DiscoveryConfig: server.OIDCDiscoveryConfig{Issuer: "https://idp.test"},
			TokenVerifier: d9Verifier{principals: map[string]*domain.Principal{
				d9AdminA: {UserID: w.ids["adminA"], Sub: w.ids["adminA"].String(), Role: domain.RoleOrgAdmin,
					OrganizationID: w.users.byID[w.ids["adminA"]].OrganizationID, Scope: domain.ScopeUsersRead + " " + domain.ScopeUsersUpdate},
			}},
			UserLookup:      w.users,
			UserRepo:        w.users,
			UserService:     service.NewUserService(lifecycle.NewStartupReport(), w.users),
			UIPublicBaseURL: d9UIBase,
			Audit:           w.audit,
		})
		if rec, _ := w.issue(d9AdminA, "member"); !strings.HasPrefix(rec.Body.String(), "404 page not found") {
			t.Errorf("issue route without a reset service = %d; want the router's 404 (not mounted)", rec.Code)
		}
		req := httptest.NewRequest(http.MethodGet, "/api/v1/component", nil)
		rec := httptest.NewRecorder()
		w.engine.ServeHTTP(rec, req)
		var body struct {
			Capabilities map[string]any `json:"capabilities"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		if got, ok := body.Capabilities["admin_reset_link"].(bool); !ok || got {
			t.Errorf("capabilities.admin_reset_link without a reset service = %v; want false", body.Capabilities["admin_reset_link"])
		}
	})
}

// hashForTest is the service's token hash (crypto.HashToken, SHA-256 hex).
func hashForTest(raw string) string { return crypto.HashToken(raw) }

type d9FailingRefreshRevoker struct{}

func (d9FailingRefreshRevoker) RevokeAllForUser(context.Context, uuid.UUID) (int64, error) {
	return 0, errors.New("simulated outage")
}

// Review F4 (OSS-0913-B-REVIEW): when the other sign-ins cannot be ended, the
// password is already set and the link spent. The answer stays 500
// internal_error, and its message says the password was set instead of
// inviting a retry that would answer invalid_token.
func TestD9_RedeemSaysThePasswordWasSetWhenRevocationFails(t *testing.T) {
	w := newD9World(t, d9UIBase)
	w.svc.WithRefreshTokenRevoker(d9FailingRefreshRevoker{})
	rec, body := w.issue(d9AdminA, "member")
	if rec.Code != http.StatusOK {
		t.Fatalf("issue = %d %v; want 200", rec.Code, body["error"])
	}
	b, _ := json.Marshal(map[string]string{"token": tokenOf(t, body), "new_password": d9NewPassword})
	req := httptest.NewRequest(http.MethodPost, d9Spec().consumePath, strings.NewReader(string(b)))
	req.Header.Set("Content-Type", "application/json")
	out := httptest.NewRecorder()
	w.engine.ServeHTTP(out, req)
	var got struct{ Error, Message string }
	_ = json.Unmarshal(out.Body.Bytes(), &got)
	if out.Code != http.StatusInternalServerError || got.Error != "internal_error" {
		t.Fatalf("redeem with a failing revocation = %d %s; want 500 internal_error", out.Code, got.Error)
	}
	if !strings.Contains(got.Message, "password is set") {
		t.Errorf("message = %q; want it to say the password is set", got.Message)
	}
	if u, _ := w.users.get(w.ids["member"]); u.PasswordHash == "h:Old-Pass-2026!z" {
		t.Errorf("the member's password did not change")
	}
}
