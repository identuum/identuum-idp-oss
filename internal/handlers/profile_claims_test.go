package handlers

// profile_claims_test.go — THE-PROFILE-CLAIMS through the handlers: the
// self-service PUT /profile and the admin PUT /users/:id patch the optional
// profile row; GET /profile projects it; userinfo releases set fields under
// the profile scope (or the consented claims) and never an unset one.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/mw"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

type memProfileRepo struct {
	rows map[uuid.UUID]*domain.UserProfile
	tick time.Time
}

func newMemProfileRepo() *memProfileRepo {
	return &memProfileRepo{rows: map[uuid.UUID]*domain.UserProfile{}, tick: time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)}
}

func (r *memProfileRepo) Get(_ context.Context, userID uuid.UUID) (*domain.UserProfile, error) {
	if row, ok := r.rows[userID]; ok {
		cp := *row
		return &cp, nil
	}
	return nil, nil
}

func (r *memProfileRepo) Upsert(_ context.Context, p *domain.UserProfile) (*domain.UserProfile, error) {
	r.tick = r.tick.Add(time.Second)
	cp := *p
	cp.UpdatedAt = r.tick
	r.rows[p.UserID] = &cp
	out := cp
	return &out, nil
}

type profileEngine struct {
	r        *gin.Engine
	userRepo *memUserRepo
	profiles *memProfileRepo
}

func newProfileEngine(t *testing.T, principal *domain.Principal) profileEngine {
	t.Helper()
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	if principal != nil {
		r.Use(mw.InjectPrincipalForTest(principal))
	}
	userRepo := newMemUserRepo()
	profiles := newMemProfileRepo()
	deps := UsersHandlerDeps{
		UserService:    service.NewUserService(nil, userRepo),
		ProfileService: service.NewUserProfileService(nil, profiles),
		Audit:          &audit.Recorder{},
	}
	RegisterUsersRoutes(r, deps)
	RegisterProfileRoute(r, deps)
	return profileEngine{r: r, userRepo: userRepo, profiles: profiles}
}

func (e profileEngine) do(t *testing.T, method, path string, body any) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	var rd *strings.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = strings.NewReader(string(b))
	} else {
		rd = strings.NewReader("")
	}
	req := httptest.NewRequest(method, path, rd)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	e.r.ServeHTTP(w, req)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w, out
}

func orgUserPrincipal() *domain.Principal {
	return &domain.Principal{UserID: uuid.New(), OrganizationID: uuid.New(), Email: "user@example.test", Role: domain.RoleOrgUser}
}

func TestProfile_SelfServicePutSetsClearsAndValidates(t *testing.T) {
	p := orgUserPrincipal()
	eng := newProfileEngine(t, p)
	seedUser(selfScopeEngine{userRepo: eng.userRepo}, p)

	w, body := eng.do(t, http.MethodPut, "/api/v1/profile", map[string]any{
		"name": "Alice Example", "given_name": "Alice", "locale": "en-GB", "website": "https://alice.example",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("PUT /profile status = %d body=%q", w.Code, w.Body.String())
	}
	if body["given_name"] != "Alice" || body["locale"] != "en-GB" || body["name"] != "Alice Example" {
		t.Errorf("response must echo the set fields: %v", body)
	}
	if _, present := body["family_name"]; present {
		t.Errorf("unset family_name must be absent from the projection: %v", body)
	}
	if body["profile_updated_at"] == nil {
		t.Errorf("profile_updated_at expected after a profile write")
	}

	w, body = eng.do(t, http.MethodGet, "/api/v1/profile", nil)
	if w.Code != http.StatusOK || body["given_name"] != "Alice" || body["website"] != "https://alice.example" {
		t.Errorf("GET /profile must project the profile row: %d %v", w.Code, body)
	}

	// "" clears; the field disappears.
	w, body = eng.do(t, http.MethodPut, "/api/v1/profile", map[string]any{"website": ""})
	if w.Code != http.StatusOK {
		t.Fatalf("clear status = %d", w.Code)
	}
	if _, present := body["website"]; present {
		t.Errorf("cleared website must be absent: %v", body)
	}
	if body["given_name"] != "Alice" {
		t.Errorf("untouched fields must survive a partial patch: %v", body)
	}

	// Format violations are honest 400s naming the field; nothing persists.
	for field, bad := range map[string]string{"picture": "not-a-url", "birthdate": "05/17/1990", "zoneinfo": "Nowhere/City", "locale": "!!"} {
		w, body = eng.do(t, http.MethodPut, "/api/v1/profile", map[string]any{field: bad})
		if w.Code != http.StatusBadRequest || !strings.Contains(body["message"].(string), field) {
			t.Errorf("%s=%q: status=%d body=%v, want 400 naming the field", field, bad, w.Code, body)
		}
	}
	if row, _ := eng.profiles.Get(context.Background(), p.UserID); row.Picture != nil || row.Birthdate != nil {
		t.Errorf("refused values must not persist: %+v", row)
	}
}

func TestProfile_SelfServiceRequiresAuthenticatedHuman(t *testing.T) {
	eng := newProfileEngine(t, nil)
	w, _ := eng.do(t, http.MethodPut, "/api/v1/profile", map[string]any{"nickname": "x"})
	if w.Code != http.StatusUnauthorized {
		t.Errorf("anonymous PUT /profile = %d, want 401", w.Code)
	}
}

// The admin surface carries the same fields with the same authority rules.
func TestUsers_AdminPutSetsProfileFields(t *testing.T) {
	admin := &domain.Principal{UserID: uuid.New(), Email: "root@system.local", Role: domain.RoleSiteAdmin}
	eng := newProfileEngine(t, admin)
	target := orgUserPrincipal()
	seedUser(selfScopeEngine{userRepo: eng.userRepo}, target)

	// Profile-only body (no user-level field) still authorizes through the
	// actor rules and persists.
	w, body := eng.do(t, http.MethodPut, "/api/v1/users/"+target.UserID.String(), map[string]any{
		"given_name": "Bob", "zoneinfo": "Europe/London",
	})
	if w.Code != http.StatusOK || body["given_name"] != "Bob" || body["zoneinfo"] != "Europe/London" {
		t.Fatalf("admin profile-only PUT: %d %v", w.Code, body)
	}
	// Mixed body: user field + profile field.
	w, body = eng.do(t, http.MethodPut, "/api/v1/users/"+target.UserID.String(), map[string]any{
		"name": "Bob Builder", "family_name": "Builder",
	})
	if w.Code != http.StatusOK || body["name"] != "Bob Builder" || body["family_name"] != "Builder" || body["given_name"] != "Bob" {
		t.Fatalf("admin mixed PUT: %d %v", w.Code, body)
	}
	w, body = eng.do(t, http.MethodGet, "/api/v1/users/"+target.UserID.String(), nil)
	if w.Code != http.StatusOK || body["family_name"] != "Builder" {
		t.Errorf("admin GET must project the profile: %d %v", w.Code, body)
	}
}

type fakeProfileLookup struct{ p *domain.UserProfile }

func (f fakeProfileLookup) Get(_ context.Context, _ uuid.UUID) (*domain.UserProfile, error) {
	return f.p, nil
}

// userinfo: the profile scope releases exactly the set fields (+ name,
// updated_at); the claims parameter releases only the requested ones.
func TestUserinfo_ProfileScopeReleasesOnlySetFields(t *testing.T) {
	uid := uuid.New()
	given, locale := "Alice", "en-GB"
	userUpdated := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	profUpdated := time.Date(2026, 9, 2, 0, 0, 0, 0, time.UTC)
	profile := &domain.UserProfile{UserID: uid, GivenName: &given, Locale: &locale, UpdatedAt: profUpdated}
	serve := func(t *testing.T, scope string, userinfoClaims []string, withProfile bool) map[string]any {
		t.Helper()
		v := &userinfoFakeVerifier{claims: &service.IntrospectionClaims{
			Sub: uid.String(), UserID: uid, Email: "user@example.com", Scope: scope, UserInfoClaims: userinfoClaims,
		}}
		gin.SetMode(gin.ReleaseMode)
		r := gin.New()
		deps := UserinfoHandlerDeps{
			IntrospectionService: service.NewIntrospectionService(nil, v, nil),
			UserLookup:           &fakeUserinfoUserLookup{user: &domain.User{ID: uid, Name: userinfoStrPtr("Alice Example"), UpdatedAt: userUpdated}},
		}
		if withProfile {
			deps.ProfileLookup = fakeProfileLookup{p: profile}
		}
		RegisterUserinfoRoutes(r, deps)
		req := httptest.NewRequest(http.MethodGet, "/api/v1/oidc/userinfo", nil)
		req.Header.Set("Authorization", "Bearer ANY")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d body=%q", w.Code, w.Body.String())
		}
		var body map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &body)
		return body
	}

	body := serve(t, "openid profile", nil, true)
	if body["name"] != "Alice Example" || body["given_name"] != "Alice" || body["locale"] != "en-GB" {
		t.Errorf("profile scope must release the set fields: %v", body)
	}
	if ua, _ := body["updated_at"].(float64); int64(ua) != profUpdated.Unix() {
		t.Errorf("updated_at = %v, want the profile row's %d", body["updated_at"], profUpdated.Unix())
	}
	for _, unset := range []string{"family_name", "middle_name", "nickname", "preferred_username", "profile", "picture", "website", "gender", "birthdate", "zoneinfo"} {
		if v, present := body[unset]; present {
			t.Errorf("%s unset → must be absent, got %v", unset, v)
		}
	}
	// No profile row: name + updated_at (user row) only.
	body = serve(t, "openid profile", nil, false)
	if body["name"] != "Alice Example" || body["given_name"] != nil {
		t.Errorf("without a profile row only name/updated_at may emit: %v", body)
	}
	if ua, _ := body["updated_at"].(float64); int64(ua) != userUpdated.Unix() {
		t.Errorf("updated_at without a profile row = %v, want the user row's %d", body["updated_at"], userUpdated.Unix())
	}
	// Claims parameter: only the requested profile claim, not the whole family.
	body = serve(t, "openid", []string{"locale"}, true)
	if body["locale"] != "en-GB" || body["given_name"] != nil || body["name"] != nil {
		t.Errorf("claims parameter must release only the requested claim: %v", body)
	}
	// Neither scope nor claim → nothing personal.
	body = serve(t, "openid", nil, true)
	for _, k := range []string{"name", "given_name", "locale", "updated_at"} {
		if v, present := body[k]; present {
			t.Errorf("%s released without scope or claim: %v", k, v)
		}
	}
}
