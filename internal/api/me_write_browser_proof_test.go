package api

// Item 1a (OSS-0913-A; posture: OSS-O18-CSRF-CHECK). The /me writes carry no
// CSRF token and no limiter of their own. Their defence is that the API takes
// the user only from an Authorization bearer (never from a cookie), and that
// the console's /bff boundary, which lifts the access_token cookie into a
// bearer, refuses every request that does not prove it came from the console
// page. This test pins that posture for every /me write, D3's DELETE
// included, through the REAL router and the REAL uiserve boundary:
//
//   - a direct API call carrying only the cookie is not signed in (401);
//   - /bff without X-Requested-With is 403 csrf_failed missing_request_header;
//   - /bff from a foreign or a sibling-subdomain Origin is 403
//     csrf_failed origin_not_permitted;
//   - /bff from the same origin with the header reaches the route as the
//     signed-in user (the route's own answer, never 401/403/404);
//   - a CORS preflight from a foreign origin gets no Access-Control-Allow-*.
//
// Messages carry status codes and reasons only, never a cookie or a token.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/repository"
	"github.com/identuum/identuum-idp-oss/internal/server"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// meWriteCookie is the access_token cookie value the stub verifier accepts.
const meWriteCookie = "me-write-access"

// meWriteUserRepo is the user store behind the profile and MFA surfaces.
type meWriteUserRepo struct {
	repository.UserRepository
	user *domain.User
}

func (r *meWriteUserRepo) GetByID(_ context.Context, id uuid.UUID) (*domain.User, error) {
	if r.user != nil && r.user.ID == id {
		cp := *r.user
		return &cp, nil
	}
	return nil, domain.ErrUserNotFound
}

func (r *meWriteUserRepo) GetByIDWithOrg(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	return r.GetByID(ctx, id)
}

// meWriteRoute is one /me write and the answer its own handler gives the
// signed-in fixture user: a handler answer proves the boundary forwarded the
// request with the user's principal. The fixture has no mail server (email
// verification answers 503 email_delivery_not_configured), no authenticator
// (MFA disable answers 400 mfa_not_enrolled) and no profile store (profile
// answers 503); the other two succeed.
type meWriteRoute struct {
	method, path, body string
	want               int
	wantError          string
}

var meWriteRoutes = []meWriteRoute{
	{http.MethodPost, "/api/v1/me/email/verification", "", http.StatusServiceUnavailable, "email_delivery_not_configured"},
	{http.MethodPost, "/api/v1/me/sessions/revoke-all", "", http.StatusNoContent, ""},
	{http.MethodPost, "/api/v1/me/mfa/disable", `{"code":"000000"}`, http.StatusBadRequest, "mfa_not_enrolled"},
	{http.MethodPut, "/api/v1/profile", `{"name":"Alice"}`, http.StatusServiceUnavailable, "profile store unavailable"},
	{http.MethodDelete, "/api/v1/me/consents/client-x", "", http.StatusNoContent, ""},
}

// newMeWriteEngine mounts every /me write on the real router with the real
// UI boundary in front of it.
func newMeWriteEngine(t *testing.T) *gin.Engine {
	t.Helper()
	ctx := context.Background()
	alice, org := uuid.New(), uuid.New()
	user := &domain.User{ID: alice, OrganizationID: org, Email: "alice@example.com", Role: domain.RoleOrgUser, AuthSource: domain.AuthSourceLocal, EmailVerified: false}
	users := d3UserLookup{users: map[uuid.UUID]*domain.User{alice: user}}
	userRepo := &meWriteUserRepo{user: user}

	consents := service.NewConsentService(nil, &d3ConsentRepo{rows: map[string]*domain.OAuthConsent{}})
	if _, err := consents.Grant(ctx, service.GrantConsentInput{UserID: alice, OrganizationID: &org, ClientID: "client-x", Scope: "openid"}); err != nil {
		t.Fatalf("seed consent: %v", err)
	}
	denylist := service.NewTokenRevocationService(nil, &d3DenyRepo{jtis: map[string]bool{}})
	refresh := service.NewRefreshTokenService(nil, &d3RefreshRepo{byID: map[uuid.UUID]*domain.RefreshToken{}}, service.RefreshTokenServiceOptions{}).
		WithTokenRevocationService(denylist)
	clients := &d3ClientRepo{live: map[string]*domain.Client{"client-x": {ID: uuid.New(), ClientID: "client-x", Name: "Expense App", OrganizationID: &org}}}

	return NewOSSEngine(OSSRouterDeps{
		DiscoveryConfig: server.OIDCDiscoveryConfig{Issuer: "https://idp.test"},
		UIStaticDir:     uiExportDir(t),
		TokenVerifier: d3Verifier{principals: map[string]*domain.Principal{
			meWriteCookie: {UserID: alice, Sub: alice.String(), Email: user.Email, Role: domain.RoleOrgUser, OrganizationID: org},
		}},
		UserLookup:               users,
		UserRepo:                 userRepo,
		UserSessionService:       service.NewUserSessionService(nil, discoveryFakeSessionRepo{}, service.UserSessionServiceOptions{}),
		MFAEnrollment:            service.NewMFAEnrollmentService(nil, service.MFAEnrollmentRepoOptions{Users: userRepo}, service.MFAEnrollmentServiceOptions{}),
		EmailVerificationService: service.NewEmailVerificationService(userRepo, nil, nil, audit.NoopService{}, service.EmailVerificationServiceOptions{}),
		ConsentService:           consents,
		RefreshTokenService:      refresh,
		TokenRevocationService:   denylist,
		ClientRepo:               clients,
		Audit:                    &audit.Recorder{},
	})
}

func meWriteDo(e http.Handler, method, target, body string, mutate ...func(*http.Request)) *httptest.ResponseRecorder {
	var req *http.Request
	if body != "" {
		req = httptest.NewRequest(method, target, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequest(method, target, nil)
	}
	for _, m := range mutate {
		m(req)
	}
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	return rec
}

// meWriteRefusal reads the error and reason fields of a JSON refusal.
func meWriteRefusal(rec *httptest.ResponseRecorder) (string, string) {
	var v struct {
		Error  string `json:"error"`
		Reason string `json:"reason"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &v)
	return v.Error, v.Reason
}

// RULE: ME-WRITE-BROWSER-PROOF-1
func TestMeWrites_RequireTheBrowserProof(t *testing.T) {
	sameOrigin := "http://example.com" // httptest.NewRequest's host
	for _, r := range meWriteRoutes {
		label := r.method + " " + r.path
		t.Run(label, func(t *testing.T) {
			// Direct API, the cookie alone: no principal.
			e := newMeWriteEngine(t)
			rec := meWriteDo(e, r.method, r.path, r.body, withCookie(meWriteCookie),
				withHeader("Origin", "https://evil.example"))
			if rec.Code != http.StatusUnauthorized {
				t.Errorf("direct API call with only the access_token cookie = %d; want 401 (the API never reads the cookie)", rec.Code)
			}

			// /bff without the request header (a form or a link).
			rec = meWriteDo(newMeWriteEngine(t), r.method, "/bff"+r.path, r.body, withCookie(meWriteCookie),
				withHeader("Sec-Fetch-Site", "cross-site"))
			if e, reason := meWriteRefusal(rec); rec.Code != http.StatusForbidden || e != "csrf_failed" || reason != "missing_request_header" {
				t.Errorf("/bff without X-Requested-With = %d %s/%s; want 403 csrf_failed missing_request_header", rec.Code, e, reason)
			}

			// /bff from a foreign origin and from a sibling subdomain.
			for _, origin := range []string{"https://evil.example", "http://a.example.com"} {
				rec = meWriteDo(newMeWriteEngine(t), r.method, "/bff"+r.path, r.body, withCookie(meWriteCookie),
					withHeader(uiBFFRequiredHeader, uiBFFRequiredHeaderValue), withHeader("Origin", origin))
				if e, reason := meWriteRefusal(rec); rec.Code != http.StatusForbidden || e != "csrf_failed" || reason != "origin_not_permitted" {
					t.Errorf("/bff from origin %s = %d %s/%s; want 403 csrf_failed origin_not_permitted", origin, rec.Code, e, reason)
				}
			}

			// /bff from the same origin with the header: the route answers as
			// the signed-in user.
			rec = meWriteDo(newMeWriteEngine(t), r.method, "/bff"+r.path, r.body, withCookie(meWriteCookie),
				withHeader(uiBFFRequiredHeader, uiBFFRequiredHeaderValue), withHeader("Origin", sameOrigin),
				withHeader("Sec-Fetch-Site", "same-origin"))
			if errField, _ := meWriteRefusal(rec); rec.Code != r.want || errField != r.wantError {
				t.Errorf("same-origin /bff with the header = %d %q; want the route's own answer %d %q for the signed-in user", rec.Code, errField, r.want, r.wantError)
			}

			// CORS preflight from a foreign origin.
			rec = meWriteDo(newMeWriteEngine(t), http.MethodOptions, r.path, "",
				withHeader("Origin", "https://evil.example"),
				withHeader("Access-Control-Request-Method", r.method),
				withHeader("Access-Control-Request-Headers", "x-requested-with"))
			for name := range rec.Header() {
				if strings.HasPrefix(strings.ToLower(name), "access-control-allow-") {
					t.Errorf("preflight from a foreign origin answered %s; want no Access-Control-Allow-* header", name)
				}
			}
		})
	}
}
