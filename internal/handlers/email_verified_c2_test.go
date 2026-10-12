package handlers

// OSS-0912-C2 (owner Q1 (a), Q2 (b), Q3 (a)): userinfo's email_verified says
// the mailbox was proven; the user projection keeps email_verified as the
// activation flag and adds email_verified_via and email_proven; POST
// /api/v1/me/email/verification sends the signed-in user's own link.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/mw"
	"github.com/identuum/identuum-idp-oss/internal/repository"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

func TestUserinfo_EmailVerifiedReadsTheProof(t *testing.T) {
	for _, c := range []struct {
		via  *string
		want bool
	}{
		{nil, false},
		{userinfoStrPtr(domain.EmailVerifiedViaAdminLink), false},
		{userinfoStrPtr(domain.EmailVerifiedViaAdminSet), false},
		{userinfoStrPtr(domain.EmailVerifiedViaSetup), false},
		{userinfoStrPtr(domain.EmailVerifiedViaEmailLink), true},
		{userinfoStrPtr(domain.EmailVerifiedViaUpstreamIDP), true},
		{userinfoStrPtr(domain.EmailVerifiedViaLegacy), true},
	} {
		uid := uuid.New()
		v := &userinfoFakeVerifier{claims: &service.IntrospectionClaims{Sub: uid.String(), UserID: uid, Email: "user@example.com", Scope: "openid email"}}
		gin.SetMode(gin.ReleaseMode)
		r := gin.New()
		RegisterUserinfoRoutes(r, UserinfoHandlerDeps{
			IntrospectionService: service.NewIntrospectionService(nil, v, nil),
			UserLookup:           &fakeUserinfoUserLookup{user: &domain.User{ID: uid, EmailVerified: true, EmailVerifiedVia: c.via}},
		})
		req := httptest.NewRequest(http.MethodGet, "/api/v1/oidc/userinfo", nil)
		req.Header.Set("Authorization", "Bearer ANY")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		var body map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &body)
		if w.Code != http.StatusOK || body["email_verified"] != c.want {
			via := "<nil>"
			if c.via != nil {
				via = *c.via
			}
			t.Errorf("via %s (activated): status %d email_verified %v; want %v", via, w.Code, body["email_verified"], c.want)
		}
	}
}

func TestToSafeUser_CarriesActivationAndProofApart(t *testing.T) {
	adminLink := domain.EmailVerifiedViaAdminLink
	for _, c := range []struct {
		u          *domain.User
		wantVia    any
		wantProven bool
	}{
		{&domain.User{ID: uuid.New(), EmailVerified: true, EmailVerifiedVia: &adminLink}, "admin_link", false},
		{&domain.User{ID: uuid.New(), EmailVerified: true, EmailVerifiedVia: userinfoStrPtr(domain.EmailVerifiedViaLegacy)}, "legacy", true},
		{&domain.User{ID: uuid.New(), EmailVerified: false}, nil, false},
	} {
		raw, err := json.Marshal(toSafeUser(c.u))
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		_ = json.Unmarshal(raw, &m)
		if m["email_verified"] != c.u.EmailVerified {
			t.Errorf("email_verified = %v; want the activation flag %v", m["email_verified"], c.u.EmailVerified)
		}
		if v, present := m["email_verified_via"]; !present || v != c.wantVia {
			t.Errorf("email_verified_via = %v (present %v); want %v, always present", v, present, c.wantVia)
		}
		if m["email_proven"] != c.wantProven {
			t.Errorf("email_proven = %v; want %v", m["email_proven"], c.wantProven)
		}
	}
}

// ---- POST /api/v1/me/email/verification ----

type c2Users struct{ byID map[uuid.UUID]*domain.User }

func (u *c2Users) FindUsersByEmail(context.Context, string) ([]*domain.User, error) { return nil, nil }
func (u *c2Users) GetByID(_ context.Context, id uuid.UUID) (*domain.User, error) {
	if x, ok := u.byID[id]; ok {
		return x, nil
	}
	return nil, domain.ErrUserNotFound
}
func (u *c2Users) Update(context.Context, uuid.UUID, uuid.UUID, repository.UpdateUserOptions) (*domain.User, error) {
	return nil, domain.ErrUserNotFound
}

type c2Verifs struct{ created int }

func (v *c2Verifs) Create(context.Context, *domain.EmailVerification) error { v.created++; return nil }
func (v *c2Verifs) GetByTokenHash(context.Context, string) (*domain.EmailVerification, error) {
	return nil, nil
}
func (v *c2Verifs) MarkAsUsed(context.Context, string) error     { return nil }
func (v *c2Verifs) DeleteExpired(context.Context) (int64, error) { return 0, nil }

type c2Notifier struct {
	sends int
	err   error
}

func (n *c2Notifier) SendVerificationEmail(context.Context, *domain.User, string) error {
	n.sends++
	return n.err
}

func TestSendOwnVerificationRoute(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	unproven := &domain.User{ID: uuid.New(), Email: "me@example.com", EmailVerified: true, EmailVerifiedVia: userinfoStrPtr(domain.EmailVerifiedViaAdminLink)}
	proven := &domain.User{ID: uuid.New(), Email: "p@example.com", EmailVerified: true, EmailVerifiedVia: userinfoStrPtr(domain.EmailVerifiedViaEmailLink)}
	users := &c2Users{byID: map[uuid.UUID]*domain.User{unproven.ID: unproven, proven.ID: proven}}
	tokenShape := regexp.MustCompile(`[0-9a-f]{64}`)

	serve := func(notifier service.EmailVerificationNotifier, limiter gin.HandlerFunc, who *domain.User) *httptest.ResponseRecorder {
		t.Helper()
		svc := service.NewEmailVerificationService(users, &c2Verifs{}, notifier, audit.NoopService{}, service.EmailVerificationServiceOptions{})
		r := gin.New()
		r.Use(func(c *gin.Context) {
			if who != nil {
				mw.SetPrincipal(c, &domain.Principal{UserID: who.ID, Role: domain.RoleOrgUser})
			}
			c.Next()
		})
		RegisterAccountLifecycleRoutes(r, AccountLifecycleHandlerDeps{EmailVerify: svc, SendOwnVerificationLimiter: limiter})
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/v1/me/email/verification", nil))
		return w
	}
	answer := func(w *httptest.ResponseRecorder) map[string]any {
		var m map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &m)
		return m
	}

	limited := 0
	countingLimiter := func(c *gin.Context) { limited++; c.Next() }
	if w := serve(&c2Notifier{}, countingLimiter, nil); w.Code != http.StatusUnauthorized || limited != 0 {
		t.Errorf("no principal = %d (limiter ran %d times); want 401 before the limiter", w.Code, limited)
	}
	n := &c2Notifier{}
	w := serve(n, countingLimiter, unproven)
	if w.Code != http.StatusOK || answer(w)["status"] != "sent" || n.sends != 1 || limited != 1 || tokenShape.MatchString(w.Body.String()) {
		t.Errorf("send = %d %s (sends %d, limiter %d); want 200 sent, one mail, the limiter, no token", w.Code, w.Body.String(), n.sends, limited)
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control = %q; want no-store", w.Header().Get("Cache-Control"))
	}
	if w := serve(&c2Notifier{}, nil, proven); w.Code != http.StatusOK || answer(w)["status"] != "already_verified" {
		t.Errorf("proven = %d %s; want 200 already_verified", w.Code, w.Body.String())
	}
	if w := serve(service.UnconfiguredEmailNotifier{}, nil, unproven); w.Code != http.StatusServiceUnavailable || answer(w)["error"] != "email_delivery_not_configured" {
		t.Errorf("no SMTP = %d %s; want 503 email_delivery_not_configured", w.Code, w.Body.String())
	}
	if w := serve(&c2Notifier{err: context.DeadlineExceeded}, nil, unproven); w.Code != http.StatusBadGateway || answer(w)["error"] != "email_delivery_failed" {
		t.Errorf("send failure = %d %s; want 502 email_delivery_failed", w.Code, w.Body.String())
	}
	if w := serve(&c2Notifier{}, nil, &domain.User{ID: uuid.New()}); w.Code != http.StatusNotFound {
		t.Errorf("unknown user = %d; want 404", w.Code)
	}
	blocking := func(c *gin.Context) {
		c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": "rate_limited"})
	}
	if w := serve(&c2Notifier{}, blocking, unproven); w.Code != http.StatusTooManyRequests {
		t.Errorf("limited = %d; want 429", w.Code)
	}
}
