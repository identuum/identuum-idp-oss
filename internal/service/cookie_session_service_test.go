package service

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// inMemoryCookieUserLookup is the tiny CookieSessionUserLookup
// the cookie tests use.
type inMemoryCookieUserLookup struct {
	user *domain.User
}

func (l *inMemoryCookieUserLookup) GetByID(_ context.Context, _ uuid.UUID) (*domain.User, error) {
	return l.user, nil
}

func newCookieHarness(t *testing.T, allowPlain bool) (*CookieSessionService, *UserSessionService, *inMemoryUserSessionRepo, *inMemoryCookieUserLookup) {
	t.Helper()
	repo := newSessionRepo()
	sessions := NewUserSessionService(nil, repo, UserSessionServiceOptions{})
	lookup := &inMemoryCookieUserLookup{
		user: &domain.User{ID: uuid.New(), Email: "alice@example.com", Role: domain.RoleOrgUser},
	}
	svc := NewCookieSessionService(nil, sessions, lookup, CookieSessionServiceOptions{AllowPlainHTTP: allowPlain})
	return svc, sessions, repo, lookup
}

// ---------- Cookie flag posture ----------

func TestCookieSession_IssueDefaultFlags(t *testing.T) {
	svc, _, _, _ := newCookieHarness(t, false)
	c := svc.Issue("sel.val", time.Now().Add(time.Hour))
	if c.Name != "identuum_session" {
		t.Errorf("name = %q", c.Name)
	}
	if !c.HttpOnly {
		t.Errorf("HttpOnly = false")
	}
	if !c.Secure {
		t.Errorf("Secure = false (must default to true)")
	}
	if c.SameSite != http.SameSiteLaxMode {
		t.Errorf("SameSite = %v", c.SameSite)
	}
	if c.Path != "/" {
		t.Errorf("Path = %q", c.Path)
	}
	if c.Domain != "" {
		t.Errorf("Domain must be empty (host-only): %q", c.Domain)
	}
	if c.MaxAge <= 0 {
		t.Errorf("MaxAge = %d", c.MaxAge)
	}
}

func TestCookieSession_IssueAllowPlainHTTPClearsSecure(t *testing.T) {
	svc, _, _, _ := newCookieHarness(t, true)
	c := svc.Issue("sel.val", time.Now().Add(time.Hour))
	if c.Secure {
		t.Errorf("AllowPlainHTTP did not clear Secure flag")
	}
}

func TestCookieSession_ClearMatchesIssueFlags(t *testing.T) {
	svc, _, _, _ := newCookieHarness(t, false)
	c := svc.Clear()
	if c.Value != "" {
		t.Errorf("clear value = %q", c.Value)
	}
	if c.MaxAge != -1 {
		t.Errorf("clear MaxAge = %d", c.MaxAge)
	}
	if !c.HttpOnly {
		t.Errorf("clear HttpOnly = false")
	}
	if !c.Secure {
		t.Errorf("clear Secure = false")
	}
}

// ---------- Read ----------

func TestCookieSession_ReadAbsentCookie(t *testing.T) {
	svc, _, _, _ := newCookieHarness(t, false)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	if _, ok := svc.Read(r); ok {
		t.Errorf("absent cookie should report ok=false")
	}
}

func TestCookieSession_ReadEmptyValueCookie(t *testing.T) {
	svc, _, _, _ := newCookieHarness(t, false)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: "identuum_session", Value: ""})
	if _, ok := svc.Read(r); ok {
		t.Errorf("empty cookie should report ok=false")
	}
}

// ---------- Resolve ----------

func TestCookieSession_ResolveValidCookieReturnsSessionAndUser(t *testing.T) {
	svc, sessions, _, lookup := newCookieHarness(t, false)
	uid := lookup.user.ID
	issued, err := sessions.CreateUserSession(context.Background(), CreateUserSessionInput{UserID: uid})
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	resolved, err := svc.Resolve(context.Background(), issued.RefreshToken)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if resolved == nil || resolved.Session == nil || resolved.User == nil {
		t.Fatalf("nil resolution: %+v", resolved)
	}
	if resolved.User.ID != uid {
		t.Errorf("user id mismatch")
	}
	if resolved.Session.UserID != uid {
		t.Errorf("session user id mismatch")
	}
}

// P0-5: tenant deletion is an authentication boundary. A cookie whose user's
// organization is non-operational (deactivated OR deleted) MUST NOT resolve —
// this catches DEACTIVATION, which does not cascade deleted_at onto the user.
func TestCookieSession_NonOperationalOrgRejected(t *testing.T) {
	resolveWithOrg := func(t *testing.T, org *domain.Organization) (*CookieSessionLookupResult, error) {
		t.Helper()
		svc, sessions, _, lookup := newCookieHarness(t, false)
		lookup.user.OrganizationID = org.ID
		svc.WithOrganizationLookup(newFakeOrgRepo(org))
		issued, err := sessions.CreateUserSession(context.Background(), CreateUserSessionInput{UserID: lookup.user.ID})
		if err != nil {
			t.Fatalf("create session: %v", err)
		}
		return svc.Resolve(context.Background(), issued.RefreshToken)
	}

	t.Run("deactivated org rejected", func(t *testing.T) {
		resolved, err := resolveWithOrg(t, &domain.Organization{ID: uuid.New(), Active: false})
		if err != nil {
			t.Fatalf("resolve err: %v", err)
		}
		if resolved != nil {
			t.Fatalf("deactivated org: resolution must be nil, got %+v", resolved)
		}
	})

	t.Run("deleted org rejected", func(t *testing.T) {
		now := time.Now()
		resolved, err := resolveWithOrg(t, &domain.Organization{ID: uuid.New(), Active: true, DeletedAt: &now})
		if err != nil {
			t.Fatalf("resolve err: %v", err)
		}
		if resolved != nil {
			t.Fatalf("deleted org: resolution must be nil")
		}
	})

	t.Run("operational org resolves", func(t *testing.T) {
		resolved, err := resolveWithOrg(t, &domain.Organization{ID: uuid.New(), Active: true})
		if err != nil {
			t.Fatalf("resolve err: %v", err)
		}
		if resolved == nil || resolved.User == nil {
			t.Fatalf("operational org must resolve to a session+user")
		}
	})
}

func TestCookieSession_ResolveUnknownCookieReturnsNil(t *testing.T) {
	svc, _, _, _ := newCookieHarness(t, false)
	resolved, err := svc.Resolve(context.Background(), "ffffffff-ffff-7fff-ffff-ffffffffffff.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if resolved != nil {
		t.Errorf("expected nil resolution, got %+v", resolved)
	}
}

func TestCookieSession_ResolveMalformedCookieReturnsNil(t *testing.T) {
	svc, _, _, _ := newCookieHarness(t, false)
	resolved, err := svc.Resolve(context.Background(), "not-a-valid-token")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if resolved != nil {
		t.Errorf("expected nil resolution, got %+v", resolved)
	}
}

func TestCookieSession_ResolveEmptyReturnsNil(t *testing.T) {
	svc, _, _, _ := newCookieHarness(t, false)
	resolved, err := svc.Resolve(context.Background(), "")
	if err != nil || resolved != nil {
		t.Errorf("empty cookie: err=%v resolved=%v", err, resolved)
	}
}

// ---------- Construction ----------

func TestNewCookieSessionService_NilSessionsPanics(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("nil sessions did not panic")
		}
	}()
	_ = NewCookieSessionService(nil, nil, nil, CookieSessionServiceOptions{})
}
