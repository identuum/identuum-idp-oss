package mw

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// A service-account token has no session, so the session gate never judged it:
// a disabled account, or a deactivated organization, kept working until the
// token expired. WithServiceAccountLiveness judges it at use.

func probeSA(t *testing.T, p *domain.Principal, opts ...BearerOption) int {
	t.Helper()
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(BearerPrincipal(nil, &stubVerifier{principal: p}, nil, nil, opts...))
	r.Use(RequireSiteAdmin())
	r.GET("/probe", func(c *gin.Context) { c.Status(http.StatusOK) })
	req := httptest.NewRequest(http.MethodGet, "/probe", nil)
	req.Header.Set("Authorization", "Bearer some-token-value")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec.Code
}

func TestBearerPrincipal_ServiceAccountTokenIsJudgedAtUse(t *testing.T) {
	sa := &domain.Principal{Role: domain.RoleSiteAdmin, ActorType: "service_account", Sub: uuid.NewString(), OrganizationID: uuid.New(), TokenID: "jti-sa"}
	user := &domain.Principal{Role: domain.RoleSiteAdmin, ActorType: "user", UserID: uuid.New()}

	calls := 0
	check := func(live bool, err error) BearerOption {
		return WithServiceAccountLiveness(func(_ context.Context, subject string) (bool, error) {
			calls++
			if subject != sa.Sub {
				t.Errorf("the check was given %q; want the token's own subject %q", subject, sa.Sub)
			}
			return live, err
		})
	}

	if got := probeSA(t, sa, check(true, nil)); got != http.StatusOK {
		t.Errorf("a live service account: status = %d, want 200", got)
	}
	if got := probeSA(t, sa, check(false, nil)); got != http.StatusUnauthorized {
		t.Errorf("a disabled account or deactivated organization: status = %d, want 401", got)
	}
	if got := probeSA(t, sa, check(false, errors.New("store down"))); got != http.StatusServiceUnavailable {
		t.Errorf("the check cannot run: status = %d, want 503 (refused, not admitted)", got)
	}

	before := calls
	if got := probeSA(t, user, check(false, nil)); got != http.StatusOK {
		t.Errorf("a console user token: status = %d, want 200 (not this check's business)", got)
	}
	if calls != before {
		t.Error("the service-account check was consulted for a user token")
	}

	if got := probeSA(t, sa); got != http.StatusOK {
		t.Errorf("no check wired: status = %d, want 200 as before", got)
	}
}
