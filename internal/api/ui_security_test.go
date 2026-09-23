package api

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/mw"
	"github.com/identuum/identuum-idp-oss/internal/repository"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

func TestUI_Security_LogoutForwardsRefreshProofOnlyWithoutExplicitBearer(t *testing.T) {
	for _, explicit := range []bool{false, true} {
		e := uiEngine(t, uiExportDir(t))
		e.POST("/api/v1/auth/logout", func(c *gin.Context) {
			var body map[string]string
			_ = json.NewDecoder(c.Request.Body).Decode(&body)
			if (body["refresh_token"] != "") == explicit {
				t.Error("logout refresh proof did not respect explicit credential precedence")
			}
			if c.GetHeader("Cookie") != "" {
				t.Error("raw cookie header reached API handler")
			}
			c.Status(http.StatusNoContent)
		})
		headers := []func(*http.Request){withHeader("Cookie", "refresh_token=fixture"), withHeader(uiBFFRequiredHeader, uiBFFRequiredHeaderValue)}
		if explicit {
			headers = append(headers, withHeader("Authorization", "Bearer other"))
		}
		w := uiPost(e, uiBFFLogoutPath, headers...)
		if w.Code != http.StatusNoContent {
			t.Errorf("status = %d, want 204", w.Code)
		}
	}
}

func TestUI_Security_StaleAccessCookieDoesNotStrandLogoutRefreshProof(t *testing.T) {
	e := uiEngine(t, uiExportDir(t))
	called := false
	e.POST("/api/v1/auth/logout", func(c *gin.Context) {
		called = true
		var body map[string]string
		_ = json.NewDecoder(c.Request.Body).Decode(&body)
		if body["refresh_token"] == "" {
			t.Error("logout lost the remaining refresh proof")
		}
		if c.GetHeader("Authorization") != "" {
			t.Error("stale access credential was forwarded again")
		}
		c.Status(http.StatusNoContent)
	})
	w := uiPost(e, uiBFFLogoutPath, withHeader("Cookie", "access_token=stale; refresh_token=fixture"), withHeader(uiBFFRequiredHeader, uiBFFRequiredHeaderValue))
	if w.Code != http.StatusNoContent || !called {
		t.Errorf("logout did not reach the revoker: status=%d called=%t", w.Code, called)
	}
}

type uiSecurityUserRepo struct {
	repository.UserRepository
	user *domain.User
}

func (r *uiSecurityUserRepo) GetByID(context.Context, uuid.UUID) (*domain.User, error) {
	return r.user, nil
}

func TestUI_Security_RealUserRouteAuthoritySurvivesBoundary(t *testing.T) {
	org := uuid.New()
	target := &domain.User{ID: uuid.New(), OrganizationID: org, Role: domain.RoleOrgUser, Email: "target@example.test"}
	admin := uiPrincipal("admin@example.test")
	admin.Role, admin.OrganizationID, admin.Scope = domain.RoleOrgAdmin, org, domain.ScopeUsersRead
	foreign := *admin
	foreign.OrganizationID = uuid.New()
	verifier := uiStubVerifier{principals: map[string]*domain.Principal{"admin": admin, "foreign": &foreign, "user": uiPrincipal("user@example.test")}}
	repo := &uiSecurityUserRepo{user: target}
	e := NewOSSEngine(OSSRouterDeps{UIStaticDir: uiExportDir(t), TokenVerifier: verifier, UserRepo: repo, UserService: service.NewUserService(nil, repo)})
	for _, tc := range []struct {
		name, credential string
		status           int
	}{
		{"same tenant administrator", "admin", http.StatusOK},
		{"wrong tenant administrator", "foreign", http.StatusNotFound},
		{"ordinary user", "user", http.StatusForbidden},
		{"anonymous", "", http.StatusUnauthorized},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, prefix := range []string{"", "/bff"} {
				var wCode int
				if prefix == "/bff" {
					wCode = uiGet(e, prefix+"/api/v1/users/"+target.ID.String(), withCookie(tc.credential)).Code
				} else if tc.credential != "" {
					wCode = uiGet(e, "/api/v1/users/"+target.ID.String(), withHeader("Authorization", "Bearer "+tc.credential)).Code
				} else {
					wCode = uiGet(e, "/api/v1/users/"+target.ID.String()).Code
				}
				if wCode != tc.status {
					t.Errorf("prefix %q: status = %d, want %d", prefix, wCode, tc.status)
				}
			}
		})
	}
}

func TestUI_Security_StaticSymlinkCannotEscapeExport(t *testing.T) {
	dir := uiExportDir(t)
	if err := os.Symlink(filepath.Join(filepath.Dir(dir), "secret.txt"), filepath.Join(dir, "assets", "escape.txt")); err != nil {
		t.Fatal(err)
	}
	e := uiEngine(t, dir)
	w := uiGet(e, "/assets/escape.txt")
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
	if strings.Contains(w.Body.String(), "outside the export root") {
		t.Error("static response exposed a file outside the export root")
	}
}

func TestUI_Security_LogoutHonorsExplicitBearer(t *testing.T) {
	e := uiEngine(t, uiExportDir(t))
	e.POST("/api/v1/auth/logout", func(c *gin.Context) {
		p, ok := mw.PrincipalFromContext(c)
		if !ok || p.Email != "bob@example.test" {
			t.Error("logout used the ambient cookie instead of the explicit principal")
		}
		c.Status(http.StatusNoContent)
	})
	w := uiPost(e, uiBFFLogoutPath, withCookie("good"), withHeader("Authorization", "Bearer other"), withHeader(uiBFFRequiredHeader, uiBFFRequiredHeaderValue))
	if w.Code != http.StatusNoContent {
		t.Errorf("status = %d, want 204", w.Code)
	}
}

func TestUI_Security_OriginIsAnOriginNotJustAHost(t *testing.T) {
	for _, origin := range []string{"http://example.com/path", "http://user@example.com", "http://example.com?query", "http://example.com#fragment", "https://example.com"} {
		t.Run(origin, func(t *testing.T) {
			e := uiEngine(t, uiExportDir(t))
			w := uiPost(e, "/bff/api/v1/probe", withCookie("good"), withHeader(uiBFFRequiredHeader, uiBFFRequiredHeaderValue), withHeader("Origin", origin))
			if w.Code != http.StatusForbidden {
				t.Errorf("status = %d, want 403", w.Code)
			}
		})
	}
}

func TestUI_Security_UnconfirmedMarkerCannotBecomeLogoutSuccess(t *testing.T) {
	e := uiEngine(t, uiExportDir(t))
	e.POST("/api/v1/auth/logout", func(c *gin.Context) {
		c.Header("X-Identuum-Logout", "revocation_unconfirmed")
		c.Status(http.StatusNoContent)
	})
	w := uiPost(e, uiBFFLogoutPath, withCookie("good"), withHeader(uiBFFRequiredHeader, uiBFFRequiredHeaderValue))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"logout":"local_only"`) {
		t.Error("unconfirmed revocation was reported as a successful logout")
	}
}
