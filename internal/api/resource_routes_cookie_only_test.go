package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

type d4AuditReader struct{}

func (d4AuditReader) ListEvents(context.Context, *uuid.UUID, domain.AuditFilters) ([]domain.AuditEvent, bool, error) {
	return nil, false, nil
}

// Owner decision D4 (PLAN-C-CLOSE, 2026-09-23), unit proof: the global CORS
// middleware lets a disallowed-origin SIMPLE request reach the router (it
// only withholds the Allow-* headers), and no code changes that. What makes
// it harmless on the resource surface is that resource routes accept a
// Bearer only: a cross-site simple request carrying the browser's auth
// COOKIES, and no Authorization header, is refused 401 by the bearer guard —
// never served as the cookie's user. Three route classes, GET and POST.
// (The UI is NOT mounted here: this is the plain API surface.)
func TestResourceRoutes_D4_CrossSiteCookieOnlyRequestIsRefused401(t *testing.T) {
	org := uuid.New()
	target := &domain.User{ID: uuid.New(), OrganizationID: org, Role: domain.RoleOrgUser, Email: "target@example.test"}
	admin := uiPrincipal("admin@example.test")
	admin.Role, admin.OrganizationID, admin.Scope = domain.RoleOrgAdmin, org, domain.ScopeUsersRead
	verifier := uiStubVerifier{principals: map[string]*domain.Principal{"admin": admin}}
	repo := &uiSecurityUserRepo{user: target}
	e := NewOSSEngine(OSSRouterDeps{
		TokenVerifier: verifier, UserRepo: repo, UserService: service.NewUserService(nil, repo),
		AuditReader: d4AuditReader{},
	})

	// Three route classes as the minimal engine mounts them: the user
	// directory (GET + POST), self-service profile (PUT) and the audit log
	// (GET).
	for _, tc := range []struct{ class, method, path string }{
		{"user directory (read)", http.MethodGet, "/api/v1/users/" + target.ID.String()},
		{"user directory (write)", http.MethodPost, "/api/v1/users"},
		{"self-service profile (write)", http.MethodPut, "/api/v1/profile"},
		{"audit log (read)", http.MethodGet, "/api/v1/audit/events"},
	} {
		t.Run(tc.class, func(t *testing.T) {
			// Control: the SAME credential as a Bearer is recognised (the
			// route answers something other than the no-credential 401).
			ctl := httptest.NewRequest(tc.method, tc.path, strings.NewReader(`{}`))
			ctl.Header.Set("Content-Type", "application/json")
			ctl.Header.Set("Authorization", "Bearer admin")
			crec := httptest.NewRecorder()
			e.ServeHTTP(crec, ctl)

			req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(`{"x":1}`))
			req.Header.Set("Origin", "https://evil.example")
			req.Header.Set("Content-Type", "text/plain")
			req.AddCookie(&http.Cookie{Name: "access_token", Value: "admin"})
			req.AddCookie(&http.Cookie{Name: "refresh_token", Value: "admin-refresh"})
			rec := httptest.NewRecorder()
			e.ServeHTTP(rec, req)
			t.Logf("%s %s: cookie-only cross-site %d %s | Bearer control %d", tc.method, tc.path, rec.Code, strings.TrimSpace(rec.Body.String()), crec.Code)
			if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), `"no_credential"`) {
				t.Fatalf("%s %s with the auth cookies only: %d %q, want 401 no_credential", tc.method, tc.path, rec.Code, rec.Body.String())
			}
			if crec.Code == http.StatusUnauthorized || crec.Code == http.StatusNotFound && tc.method != http.MethodGet {
				t.Fatalf("control: %s %s with the same credential as a Bearer answered %d — the route is not mounted or the credential is not recognised, so the refusal above proves nothing", tc.method, tc.path, crec.Code)
			}
		})
	}
}
