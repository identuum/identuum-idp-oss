package service

import (
	"context"
	"errors"
	"testing"

	"github.com/golang-jwt/jwt/v5"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

func consentedClientClaims(t *testing.T, svc *UserTokenService, user *domain.User, session *domain.Session, consented string) (jwt.MapClaims, *UserAccessTokenResponse) {
	t.Helper()
	resp, err := svc.IssueForConsentedClient(context.Background(), user, session, "cli-1", consented)
	if err != nil {
		t.Fatalf("IssueForConsentedClient(%q): %v", consented, err)
	}
	tok, _, err := jwt.NewParser(jwt.WithValidMethods([]string{"EdDSA"})).ParseUnverified(resp.AccessToken, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return tok.Claims.(jwt.MapClaims), resp
}

// RULE: TOKEN-SCOPE-INTERSECTION-1
func TestIssueForConsentedClient_ScopeIsConsentIntersectRole(t *testing.T) {
	svc, _, _ := newUserTokenSvc(t)

	t.Run("consented but role-forbidden never lands", func(t *testing.T) {
		user, session := newUserAndSession(t)
		user.Role = domain.RoleOrgUser
		claims, resp := consentedClientClaims(t, svc, user, session, "openid profile clients:read users:delete")
		if claims["scope"] != "openid profile" {
			t.Errorf("org_user token scope = %v, want %q — consent must not grant beyond the role", claims["scope"], "openid profile")
		}
		if resp.Scope != "openid profile" {
			t.Errorf("Response.Scope = %q, want the stamped claim", resp.Scope)
		}
	})

	t.Run("role-permitted but unconsented never lands", func(t *testing.T) {
		user, session := newUserAndSession(t)
		user.Role = domain.RoleOrgAdmin
		claims, _ := consentedClientClaims(t, svc, user, session, "openid")
		if claims["scope"] != "openid" {
			t.Errorf("org_admin token scope = %v, want %q — the role set must not leak past consent", claims["scope"], "openid")
		}
	})

	t.Run("consented and role-permitted lands (control)", func(t *testing.T) {
		user, session := newUserAndSession(t)
		user.Role = domain.RoleOrgAdmin
		claims, resp := consentedClientClaims(t, svc, user, session, "openid clients:read")
		if claims["scope"] != "openid clients:read" {
			t.Errorf("org_admin token scope = %v, want %q", claims["scope"], "openid clients:read")
		}
		if resp.Scope != "openid clients:read" {
			t.Errorf("Response.Scope = %q", resp.Scope)
		}
	})

	t.Run("empty consent carries no scope claim", func(t *testing.T) {
		user, session := newUserAndSession(t)
		user.Role = domain.RoleOrgAdmin
		claims, resp := consentedClientClaims(t, svc, user, session, "")
		if v, present := claims["scope"]; present {
			t.Errorf("scope = %v, want absent", v)
		}
		if resp.Scope != "" {
			t.Errorf("Response.Scope = %q, want empty", resp.Scope)
		}
	})
}

// The client-bound token names its client (RFC 9068 §2.2) and keeps every
// session claim; the login-session token keeps carrying the role set and no
// client_id — the two issuance paths stay distinguishable to introspection.
func TestIssueForConsentedClient_ClientIDAndSessionClaims(t *testing.T) {
	svc, _, _ := newUserTokenSvc(t)
	user, session := newUserAndSession(t)
	user.Role = domain.RoleOrgAdmin
	claims, _ := consentedClientClaims(t, svc, user, session, "openid")
	if claims["client_id"] != "cli-1" {
		t.Errorf("client_id = %v, want cli-1", claims["client_id"])
	}
	if claims["session_id"] != session.ID.String() || claims["actor_type"] != ActorTypeUser || claims["role"] != string(domain.RoleOrgAdmin) {
		t.Errorf("session claims lost on the client-bound token: %v", claims)
	}

	sessResp, err := svc.IssueForSession(context.Background(), user, session)
	if err != nil {
		t.Fatalf("IssueForSession: %v", err)
	}
	tok, _, _ := jwt.NewParser(jwt.WithValidMethods([]string{"EdDSA"})).ParseUnverified(sessResp.AccessToken, jwt.MapClaims{})
	sessClaims := tok.Claims.(jwt.MapClaims)
	if v, present := sessClaims["client_id"]; present {
		t.Errorf("session token client_id = %v, want absent", v)
	}
	if sessClaims["scope"] != domain.SessionScopesForRole(domain.RoleOrgAdmin) || sessResp.Scope != domain.SessionScopesForRole(domain.RoleOrgAdmin) {
		t.Errorf("session token scope = %v / %q, want the role-derived set unchanged", sessClaims["scope"], sessResp.Scope)
	}
}

func TestIssueForConsentedClient_RejectsMissingUserOrClient(t *testing.T) {
	svc, _, _ := newUserTokenSvc(t)
	user, session := newUserAndSession(t)
	if _, err := svc.IssueForConsentedClient(context.Background(), nil, session, "cli-1", "openid"); !errors.Is(err, ErrTokenServiceInvalidRequest) {
		t.Errorf("nil user: err = %v", err)
	}
	if _, err := svc.IssueForConsentedClient(context.Background(), user, session, "", "openid"); !errors.Is(err, ErrTokenServiceInvalidRequest) {
		t.Errorf("empty client_id: err = %v", err)
	}
	if _, err := svc.IssueForConsentedClient(context.Background(), user, nil, "cli-1", "openid"); !errors.Is(err, ErrTokenServiceInvalidRequest) {
		t.Errorf("nil session: err = %v", err)
	}
}
