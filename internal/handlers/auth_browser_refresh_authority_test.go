package handlers

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// THE-BROWSER-BOUNDARY-IN-GO-2 (Plan C), unit proofs: a browser refresh
// re-reads AUTHORITY from the current user row — it never carries forward a
// role the user no longer holds and never refreshes a banned account — while
// it keeps the session's original authentication facts (auth_time, acr, amr).

func browserRefreshAuthorityFixture(t *testing.T) (*gin.Engine, *inMemoryUserByIDLookup, *browserRefreshMinter, *service.IssuedUserSession) {
	t.Helper()
	r := &browserRefreshRepo{inMemorySessionRepoForHandlers: newSessionRepoForHandlers()}
	svc := service.NewUserSessionService(nil, r, service.UserSessionServiceOptions{})
	user := &domain.User{ID: uuid.New(), Role: domain.RoleOrgAdmin, Email: "fixture@example.test"}
	issued, err := svc.CreateUserSession(context.Background(), service.CreateUserSessionInput{UserID: user.ID, Acr: "urn:identuum:acr:mfa", Amr: []string{"pwd", "otp"}})
	if err != nil {
		t.Fatal("fixture session creation failed")
	}
	m := &browserRefreshMinter{}
	signer := service.NewUserTokenService(nil, userTokenKeyProvider(t), service.UserTokenServiceOptions{Issuer: "https://idp.test", AccessTokenTTL: 15 * time.Minute, Minter: m})
	lookup := &inMemoryUserByIDLookup{byID: map[uuid.UUID]*domain.User{user.ID: user}}
	e := gin.New()
	e.POST("/refresh", HandleBrowserSessionRefresh(AuthSessionsHandlerDeps{UserSession: svc, UserToken: signer, UserLookup: lookup}))
	return e, lookup, m, issued
}

func TestBrowserRefresh_DemotedRoleIsNotCarriedForwardAssuranceIs(t *testing.T) {
	e, lookup, m, issued := browserRefreshAuthorityFixture(t)
	rec := browserRefreshRequest(e, issued.RefreshToken)
	if rec.Code != 204 {
		t.Fatalf("admin refresh: status %d", rec.Code)
	}
	next := ""
	for _, c := range rec.Result().Cookies() {
		if c.Name == "refresh_token" {
			next = c.Value
		}
	}
	if next == "" {
		t.Fatal("the first refresh must rotate the refresh cookie")
	}
	lookup.byID[issued.Session.UserID].Role = domain.RoleOrgUser
	if rec := browserRefreshRequest(e, next); rec.Code != 204 {
		t.Fatalf("demoted refresh: status %d", rec.Code)
	}
	if len(m.claims) != 2 {
		t.Fatalf("minted %d tokens, want 2", len(m.claims))
	}
	// issue() carries the role-derived scope in the claim set's "scope".
	if m.claims[0].Extra["scope"] == nil || m.claims[1].Extra["scope"] != nil {
		t.Fatalf("scopes admin=%v demoted=%v: a refresh must mint the CURRENT role's scopes", m.claims[0].Extra["scope"], m.claims[1].Extra["scope"])
	}
	for _, c := range m.claims {
		if c.Extra["auth_time"] != issued.Session.EffectiveAuthTime().Unix() ||
			c.Extra["acr"] != issued.Session.EffectiveACR() ||
			!reflect.DeepEqual(c.Extra["amr"], issued.Session.EffectiveAMR()) {
			t.Fatalf("refresh changed the original authentication facts: auth_time=%v acr=%v amr=%v", c.Extra["auth_time"], c.Extra["acr"], c.Extra["amr"])
		}
	}
}

func TestBrowserRefresh_BannedAccountIsRefusedAndMintsNothing(t *testing.T) {
	e, lookup, m, issued := browserRefreshAuthorityFixture(t)
	lookup.byID[issued.Session.UserID].Banned = true
	rec := browserRefreshRequest(e, issued.RefreshToken)
	if rec.Code != 401 || len(rec.Result().Cookies()) != 0 || len(m.claims) != 0 {
		t.Fatalf("banned refresh: status %d, cookies %d, minted %d; want 401, none, none", rec.Code, len(rec.Result().Cookies()), len(m.claims))
	}
}
