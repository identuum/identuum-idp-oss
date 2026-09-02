package service

import (
	"context"
	"testing"
	"time"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// THE-PROFILE-CLAIMS in the id_token: a consented claims.id_token request
// emits set profile fields and never an unset one.
func TestIDToken_ProfileClaimsEmitOnlyWhatIsSet(t *testing.T) {
	svc, _ := newIDTokenSvc(t)
	user := newIDTokenUser()
	name := "Alice Example"
	user.Name = &name
	user.UpdatedAt = time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	given := "Alice"
	locale := "en-GB"
	profile := &domain.UserProfile{UserID: user.ID, GivenName: &given, Locale: &locale, UpdatedAt: time.Date(2026, 9, 2, 0, 0, 0, 0, time.UTC)}

	resp, err := svc.Issue(context.Background(), IDTokenInput{
		User: user, Session: newIDTokenSession(), Audience: "cli-1", Nonce: "n", Scope: "openid",
		Claims:  []string{"given_name", "family_name", "locale", "updated_at", "name"},
		Profile: profile,
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	claims, _ := parseIDToken(t, resp.IDToken)
	if claims["given_name"] != "Alice" || claims["locale"] != "en-GB" || claims["name"] != "Alice Example" {
		t.Errorf("set profile claims must emit: %v", claims)
	}
	if v, present := claims["family_name"]; present {
		t.Errorf("family_name unset → must be absent, got %v", v)
	}
	if ua, _ := claims["updated_at"].(float64); int64(ua) != profile.UpdatedAt.Unix() {
		t.Errorf("updated_at = %v, want the profile row's %d", claims["updated_at"], profile.UpdatedAt.Unix())
	}
	// Not requested → not emitted, even though set.
	resp, _ = svc.Issue(context.Background(), IDTokenInput{
		User: user, Session: newIDTokenSession(), Audience: "cli-1", Nonce: "n", Scope: "openid",
		Claims: []string{"name"}, Profile: profile,
	})
	claims, _ = parseIDToken(t, resp.IDToken)
	if v, present := claims["given_name"]; present {
		t.Errorf("unrequested given_name emitted: %v", v)
	}
}
