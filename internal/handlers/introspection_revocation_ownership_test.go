package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/service"
)

// An authenticated client may judge and revoke the tokens that are ITS OWN —
// issued to it (client_id) or addressed to it (aud) — and no one else's. The
// answer for any other token is the same as for an unknown one:
// {"active":false} from introspection, and a plain 200 that changes nothing
// from revocation (RFC 7662 §2.2, RFC 7009 §2.2).

func introspectAs(t *testing.T, claims *service.IntrospectionClaims, callerClientID string) map[string]any {
	t.Helper()
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	RegisterIntrospectionRoutes(r, IntrospectionHandlerDeps{
		IntrospectionService: service.NewIntrospectionService(nil, &revFakeVerifier{claims: claims}, nil),
		ClientAuth:           stubClientAuth{},
	})
	form := url.Values{"token": {"opaque-token"}, "client_id": {callerClientID}, "client_secret": {"S"}}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/introspection", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("introspection = %d %q; want 200", w.Code, w.Body.String())
	}
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return out
}

func TestIntrospection_ClientJudgesOnlyItsOwnTokens(t *testing.T) {
	sub := uuid.New()
	issuedToA := &service.IntrospectionClaims{Sub: sub.String(), UserID: sub, ClientID: "cli-A", Aud: []string{"https://idp.test"}}
	forResource := &service.IntrospectionClaims{Sub: sub.String(), UserID: sub, ClientID: "cli-A", Aud: []string{"res-1"}}

	if got := introspectAs(t, issuedToA, "cli-A"); got["active"] != true {
		t.Errorf("the client a token was issued to = %v; want active", got["active"])
	}
	if got := introspectAs(t, issuedToA, "cli-B"); got["active"] != false {
		t.Errorf("another client asking about that token = %v; want active:false", got["active"])
	}
	if got := introspectAs(t, forResource, "res-1"); got["active"] != true {
		t.Errorf("the resource a token is addressed to = %v; want active", got["active"])
	}
	if got := introspectAs(t, forResource, "res-2"); got["active"] != false {
		t.Errorf("a resource the token is NOT addressed to = %v; want active:false", got["active"])
	}
	// A cross-client answer reveals nothing: the inactive body carries no claims.
	if got := introspectAs(t, issuedToA, "cli-B"); len(got) != 1 {
		t.Errorf("a refused introspection body = %v; want only active:false", got)
	}
}

// resourceClientAuth authenticates every caller as an API resource (a
// resource server's own credential).
type resourceClientAuth struct{}

func (resourceClientAuth) Authenticate(_ context.Context, id, _, _ string) (*service.AuthenticatedClient, error) {
	return &service.AuthenticatedClient{Kind: service.AuthenticatedClientKindAPIResource, ClientID: id, AuthRecordID: uuid.New()}, nil
}

// A resource server is who introspection is for (RFC 7662 §1): an API
// resource's credential may judge a user's token whatever app it was issued
// to, while an app's own credential still sees only its own tokens.
func TestIntrospection_ResourceServerJudgesTokensPresentedToIt(t *testing.T) {
	sub := uuid.New()
	issuedToSPA := &service.IntrospectionClaims{Sub: sub.String(), UserID: sub, ClientID: "spa-1", Aud: []string{"https://idp.test"}}

	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	RegisterIntrospectionRoutes(r, IntrospectionHandlerDeps{
		IntrospectionService: service.NewIntrospectionService(nil, &revFakeVerifier{claims: issuedToSPA}, nil),
		ClientAuth:           resourceClientAuth{},
	})
	form := url.Values{"token": {"opaque-token"}, "client_id": {"https://api.a"}, "client_secret": {"S"}}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/introspection", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	var got map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &got)
	if w.Code != http.StatusOK || got["active"] != true {
		t.Errorf("an API resource introspecting a user's token issued to an app = %d %v; want 200 active", w.Code, got["active"])
	}
	if got := introspectAs(t, issuedToSPA, "cli-other"); got["active"] != false {
		t.Errorf("another app's credential introspecting it = %v; want active:false", got["active"])
	}
}

// Revocation stays the issuing client's alone (RFC 7009 §2.1): an API
// resource's credential cannot revoke a token issued to an app.
func TestRevoke_ResourceServerCannotRevokeAnAppsToken(t *testing.T) {
	sub := uuid.New()
	verifier := &revFakeVerifier{claims: &service.IntrospectionClaims{
		Sub: sub.String(), UserID: sub, ClientID: "cli-ISSUER", Jti: "jti-app", Exp: time.Now().Add(time.Hour).Unix(),
	}}
	r, repo, _ := newRevocationEngineWithJTI(t, verifier, &service.RecorderSessionRevoker{}, resourceClientAuth{})
	if w := postRevoke(t, r, "token=app-access&client_id=https://api.a&client_secret=S"); w.Code != http.StatusOK {
		t.Fatalf("revoke = %d; want the opaque 200", w.Code)
	}
	if len(repo.inserts) != 0 {
		t.Errorf("an API resource revoked an app's token: %+v", repo.inserts)
	}
}

// A cross-client revoke is the same opaque 200, but the token is NOT revoked:
// no jti is recorded (the session fan-out half is pinned by
// REVOKE-CLIENT-BINDING-1).
func TestRevoke_AccessTokenOfAnotherClientIsNotRevoked(t *testing.T) {
	exp := time.Now().Add(time.Hour).Unix()
	sub := uuid.New()
	verifier := &revFakeVerifier{claims: &service.IntrospectionClaims{
		Sub: sub.String(), UserID: sub, ClientID: "cli-ISSUER", Jti: "jti-victim", Exp: exp,
	}}

	rHolder, repoHolder, _ := newRevocationEngineWithJTI(t, verifier, &service.RecorderSessionRevoker{}, stubClientAuth{})
	if w := postRevoke(t, rHolder, "token=victim-access&client_id=cli-HOLDER&client_secret=S"); w.Code != http.StatusOK {
		t.Fatalf("a cross-client revoke must stay an opaque 200, got %d", w.Code)
	}
	if len(repoHolder.inserts) != 0 {
		t.Errorf("a client revoked a token that is not its own: %+v", repoHolder.inserts)
	}

	rOwner, repoOwner, _ := newRevocationEngineWithJTI(t, verifier, &service.RecorderSessionRevoker{}, stubClientAuth{})
	postRevoke(t, rOwner, "token=victim-access&client_id=cli-ISSUER&client_secret=S")
	if len(repoOwner.inserts) != 1 {
		t.Errorf("the owning client's revoke recorded %d jtis; want 1", len(repoOwner.inserts))
	}
}

// RFC 7009 §2.1: token_type_hint is a hint, not a filter. Hinting
// access_token at a refresh token must still revoke it.
func TestRevoke_WrongHintStillRevokesTheRefreshToken(t *testing.T) {
	refreshRepo := newInMemoryRefreshRepoHandlers()
	r, _, _, svc := newRevocationEngineWithRefresh(t, &revFakeVerifier{}, refreshRepo)
	issued, err := svc.Issue(context.Background(), service.IssueRefreshTokenInput{ClientID: "cli-own", Subject: "cli-own", AccessJTI: "jti-own"})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	w := postRevoke(t, r, "token="+issued.Token+"&token_type_hint=access_token&client_id=cli-own&client_secret=S")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if row := refreshRepo.byID[issued.ID]; row == nil || row.RevokedAt == nil {
		t.Errorf("a refresh token revoked with the wrong hint is still live: %+v", row)
	}
}
