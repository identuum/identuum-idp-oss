package service

import (
	"context"
	"testing"
)

// OIDC Front-Channel and Back-Channel Logout name the session an ID token was
// issued for by its `sid` claim: the RP keeps it and matches it against the
// logout token (or the `sid` of the front-channel request) to end exactly that
// session. An ID token without it cannot be matched.
func TestIDToken_CarriesTheSessionAsSid(t *testing.T) {
	svc, _ := newIDTokenSvc(t)
	user, session := newIDTokenUser(), newIDTokenSession()

	resp, err := svc.Issue(context.Background(), IDTokenInput{User: user, Session: session, Audience: "cli-1", Nonce: "n", Scope: "openid"})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	claims, _ := parseIDToken(t, resp.IDToken)
	if claims["sid"] != session.ID.String() {
		t.Errorf("sid = %v, want the session id %s", claims["sid"], session.ID)
	}
}
