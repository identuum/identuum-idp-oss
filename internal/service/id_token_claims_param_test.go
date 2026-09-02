package service

import (
	"context"
	"testing"
)

// THE-CLAIMS-PARAMETER: a consented `claims.id_token` member puts the named
// identity claims in the id_token — only what the user record can supply.
func TestIDToken_ClaimsParameterEmitsRequestedIdentityClaims(t *testing.T) {
	svc, _ := newIDTokenSvc(t)
	user := newIDTokenUser()
	name := "Alice Example"
	user.Name = &name
	session := newIDTokenSession()

	resp, err := svc.Issue(context.Background(), IDTokenInput{
		User: user, Session: session, Audience: "cli-1", Nonce: "n", Scope: "openid",
		Claims: []string{"name", "email"},
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	claims, _ := parseIDToken(t, resp.IDToken)
	if claims["name"] != "Alice Example" {
		t.Errorf("name = %v, want the user record's name", claims["name"])
	}
	if claims["email"] != "alice@example.com" || claims["email_verified"] != true {
		t.Errorf("email/email_verified = %v/%v, want the user record's values", claims["email"], claims["email_verified"])
	}

	// Without a claims request nothing personal lands (THE-CONSENTED-SCOPE).
	resp, err = svc.Issue(context.Background(), IDTokenInput{
		User: user, Session: session, Audience: "cli-1", Nonce: "n", Scope: "openid email profile",
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	claims, _ = parseIDToken(t, resp.IDToken)
	for _, k := range []string{"name", "email", "email_verified"} {
		if v, present := claims[k]; present {
			t.Errorf("%s = %v, want absent without a claims request", k, v)
		}
	}

	// A claim the record cannot supply is never emitted, consented or not.
	user.Name = nil
	resp, err = svc.Issue(context.Background(), IDTokenInput{
		User: user, Session: session, Audience: "cli-1", Nonce: "n", Scope: "openid",
		Claims: []string{"name"},
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	claims, _ = parseIDToken(t, resp.IDToken)
	if v, present := claims["name"]; present {
		t.Errorf("name = %v, want absent when the record has none (no null placeholder)", v)
	}
}
