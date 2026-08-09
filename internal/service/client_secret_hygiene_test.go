package service

// client_secret_hygiene_test.go — P0-7b: a client that stops authenticating
// with a secret must stop storing one.
//
// The auth layer already refuses to consult a secret for private_key_jwt and
// none, so this is data hygiene rather than an authentication change: without
// it, switching a client's method leaves a hash on the row that can never be
// presented and will never be rotated.
//
// Creation was already compliant — prepareClient mints no secret when the
// requested method is private_key_jwt — so the gap was UpdateClient, which set
// the new method and left the old hash in place.

import (
	"context"
	"testing"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// TestUpdateClient_ClearsSecretWhenMethodStopsUsingOne pins the switch.
func TestUpdateClient_ClearsSecretWhenMethodStopsUsingOne(t *testing.T) {
	for _, tc := range []struct {
		method   string
		wantHash bool
	}{
		{"private_key_jwt", false},
		{"none", false},
		{"client_secret_post", true},
		{"client_secret_basic", true},
	} {
		t.Run(tc.method, func(t *testing.T) {
			svc := NewClientService(nil, newClientRepo())
			c, secret, err := svc.RegisterClient(context.Background(), RegisterClientOptions{
				Name:         "hygiene",
				RedirectURIs: []string{"https://app.example.com/cb"},
			})
			if err != nil {
				t.Fatalf("RegisterClient: %v", err)
			}
			if secret == "" || c.ClientSecretHash == "" {
				t.Fatalf("precondition: a confidential client must start WITH a secret hash")
			}

			got, err := svc.UpdateClient(context.Background(), c.ID, UpdateClientOptions{
				TokenEndpointAuthMethod: tc.method,
			})
			if err != nil {
				t.Fatalf("UpdateClient: %v", err)
			}
			if hasHash := got.ClientSecretHash != ""; hasHash != tc.wantHash {
				t.Errorf("after switching to %q: ClientSecretHash present = %v, want %v",
					tc.method, hasHash, tc.wantHash)
			}
		})
	}
}

// TestAuthMethodUsesClientSecret pins the predicate itself against the full
// allowed set, so a method added to AllowedClientAuthMethods without a decision
// here shows up as a failing case rather than defaulting to "keeps a secret".
func TestAuthMethodUsesClientSecret(t *testing.T) {
	want := map[string]bool{
		"client_secret_basic": true,
		"client_secret_post":  true,
		"none":                false,
		"private_key_jwt":     false,
	}
	for m := range domain.AllowedClientAuthMethods {
		w, known := want[m]
		if !known {
			t.Errorf("method %q is allowed but this test has no expectation for it — decide whether it uses a client secret", m)
			continue
		}
		if got := domain.AuthMethodUsesClientSecret(m); got != w {
			t.Errorf("AuthMethodUsesClientSecret(%q) = %v, want %v", m, got, w)
		}
	}
}
