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
//
// THE-INCONSISTENT-DOCUMENT: the switches themselves must now be VALID
// documents. private_key_jwt needs its key source in the same PUT; and a
// confidential client can no longer be moved to "none" at all — that was
// hole #2, so the none case asserts the REFUSAL and records that the P0-7b
// hash-clearing branch for none is unreachable through valid documents
// (kept as defense, no longer observable here).
func TestUpdateClient_ClearsSecretWhenMethodStopsUsingOne(t *testing.T) {
	newConfidential := func(t *testing.T) (*ClientService, *domain.Client) {
		t.Helper()
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
		return svc, c
	}

	t.Run("private_key_jwt", func(t *testing.T) {
		svc, c := newConfidential(t)
		method, jwksURI := "private_key_jwt", "https://app.example.com/jwks.json"
		got, err := svc.UpdateClient(context.Background(), c.ID, UpdateClientOptions{
			TokenEndpointAuthMethod: &method,
			JWKSUri:                 &jwksURI, // the key source the document now requires
		})
		if err != nil {
			t.Fatalf("UpdateClient: %v", err)
		}
		if got.ClientSecretHash != "" {
			t.Errorf("after switching to private_key_jwt: the dead secret hash was retained")
		}
	})

	t.Run("none is refused on a confidential client", func(t *testing.T) {
		svc, c := newConfidential(t)
		method := "none"
		if _, err := svc.UpdateClient(context.Background(), c.ID, UpdateClientOptions{
			TokenEndpointAuthMethod: &method,
		}); err == nil {
			t.Fatal("a confidential client was moved to method none — hole #2 of THE-INCONSISTENT-DOCUMENT is open")
		}
	})

	for _, method := range []string{"client_secret_post", "client_secret_basic"} {
		t.Run(method, func(t *testing.T) {
			svc, c := newConfidential(t)
			m := method
			got, err := svc.UpdateClient(context.Background(), c.ID, UpdateClientOptions{
				TokenEndpointAuthMethod: &m,
			})
			if err != nil {
				t.Fatalf("UpdateClient: %v", err)
			}
			if got.ClientSecretHash == "" {
				t.Errorf("after switching to %q: the secret hash was dropped but the method still uses one", method)
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
