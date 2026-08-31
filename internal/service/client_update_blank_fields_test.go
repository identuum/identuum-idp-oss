package service

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// THE-SILENT-DROP-2 (2026-09-01): five fields on UpdateClientOptions were
// still plain strings compared against "", so a supplied blank was
// indistinguishable from absent and was dropped with a 200.
//
// The per-field answer is decided by what the storage layer can represent:
//
//	Scope, JWKSUri, JWKS         CLEAR  — nullable columns; the repository
//	                                      already maps "" to NULL, which is
//	                                      what oauth_clients_pkj_key_source_check
//	                                      compares against
//	TokenEndpointAuthMethod      REFUSE — NOT NULL, CHECK allow-list with no
//	TokenEndpointAuthSigningAlg           empty member, and the repository
//	                                      silently substitutes the column
//	                                      DEFAULT for a blank, so a "clear"
//	                                      would store client_secret_basic /
//	                                      EdDSA without the caller asking
//
// RULE: CLIENT-UPDATE-BLANK-FIELDS-1
func TestClientUpdate_BlankFieldsClearOrRefusePerField(t *testing.T) {
	seed := func() (*ClientService, *recordingClientRepo) {
		repo := &recordingClientRepo{stored: domain.Client{
			ID:                          uuid.New(),
			ClientID:                    "cid",
			Name:                        "Billing Portal",
			RedirectURIs:                []string{"https://app.example.test/cb"},
			Scope:                       "read write",
			JWKSUri:                     "https://app.example.test/jwks.json",
			JWKS:                        `{"keys":[]}`,
			TokenEndpointAuthMethod:     "client_secret_post",
			TokenEndpointAuthSigningAlg: "RS256",
		}}
		return NewClientService(nil, repo), repo
	}

	// ── CLEARABLE: a supplied blank must actually reach the repository as
	// empty. Under the old plain string these could be set but never unset.
	for _, c := range []struct {
		field string
		opts  UpdateClientOptions
		read  func(*domain.Client) string
	}{
		{"scope", UpdateClientOptions{Scope: strPtr("")}, func(c *domain.Client) string { return c.Scope }},
		{"jwks_uri", UpdateClientOptions{JWKSUri: strPtr("")}, func(c *domain.Client) string { return c.JWKSUri }},
		{"jwks", UpdateClientOptions{JWKS: strPtr("")}, func(c *domain.Client) string { return c.JWKS }},
	} {
		svc, repo := seed()
		if _, err := svc.UpdateClient(context.Background(), uuid.New(), c.opts); err != nil {
			t.Errorf("clearing %s was rejected: %v", c.field, err)
			continue
		}
		if repo.updateCalls != 1 || repo.last == nil {
			t.Errorf("clearing %s never reached the repository", c.field)
			continue
		}
		if got := c.read(repo.last); got != "" {
			t.Errorf("clearing %s left %q — the supplied blank was DROPPED, not applied", c.field, got)
		}
	}

	// ── REFUSED: a supplied blank must not become the column default ──
	for _, c := range []struct {
		field string
		opts  UpdateClientOptions
	}{
		{"token_endpoint_auth_method", UpdateClientOptions{TokenEndpointAuthMethod: strPtr("")}},
		{"token_endpoint_auth_signing_alg", UpdateClientOptions{TokenEndpointAuthSigningAlg: strPtr("")}},
	} {
		svc, repo := seed()
		if _, err := svc.UpdateClient(context.Background(), uuid.New(), c.opts); err == nil {
			t.Errorf("a blank %s was ACCEPTED — the repository would store the column default instead", c.field)
		}
		if repo.updateCalls != 0 {
			t.Errorf("a blank %s still reached the repository", c.field)
		}
	}

	// ── and an UNLISTED value must be refused by the SERVICE, not by the
	// database. domain.AllowedClientAuthMethods and
	// PrivateKeyJWTSigningAlgorithms both had zero production callers. ──
	for _, c := range []struct {
		why  string
		opts UpdateClientOptions
	}{
		{"an auth method outside the allow-list", UpdateClientOptions{TokenEndpointAuthMethod: strPtr("banana")}},
		{"an auth method that only looks close", UpdateClientOptions{TokenEndpointAuthMethod: strPtr("client_secret_jwt")}},
		{"a signing alg outside the allow-list", UpdateClientOptions{TokenEndpointAuthSigningAlg: strPtr("HS256")}},
		{"a signing alg in the wrong case", UpdateClientOptions{TokenEndpointAuthSigningAlg: strPtr("rs256")}},
	} {
		svc, repo := seed()
		if _, err := svc.UpdateClient(context.Background(), uuid.New(), c.opts); err == nil {
			t.Errorf("%s was ACCEPTED — only the database CHECK constraint stands between it and the row", c.why)
		}
		if repo.updateCalls != 0 {
			t.Errorf("%s still reached the repository", c.why)
		}
	}

	// ── CONTROLS: every listed value is still accepted, so a service that
	// refused everything would not pass. ──
	for _, m := range []string{"client_secret_basic", "client_secret_post", "none", "private_key_jwt"} {
		svc, _ := seed()
		if _, err := svc.UpdateClient(context.Background(), uuid.New(), UpdateClientOptions{
			TokenEndpointAuthMethod: &m,
		}); err != nil {
			t.Errorf("the listed auth method %q was rejected: %v", m, err)
		}
	}
	for _, a := range []string{"EdDSA", "ES256", "ES384", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512"} {
		svc, _ := seed()
		if _, err := svc.UpdateClient(context.Background(), uuid.New(), UpdateClientOptions{
			TokenEndpointAuthSigningAlg: &a,
		}); err != nil {
			t.Errorf("the listed signing alg %q was rejected: %v", a, err)
		}
	}

	// ── ABSENT still leaves every field alone ──
	svc, repo := seed()
	if _, err := svc.UpdateClient(context.Background(), uuid.New(), UpdateClientOptions{}); err != nil {
		t.Fatalf("an empty option set was rejected: %v", err)
	}
	if repo.last == nil {
		t.Fatal("an empty option set never reached the repository")
	}
	if repo.last.Scope != "read write" || repo.last.JWKSUri == "" || repo.last.JWKS == "" ||
		repo.last.TokenEndpointAuthMethod != "client_secret_post" || repo.last.TokenEndpointAuthSigningAlg != "RS256" {
		t.Errorf("an absent field was treated as supplied: %+v", repo.last)
	}
}
