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
	// THE-INCONSISTENT-DOCUMENT: fixtures must be documents the DATABASE
	// could hold. The earlier fixture stored jwks material on a
	// client_secret_post client — a row oauth_clients_pkj_key_source_check
	// has always refused — which the recording repository accepted only
	// because fakes have no constraints. Two consistent fixtures instead.
	seed := func() (*ClientService, *recordingClientRepo) {
		repo := &recordingClientRepo{stored: domain.Client{
			ID:                          uuid.New(),
			ClientID:                    "cid",
			Name:                        "Billing Portal",
			RedirectURIs:                []string{"https://app.example.test/cb"},
			Scope:                       "read write",
			TokenEndpointAuthMethod:     "client_secret_post",
			TokenEndpointAuthSigningAlg: "RS256",
		}}
		return NewClientService(nil, repo), repo
	}
	seedPKJ := func(inline bool) (*ClientService, *recordingClientRepo) {
		stored := domain.Client{
			ID:                          uuid.New(),
			ClientID:                    "cid",
			Name:                        "Billing Portal",
			RedirectURIs:                []string{"https://app.example.test/cb"},
			TokenEndpointAuthMethod:     "private_key_jwt",
			TokenEndpointAuthSigningAlg: "RS256",
		}
		if inline {
			stored.JWKS = `{"keys":[]}`
		} else {
			stored.JWKSUri = "https://app.example.test/jwks.json"
		}
		repo := &recordingClientRepo{stored: stored}
		return NewClientService(nil, repo), repo
	}

	// ── CLEARABLE: a supplied blank must actually reach the repository as
	// empty. Under the old plain string these could be set but never unset.
	// Clearing key material stands alone only alongside a method switch —
	// a pkj client without a key source is not a valid document.
	basicMethod := "client_secret_basic"
	svcScope, repoScope := seed()
	if _, err := svcScope.UpdateClient(context.Background(), uuid.New(), UpdateClientOptions{Scope: strPtr("")}); err != nil {
		t.Errorf("clearing scope was rejected: %v", err)
	} else if repoScope.last == nil || repoScope.last.Scope != "" {
		t.Errorf("clearing scope was DROPPED, not applied")
	}
	svcURI, repoURI := seedPKJ(false)
	if _, err := svcURI.UpdateClient(context.Background(), uuid.New(), UpdateClientOptions{
		JWKSUri:                 strPtr(""),
		TokenEndpointAuthMethod: &basicMethod,
	}); err != nil {
		t.Errorf("clearing jwks_uri alongside the method switch was rejected: %v", err)
	} else if repoURI.last == nil || repoURI.last.JWKSUri != "" {
		t.Errorf("clearing jwks_uri was DROPPED, not applied")
	}
	svcJWKS, repoJWKS := seedPKJ(true)
	if _, err := svcJWKS.UpdateClient(context.Background(), uuid.New(), UpdateClientOptions{
		JWKS:                    strPtr(""),
		TokenEndpointAuthMethod: &basicMethod,
	}); err != nil {
		t.Errorf("clearing jwks alongside the method switch was rejected: %v", err)
	} else if repoJWKS.last == nil || repoJWKS.last.JWKS != "" {
		t.Errorf("clearing jwks was DROPPED, not applied")
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
	// database. Neither allow-list had a caller on the client WRITE paths
	// (corrected by THE-MIRROR: PrivateKeyJWTSigningAlgorithms always had
	// readers in the assertion validator; the write paths consulted neither). ──
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

	// ── CONTROLS: every listed value is still accepted IN a valid document,
	// so a service that refused everything would not pass. Since
	// THE-INCONSISTENT-DOCUMENT the whole document must hold: "none" needs a
	// public client, and "private_key_jwt" needs its key source. ──
	for _, m := range []string{"client_secret_basic", "client_secret_post"} {
		svc, _ := seed()
		if _, err := svc.UpdateClient(context.Background(), uuid.New(), UpdateClientOptions{
			TokenEndpointAuthMethod: &m,
		}); err != nil {
			t.Errorf("the listed auth method %q was rejected: %v", m, err)
		}
	}
	{
		repo := &recordingClientRepo{stored: domain.Client{
			ID: uuid.New(), ClientID: "cid", Name: "Public App",
			RedirectURIs: []string{"https://app.example.test/cb"}, IsPublic: true,
		}}
		svc := NewClientService(nil, repo)
		noneMethod := "none"
		if _, err := svc.UpdateClient(context.Background(), uuid.New(), UpdateClientOptions{
			TokenEndpointAuthMethod: &noneMethod,
		}); err != nil {
			t.Errorf("the listed auth method %q was rejected on a public client: %v", noneMethod, err)
		}
	}
	{
		svc, _ := seed()
		pkj, uri := "private_key_jwt", "https://app.example.test/jwks.json"
		if _, err := svc.UpdateClient(context.Background(), uuid.New(), UpdateClientOptions{
			TokenEndpointAuthMethod: &pkj,
			JWKSUri:                 &uri,
		}); err != nil {
			t.Errorf("the listed auth method %q with its key source was rejected: %v", pkj, err)
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
	if repo.last.Scope != "read write" ||
		repo.last.TokenEndpointAuthMethod != "client_secret_post" || repo.last.TokenEndpointAuthSigningAlg != "RS256" {
		t.Errorf("an absent field was treated as supplied: %+v", repo.last)
	}
}
