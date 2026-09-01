package service

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// THE-INCONSISTENT-DOCUMENT (2026-09-01): create validated the whole client
// document; update validated only the supplied fields, so the CROSS-FIELD
// rules were DB-only there. PUT could move a client onto private_key_jwt with
// no key source, onto method none while confidential, or leave jwks material
// on a secret-based client — each refused only by a CHECK constraint
// answering a flattened 400.
//
// UpdateClient now runs Client.Validate on the UPDATED document before the
// repository write. Wired after a read-only sweep of every stored
// oauth_clients row measured ZERO that would newly fail (0 rows exist in this
// environment's disposable database).
//
// Asserted THROUGH the service with a recording repository.
//
// RULE: CLIENT-UPDATE-DOCUMENT-1
func TestClientUpdate_InconsistentDocumentIsRefused(t *testing.T) {
	seedBasic := func() (*ClientService, *recordingClientRepo) {
		repo := &recordingClientRepo{stored: domain.Client{
			ID: uuid.New(), ClientID: "cid", Name: "Billing Portal",
			RedirectURIs:            []string{"https://app.example.test/cb"},
			ClientSecretHash:        "hash",
			TokenEndpointAuthMethod: "client_secret_basic",
		}}
		return NewClientService(nil, repo), repo
	}
	seedPKJ := func() (*ClientService, *recordingClientRepo) {
		repo := &recordingClientRepo{stored: domain.Client{
			ID: uuid.New(), ClientID: "cid", Name: "Assertion App",
			RedirectURIs:            []string{"https://app.example.test/cb"},
			TokenEndpointAuthMethod: "private_key_jwt",
			JWKSUri:                 "https://app.example.test/jwks.json",
		}}
		return NewClientService(nil, repo), repo
	}
	pkj, none, basic := "private_key_jwt", "none", "client_secret_basic"
	httpURI := "http://insecure.example.test/jwks.json"

	// ── the three PM-named holes, plus the non-https key source ──
	for _, c := range []struct {
		why  string
		seed func() (*ClientService, *recordingClientRepo)
		opts UpdateClientOptions
	}{
		{"switch to private_key_jwt with NO key source", seedBasic,
			UpdateClientOptions{TokenEndpointAuthMethod: &pkj}},
		{"switch to method none while confidential", seedBasic,
			UpdateClientOptions{TokenEndpointAuthMethod: &none}},
		{"switch to secret-based auth while KEEPING jwks material", seedPKJ,
			UpdateClientOptions{TokenEndpointAuthMethod: &basic}},
		{"switch to private_key_jwt with a NON-HTTPS jwks_uri", seedBasic,
			UpdateClientOptions{TokenEndpointAuthMethod: &pkj, JWKSUri: &httpURI}},
	} {
		svc, repo := c.seed()
		if _, err := svc.UpdateClient(context.Background(), uuid.New(), c.opts); err == nil {
			t.Errorf("UpdateClient ACCEPTED %s — the DB CHECK constraint is the only guard", c.why)
		}
		if repo.updateCalls != 0 {
			t.Errorf("%s: the inconsistent document still reached the repository", c.why)
		}
	}

	// ── CONTROLS: the same transitions done COHERENTLY still land ──
	jwksURI := "https://app.example.test/jwks.json"
	empty := ""
	svc, repo := seedBasic()
	if _, err := svc.UpdateClient(context.Background(), uuid.New(), UpdateClientOptions{
		TokenEndpointAuthMethod: &pkj, JWKSUri: &jwksURI,
	}); err != nil {
		t.Errorf("switching to private_key_jwt WITH its key source was rejected: %v", err)
	} else if repo.last == nil || repo.last.ClientSecretHash != "" {
		t.Errorf("the pkj switch retained the dead secret hash")
	}
	svc, repo = seedPKJ()
	if _, err := svc.UpdateClient(context.Background(), uuid.New(), UpdateClientOptions{
		TokenEndpointAuthMethod: &basic, JWKSUri: &empty,
	}); err != nil {
		t.Errorf("switching to secret-based auth WHILE clearing jwks was rejected: %v", err)
	} else if repo.last == nil || repo.last.JWKSUri != "" {
		t.Errorf("the coherent switch did not clear the key material")
	}
	// An untouched-field update on a consistent stored row still lands.
	svc, repo = seedBasic()
	newName := "Billing Portal v2"
	if _, err := svc.UpdateClient(context.Background(), uuid.New(), UpdateClientOptions{Name: &newName}); err != nil {
		t.Errorf("an unrelated update on a consistent row was rejected: %v", err)
	}
	if repo.updateCalls != 1 {
		t.Errorf("the unrelated update did not reach the repository")
	}
}
