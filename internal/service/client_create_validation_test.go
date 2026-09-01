package service

import (
	"context"
	"testing"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/repository"
)

// registerRecordingClientRepo records what RegisterClient tried to persist.
// The embedded interface is nil on purpose — a method this test does not stub
// is one a REFUSED create must never reach.
type registerRecordingClientRepo struct {
	repository.ClientRepository
	registerCalls int
	last          *domain.Client
}

func (r *registerRecordingClientRepo) RegisterClient(_ context.Context, c *domain.Client) error {
	r.registerCalls++
	r.last = c
	return nil
}

// THE-MIRROR (2026-09-01): the previous slice validated the auth method and
// signing alg on UPDATE and left CREATE assigning both raw — the original
// defect inverted, in the very fields that slice decided. POST with
// {"token_endpoint_auth_method":"wizard"} reached the DB CHECK constraint and
// came back as a flattened "invalid request".
//
// prepareClient now runs domain.Client.Validate() on the built document — the
// validator that had held these rules all along with no production caller
// (the ScopeTemplate.Validate defect, again). It calls the SAME
// ValidateClientAuthMethod/ValidateClientSigningAlg the update path calls,
// and adds the cross-field rules only a whole document can check.
//
// Asserted THROUGH the service with a recording repository.
//
// RULE: CLIENT-CREATE-VALIDATION-1
func TestClientServiceRegister_RefusesInvalidBeforeReachingTheRepository(t *testing.T) {
	base := func() RegisterClientOptions {
		return RegisterClientOptions{
			Name:         "Billing Portal",
			RedirectURIs: []string{"https://app.example.test/cb"},
		}
	}

	// ── the two mirrored fields: every unlisted value create must refuse ──
	bad := []struct {
		why    string
		mutate func(*RegisterClientOptions)
	}{
		{"an unlisted auth method", func(o *RegisterClientOptions) { o.TokenEndpointAuthMethod = "wizard" }},
		{"an auth method that only looks close", func(o *RegisterClientOptions) { o.TokenEndpointAuthMethod = "client_secret_jwt" }},
		{"an unlisted signing alg", func(o *RegisterClientOptions) { o.TokenEndpointAuthSigningAlg = "HS256" }},
		{"a signing alg in the wrong case", func(o *RegisterClientOptions) { o.TokenEndpointAuthSigningAlg = "rs256" }},
		// ── the cross-field rules Validate brings, previously DB-only ──
		{"jwks_uri on a non-private_key_jwt client", func(o *RegisterClientOptions) { o.JWKSUri = "https://x.test/jwks.json" }},
		{"private_key_jwt with NO key source", func(o *RegisterClientOptions) { o.TokenEndpointAuthMethod = "private_key_jwt" }},
		{"private_key_jwt with BOTH key sources", func(o *RegisterClientOptions) {
			o.TokenEndpointAuthMethod = "private_key_jwt"
			o.JWKSUri = "https://x.test/jwks.json"
			o.JWKS = `{"keys":[]}`
		}},
		{"method none on a confidential client", func(o *RegisterClientOptions) { o.TokenEndpointAuthMethod = "none" }},
	}
	for _, c := range bad {
		repo := &registerRecordingClientRepo{}
		svc := NewClientService(nil, repo)
		opts := base()
		c.mutate(&opts)
		if _, _, err := svc.RegisterClient(context.Background(), opts); err == nil {
			t.Errorf("RegisterClient ACCEPTED %s — the DB CHECK constraint is the only guard again", c.why)
		}
		if repo.registerCalls != 0 {
			t.Errorf("%s: the repository was called %d time(s) with an invalid client", c.why, repo.registerCalls)
		}
	}

	// ── CONTROLS: every listed value still creates ──
	for _, ok := range []struct {
		why    string
		mutate func(*RegisterClientOptions)
	}{
		{"defaults only", func(o *RegisterClientOptions) {}},
		{"client_secret_post", func(o *RegisterClientOptions) { o.TokenEndpointAuthMethod = "client_secret_post" }},
		{"a listed signing alg", func(o *RegisterClientOptions) { o.TokenEndpointAuthSigningAlg = "ES256" }},
		{"private_key_jwt with one key source", func(o *RegisterClientOptions) {
			o.TokenEndpointAuthMethod = "private_key_jwt"
			o.JWKSUri = "https://x.test/jwks.json"
		}},
		{"a public client with method none", func(o *RegisterClientOptions) {
			o.IsPublic = true
			o.TokenEndpointAuthMethod = "none"
		}},
	} {
		repo := &registerRecordingClientRepo{}
		svc := NewClientService(nil, repo)
		opts := base()
		ok.mutate(&opts)
		if _, _, err := svc.RegisterClient(context.Background(), opts); err != nil {
			t.Errorf("RegisterClient rejected a legitimate client (%s): %v", ok.why, err)
		}
		if repo.registerCalls != 1 {
			t.Errorf("%s: repository register calls = %d, want 1", ok.why, repo.registerCalls)
		}
	}
}
