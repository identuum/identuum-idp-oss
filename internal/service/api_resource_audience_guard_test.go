package service

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/repository"
)

// H7: an API resource's audience is what its tokens are addressed to. It must
// never be the identity provider's own issuer (a resource token would then read
// as one meant for the IdP) or an application's client id (an ID token's
// audience is a client id, so a resource token could stand in for one).

func TestAPIResourceService_ReservedAudienceIsRefused(t *testing.T) {
	ctx := context.Background()
	org := uuid.New()
	admin := apiResourcePrincipal(domain.RoleOrgAdmin, org)
	reserved := func(_ context.Context, aud string) (bool, error) {
		return aud == "https://idp.example.test" || aud == "0123456789abcdef0123456789abcdef", nil
	}
	svc := NewAPIResourceService(nil, newAPIResourceRepo()).WithReservedAudiences(reserved)
	create := func(aud string) (*domain.APIResource, error) {
		res, _, err := svc.Create(ctx, admin, CreateAPIResourceOptions{OrganizationID: org, Name: "R", Audience: aud, Active: true, TokenTTLSecs: 60})
		return res, err
	}

	for _, aud := range []string{"https://idp.example.test", "0123456789abcdef0123456789abcdef"} {
		if _, err := create(aud); !errors.Is(err, ErrAPIResourceInvalid()) {
			t.Errorf("create with reserved audience %q: err=%v, want ErrAPIResourceInvalid", aud, err)
		}
	}

	ok, err := create("https://api.example.test")
	if err != nil {
		t.Fatalf("a free audience must be served: %v", err)
	}
	bad := "https://idp.example.test"
	if _, err := svc.Update(ctx, admin, ok.ID, UpdateAPIResourceOptions{Audience: &bad}); !errors.Is(err, ErrAPIResourceInvalid()) {
		t.Errorf("update to a reserved audience: err=%v, want ErrAPIResourceInvalid", err)
	}
	// Only a CHANGED audience is checked: renaming a resource whose audience
	// later became reserved must not be blocked.
	name := "renamed"
	same := ok.Audience
	if _, err := svc.Update(ctx, admin, ok.ID, UpdateAPIResourceOptions{Name: &name, Audience: &same}); err != nil {
		t.Errorf("update leaving the audience as it is: %v", err)
	}
}

func TestAPIResourceService_ReservedAudienceLookupFailureRefuses(t *testing.T) {
	ctx := context.Background()
	org := uuid.New()
	admin := apiResourcePrincipal(domain.RoleOrgAdmin, org)
	repo := newAPIResourceRepo()
	svc := NewAPIResourceService(nil, repo).WithReservedAudiences(func(context.Context, string) (bool, error) {
		return false, errors.New("client store down")
	})
	_, _, err := svc.Create(ctx, admin, CreateAPIResourceOptions{OrganizationID: org, Name: "R", Audience: "https://api.example.test", Active: true, TokenTTLSecs: 60})
	if err == nil {
		t.Fatal("a failing reservation check must refuse, not pass")
	}
	if got, _, _ := svc.List(ctx, admin, repository.Pagination{Page: 1, PageSize: 10}); len(got) != 0 {
		t.Errorf("nothing may be stored when the check could not run, got %d", len(got))
	}
}

type reservedClientLookup struct {
	known map[string]bool
	err   error
}

func (r reservedClientLookup) GetClientByClientID(_ context.Context, id string) (*domain.Client, error) {
	if r.err != nil {
		return nil, r.err
	}
	if r.known[id] {
		return &domain.Client{ClientID: id}, nil
	}
	return nil, domain.ErrClientNotFound
}

func TestReservedAudienceChecker(t *testing.T) {
	ctx := context.Background()
	check := ReservedAudienceChecker("https://idp.example.test/", reservedClientLookup{known: map[string]bool{"client-1": true}})

	for aud, want := range map[string]bool{
		"https://idp.example.test":   true,
		"https://idp.example.test/":  true,
		"HTTPS://IDP.EXAMPLE.TEST":   true,
		"client-1":                   true,
		"https://api.example.test":   false,
		"https://idp.example.test/x": false,
	} {
		got, err := check(ctx, aud)
		if err != nil || got != want {
			t.Errorf("reserved(%q) = %v, %v; want %v, nil", aud, got, err, want)
		}
	}

	failing := ReservedAudienceChecker("https://idp.example.test", reservedClientLookup{err: errors.New("store down")})
	if got, err := failing(ctx, "https://api.example.test"); err == nil || got {
		t.Errorf("a failing client lookup = %v, %v; want an error (fail closed)", got, err)
	}
	noClients := ReservedAudienceChecker("https://idp.example.test", nil)
	if got, err := noClients(ctx, "https://idp.example.test"); err != nil || !got {
		t.Errorf("issuer with no client lookup wired = %v, %v; want reserved", got, err)
	}
}
