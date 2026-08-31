package service

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/repository"
)

// recordingIDPRepo records the provider the service tried to persist.
type recordingIDPRepo struct {
	repository.IdentityProviderRepository
	stored      *domain.IdentityProvider
	updateCalls int
	createCalls int
	last        *domain.IdentityProvider
}

func (r *recordingIDPRepo) ListByOrganization(_ context.Context, _ uuid.UUID) ([]*domain.IdentityProvider, error) {
	if r.stored == nil {
		return nil, nil
	}
	c := *r.stored
	return []*domain.IdentityProvider{&c}, nil
}

func (r *recordingIDPRepo) Update(_ context.Context, p *domain.IdentityProvider) (*domain.IdentityProvider, error) {
	r.updateCalls++
	r.last = p
	return p, nil
}

func (r *recordingIDPRepo) Create(_ context.Context, p *domain.IdentityProvider) (*domain.IdentityProvider, error) {
	r.createCalls++
	r.last = p
	return p, nil
}

type noopCipher struct{}

func (noopCipher) Encrypt(s string) (string, error) { return "enc:" + s, nil }
func (noopCipher) Decrypt(s string) (string, error) { return s, nil }

// THE-SILENT-DROP-2 (2026-09-01): UpdateOIDCProvider read
//
//	slug := strings.TrimSpace(in.Slug); if slug == "" { slug = existing.Slug }
//
// so a supplied blank slug silently kept the stored one and answered 200 —
// the same class this arc has been closing, in the one field of an otherwise
// full-document REPLACE that quietly preserved state.
//
// THE CONTRACT, changed for this field ONLY: absent (nil) keeps the stored
// slug, a supplied non-blank replaces it, and a supplied blank is refused —
// a slug cannot be cleared, because create always defaults one and the row
// always carries it. The other fields keep their replace semantics.
//
// RULE: IDP-SLUG-BLANK-1
func TestOIDCProviderSlug_BlankIsRefusedAbsentKeeps(t *testing.T) {
	orgID := uuid.New()
	valid := func(slug *string) OIDCProviderInput {
		return OIDCProviderInput{
			OrganizationID: orgID,
			Type:           domain.IDPTypeOIDC,
			Name:           "Corp IdP",
			Slug:           slug,
			IssuerURL:      "https://issuer.example.test",
			ClientID:       "client-abc",
		}
	}
	seed := func() (*OIDCProviderConfigService, *recordingIDPRepo) {
		repo := &recordingIDPRepo{stored: &domain.IdentityProvider{
			ID: uuid.New(), OrganizationID: orgID, Type: domain.IDPTypeOIDC,
			Name: "Corp IdP", Slug: "corp-idp", Active: true,
		}}
		return NewOIDCProviderConfigService(nil, repo, noopCipher{}), repo
	}

	// ── SUPPLIED BLANK on UPDATE: refused, never a silent keep ──
	for _, blank := range []string{"", "   ", "\t"} {
		svc, repo := seed()
		b := blank
		got, err := svc.UpdateOIDCProvider(context.Background(), orgID, valid(&b))
		if err == nil {
			t.Errorf("a blank slug (%q) was ACCEPTED", blank)
			if got != nil && got.Slug == "corp-idp" {
				t.Errorf("  and the stored slug was silently kept — the lying success")
			}
		} else if !errors.Is(err, errOIDCProviderInvalidInput) {
			t.Errorf("a blank slug (%q) refused with %v, want the invalid-input sentinel", blank, err)
		}
		if repo.updateCalls != 0 {
			t.Errorf("a blank slug (%q) still reached the repository", blank)
		}
	}

	// ── ABSENT on UPDATE: keeps the stored slug, which is the behaviour
	// that used to depend on blankness and is now explicit ──
	svc, repo := seed()
	got, err := svc.UpdateOIDCProvider(context.Background(), orgID, valid(nil))
	if err != nil {
		t.Fatalf("an absent slug was rejected: %v", err)
	}
	if got.Slug != "corp-idp" {
		t.Fatalf("an absent slug changed the stored value to %q", got.Slug)
	}
	if repo.updateCalls != 1 {
		t.Fatalf("repository update calls = %d, want 1", repo.updateCalls)
	}

	// ── SUPPLIED non-blank on UPDATE: replaces, trimmed ──
	svc, _ = seed()
	renamed := "  corp-idp-v2  "
	got, err = svc.UpdateOIDCProvider(context.Background(), orgID, valid(&renamed))
	if err != nil {
		t.Fatalf("a real slug change was rejected: %v", err)
	}
	if got.Slug != "corp-idp-v2" {
		t.Fatalf("the slug stored as %q, want the trimmed value", got.Slug)
	}

	// ── CREATE gives the SAME answer to a supplied blank, and still
	// defaults when absent ──
	for _, blank := range []string{"", "   "} {
		repo := &recordingIDPRepo{}
		svc := NewOIDCProviderConfigService(nil, repo, noopCipher{})
		b := blank
		if _, err := svc.CreateOIDCProvider(context.Background(), valid(&b)); err == nil {
			t.Errorf("create ACCEPTED a blank slug (%q) — the two paths must agree", blank)
		}
		if repo.createCalls != 0 {
			t.Errorf("create with a blank slug (%q) still reached the repository", blank)
		}
	}
	repo = &recordingIDPRepo{}
	svc = NewOIDCProviderConfigService(nil, repo, noopCipher{})
	created, err := svc.CreateOIDCProvider(context.Background(), valid(nil))
	if err != nil {
		t.Fatalf("create with an absent slug was rejected: %v", err)
	}
	if created.Slug != "oidc" {
		t.Fatalf("create with an absent slug stored %q, want the documented default", created.Slug)
	}
}
