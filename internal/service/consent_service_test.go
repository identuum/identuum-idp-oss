package service

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// inMemoryConsentRepo is the test seam for ConsentService.
type inMemoryConsentRepo struct {
	mu   sync.Mutex
	rows map[string]*domain.OAuthConsent
}

func newConsentRepo() *inMemoryConsentRepo {
	return &inMemoryConsentRepo{rows: map[string]*domain.OAuthConsent{}}
}

func consentKey(userID uuid.UUID, client, aud string) string {
	return userID.String() + "|" + client + "|" + aud
}

func (r *inMemoryConsentRepo) Upsert(_ context.Context, c *domain.OAuthConsent) (*domain.OAuthConsent, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	k := consentKey(c.UserID, c.ClientID, c.Audience)
	existing, ok := r.rows[k]
	if ok {
		existing.Scope = c.Scope
		existing.GrantedAt = c.GrantedAt
		existing.RevokedAt = nil
		existing.UpdatedAt = c.GrantedAt
		cp := *existing
		return &cp, nil
	}
	cp := *c
	cp.CreatedAt = c.GrantedAt
	cp.UpdatedAt = c.GrantedAt
	r.rows[k] = &cp
	out := cp
	return &out, nil
}

func (r *inMemoryConsentRepo) GetActive(_ context.Context, userID uuid.UUID, clientID, audience string) (*domain.OAuthConsent, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	row, ok := r.rows[consentKey(userID, clientID, audience)]
	if !ok {
		return nil, nil
	}
	if row.RevokedAt != nil {
		return nil, nil
	}
	cp := *row
	return &cp, nil
}

func (r *inMemoryConsentRepo) Revoke(_ context.Context, userID uuid.UUID, clientID, audience string, at time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	row, ok := r.rows[consentKey(userID, clientID, audience)]
	if !ok {
		return nil
	}
	row.RevokedAt = &at
	return nil
}

// ---------- Construction ----------

func TestNewConsentService_NilRepoPanics(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("nil repo did not panic")
		}
	}()
	_ = NewConsentService(nil, nil)
}

// ---------- Lookup ----------

func TestConsent_LookupAbsentReturnsNotFound(t *testing.T) {
	svc := NewConsentService(nil, newConsentRepo())
	d, err := svc.Lookup(context.Background(), uuid.New(), "cli-1", "", "openid")
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if d.Found {
		t.Errorf("expected absent, got Found=true")
	}
}

func TestConsent_GrantThenLookupCoversSubset(t *testing.T) {
	svc := NewConsentService(nil, newConsentRepo())
	uid := uuid.New()
	if _, err := svc.Grant(context.Background(), GrantConsentInput{
		UserID:   uid,
		ClientID: "cli-1",
		Scope:    "openid profile email",
	}); err != nil {
		t.Fatalf("grant: %v", err)
	}
	d, _ := svc.Lookup(context.Background(), uid, "cli-1", "", "openid email")
	if !d.Found || !d.Covered {
		t.Errorf("decision = %+v", d)
	}
}

func TestConsent_GrantedDoesNotCoverSuperset(t *testing.T) {
	svc := NewConsentService(nil, newConsentRepo())
	uid := uuid.New()
	_, _ = svc.Grant(context.Background(), GrantConsentInput{
		UserID:   uid,
		ClientID: "cli-1",
		Scope:    "openid",
	})
	d, _ := svc.Lookup(context.Background(), uid, "cli-1", "", "openid offline_access")
	if !d.Found {
		t.Errorf("expected Found=true")
	}
	if d.Covered {
		t.Errorf("expected Covered=false")
	}
}

func TestConsent_AudienceScopedRowsAreSeparate(t *testing.T) {
	svc := NewConsentService(nil, newConsentRepo())
	uid := uuid.New()
	_, _ = svc.Grant(context.Background(), GrantConsentInput{
		UserID:   uid,
		ClientID: "cli-1",
		Audience: "https://api.a/",
		Scope:    "openid",
	})
	d, _ := svc.Lookup(context.Background(), uid, "cli-1", "https://api.b/", "openid")
	if d.Found {
		t.Errorf("audience leak: %+v", d)
	}
}

func TestConsent_RegrantReplacesScope(t *testing.T) {
	svc := NewConsentService(nil, newConsentRepo())
	uid := uuid.New()
	_, _ = svc.Grant(context.Background(), GrantConsentInput{UserID: uid, ClientID: "cli-1", Scope: "openid"})
	_, _ = svc.Grant(context.Background(), GrantConsentInput{UserID: uid, ClientID: "cli-1", Scope: "openid email"})
	d, _ := svc.Lookup(context.Background(), uid, "cli-1", "", "email")
	if !d.Covered {
		t.Errorf("regrant did not flip granted scope: %+v", d)
	}
}

func TestConsent_RevokeRowsLookupAbsent(t *testing.T) {
	svc := NewConsentService(nil, newConsentRepo())
	uid := uuid.New()
	_, _ = svc.Grant(context.Background(), GrantConsentInput{UserID: uid, ClientID: "cli-1", Scope: "openid"})
	if err := svc.Revoke(context.Background(), uid, "cli-1", ""); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	d, _ := svc.Lookup(context.Background(), uid, "cli-1", "", "openid")
	if d.Found {
		t.Errorf("revoked row still found: %+v", d)
	}
}

func TestConsent_RegrantAfterRevokeReactivates(t *testing.T) {
	svc := NewConsentService(nil, newConsentRepo())
	uid := uuid.New()
	_, _ = svc.Grant(context.Background(), GrantConsentInput{UserID: uid, ClientID: "cli-1", Scope: "openid"})
	_ = svc.Revoke(context.Background(), uid, "cli-1", "")
	_, _ = svc.Grant(context.Background(), GrantConsentInput{UserID: uid, ClientID: "cli-1", Scope: "openid email"})
	d, _ := svc.Lookup(context.Background(), uid, "cli-1", "", "email")
	if !d.Covered {
		t.Errorf("re-grant after revoke did not reactivate")
	}
}

func TestConsent_LookupInvalidInputReturnsSentinel(t *testing.T) {
	svc := NewConsentService(nil, newConsentRepo())
	_, err := svc.Lookup(context.Background(), uuid.Nil, "cli-1", "", "openid")
	if !errors.Is(err, ErrConsentInvalidInput) {
		t.Errorf("err = %v", err)
	}
	_, err = svc.Lookup(context.Background(), uuid.New(), "", "", "openid")
	if !errors.Is(err, ErrConsentInvalidInput) {
		t.Errorf("err = %v", err)
	}
}

func TestScopeCovers_EmptyRequestedAlwaysCovered(t *testing.T) {
	if !scopeCovers("openid", "") {
		t.Errorf("empty requested should be covered")
	}
}
