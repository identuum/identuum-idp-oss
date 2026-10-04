package service

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// Owner ruling (v0.9.5): an org_admin lists, reads and replays the
// back-channel logout deliveries of its own organization's apps; a
// site_admin keeps the list but no longer sees a tenant's user or session
// ids, and replays only the apps it owns (the system organization's and the
// global apps it registered), D-025.

type clientsByID map[string]*domain.Client

func (m clientsByID) GetClientByClientID(_ context.Context, clientID string) (*domain.Client, error) {
	return m[clientID], nil
}

type scopedDeliveries struct {
	admin  *BackchannelDeliveryAdminService
	repo   *inMemoryDeliveryRepo
	orgA   uuid.UUID
	orgB   uuid.UUID
	rowA   uuid.UUID // delivery of orgA's app
	rowB   uuid.UUID // delivery of orgB's app
	rowSys uuid.UUID // delivery of a system-organization app
	rowAll uuid.UUID // delivery of a global app (no organization)
}

func newScopedDeliveries(t *testing.T) scopedDeliveries {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	pkPEM, _ := x509.MarshalPKCS8PrivateKey(priv)
	provider := &inMemoryKeyProvider{keys: []domain.SigningKey{{
		KID: "kid-eddsa", Algorithm: domain.KeyAlgorithmEdDSA,
		PrivateKey: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkPEM})),
		State:      domain.KeyStateActive,
	}}}
	tokens := NewLogoutTokenService(nil, provider, LogoutTokenServiceOptions{Issuer: "https://idp.test", TTL: time.Minute})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	t.Cleanup(srv.Close)
	repo := newDeliveryRepo()
	delivery := NewBackchannelLogoutService(nil, tokens, BackchannelLogoutServiceOptions{
		HTTPClient: &http.Client{Timeout: time.Second}, AllowPlainHTTP: true,
	}).WithDeliveryRepository(repo).WithRetryPolicy(1, time.Millisecond)

	s := scopedDeliveries{repo: repo, orgA: uuid.New(), orgB: uuid.New()}
	sys := uuid.MustParse(domain.SystemOrgID)
	clients := clientsByID{
		"app-a":   {ClientID: "app-a", OrganizationID: &s.orgA, BackchannelLogoutURI: srv.URL},
		"app-b":   {ClientID: "app-b", OrganizationID: &s.orgB, BackchannelLogoutURI: srv.URL},
		"app-sys": {ClientID: "app-sys", OrganizationID: &sys, BackchannelLogoutURI: srv.URL},
		"app-all": {ClientID: "app-all", BackchannelLogoutURI: srv.URL},
	}
	repo.clientOrg = map[string]uuid.UUID{"app-a": s.orgA, "app-b": s.orgB, "app-sys": sys}
	s.admin = NewBackchannelDeliveryAdminService(nil, repo, delivery, clients)
	seed := func(clientID string) uuid.UUID {
		id, uid, sid := uuid.New(), uuid.New(), uuid.New()
		_ = repo.Insert(context.Background(), &domain.BackchannelLogoutDelivery{
			ID: id, ClientID: clientID, UserID: &uid, SessionID: &sid, Status: domain.BackchannelLogoutDeliveryFailed,
		})
		return id
	}
	s.rowA, s.rowB, s.rowSys, s.rowAll = seed("app-a"), seed("app-b"), seed("app-sys"), seed("app-all")
	return s
}

func deliveryOrgAdmin(org uuid.UUID) *domain.Principal {
	return &domain.Principal{UserID: uuid.New(), OrganizationID: org, Role: domain.RoleOrgAdmin}
}

func deliverySiteAdmin() *domain.Principal {
	return &domain.Principal{UserID: uuid.New(), OrganizationID: uuid.MustParse(domain.SystemOrgID), Role: domain.RoleSiteAdmin}
}

func TestDeliveryAdmin_OrgAdminSeesOnlyItsOrganizationsApps(t *testing.T) {
	s := newScopedDeliveries(t)
	ctx := context.Background()
	rows, err := s.admin.ListFor(ctx, deliveryOrgAdmin(s.orgA), ListBackchannelDeliveriesInput{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) != 1 || rows[0].ID != s.rowA || rows[0].UserID == nil {
		t.Fatalf("org_admin list = %+v, want only its app's delivery, with its user id", rows)
	}
	if row, err := s.admin.GetFor(ctx, deliveryOrgAdmin(s.orgA), s.rowA); err != nil || row.UserID == nil {
		t.Errorf("get own = %v, %v; want the row with its user id", row, err)
	}
	for _, other := range []uuid.UUID{s.rowB, s.rowSys, s.rowAll} {
		if _, err := s.admin.GetFor(ctx, deliveryOrgAdmin(s.orgA), other); !errors.Is(err, ErrBackchannelAdminNotFound) {
			t.Errorf("get of another organization's delivery: err = %v, want not found", err)
		}
		if _, err := s.admin.ReplayFor(ctx, deliveryOrgAdmin(s.orgA), other); !errors.Is(err, ErrBackchannelAdminNotFound) {
			t.Errorf("replay of another organization's delivery: err = %v, want not found", err)
		}
	}
	if res, err := s.admin.ReplayFor(ctx, deliveryOrgAdmin(s.orgA), s.rowA); err != nil || !res.Delivered {
		t.Errorf("replay own = %+v, %v; want delivered", res, err)
	}
}

func TestDeliveryAdmin_SiteAdminSeesNoTenantUserIDs(t *testing.T) {
	s := newScopedDeliveries(t)
	ctx := context.Background()
	rows, err := s.admin.ListFor(ctx, deliverySiteAdmin(), ListBackchannelDeliveriesInput{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) != 4 {
		t.Fatalf("site_admin list = %d rows, want all 4", len(rows))
	}
	for _, r := range rows {
		system := r.ID == s.rowSys
		if system && (r.UserID == nil || r.SessionID == nil) {
			t.Errorf("system-organization delivery lost its ids")
		}
		if !system && (r.UserID != nil || r.SessionID != nil) {
			t.Errorf("delivery of %s shows user=%v session=%v to a site_admin", r.ClientID, r.UserID, r.SessionID)
		}
	}
	if row, err := s.admin.GetFor(ctx, deliverySiteAdmin(), s.rowA); err != nil || row.UserID != nil || row.SessionID != nil {
		t.Errorf("get of a tenant delivery = %+v, %v; want the row without user and session ids", row, err)
	}
}

func TestDeliveryAdmin_SiteAdminReplaysOnlyTheAppsItOwns(t *testing.T) {
	s := newScopedDeliveries(t)
	ctx := context.Background()
	if _, err := s.admin.ReplayFor(ctx, deliverySiteAdmin(), s.rowA); !errors.Is(err, domain.ErrForbidden) {
		t.Errorf("site_admin replay of a tenant app's delivery: err = %v, want ErrForbidden", err)
	}
	for _, own := range []uuid.UUID{s.rowSys, s.rowAll} {
		if res, err := s.admin.ReplayFor(ctx, deliverySiteAdmin(), own); err != nil || !res.Delivered {
			t.Errorf("site_admin replay of its own app's delivery = %+v, %v; want delivered", res, err)
		}
	}
}

func TestDeliveryAdmin_OtherActorsAreRefused(t *testing.T) {
	s := newScopedDeliveries(t)
	ctx := context.Background()
	if _, err := s.admin.ListFor(ctx, nil, ListBackchannelDeliveriesInput{}); !errors.Is(err, domain.ErrUnauthorized) {
		t.Errorf("nil actor: err = %v, want ErrUnauthorized", err)
	}
	user := &domain.Principal{UserID: uuid.New(), OrganizationID: s.orgA, Role: domain.RoleOrgUser}
	if _, err := s.admin.ListFor(ctx, user, ListBackchannelDeliveriesInput{}); !errors.Is(err, domain.ErrForbidden) {
		t.Errorf("org_user: err = %v, want ErrForbidden", err)
	}
}
