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

type fakeAdminClientLookup struct {
	client *domain.Client
}

func (f *fakeAdminClientLookup) GetClientByClientID(_ context.Context, _ string) (*domain.Client, error) {
	return f.client, nil
}

func newAdminHarness(t *testing.T, client *domain.Client) (*BackchannelDeliveryAdminService, *inMemoryDeliveryRepo, *httptest.Server) {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	pkPEM, _ := x509.MarshalPKCS8PrivateKey(priv)
	provider := &inMemoryKeyProvider{keys: []domain.SigningKey{{
		KID: "kid-eddsa", Algorithm: domain.KeyAlgorithmEdDSA,
		PrivateKey: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkPEM})),
		State:      domain.KeyStateActive,
	}}}
	tokens := NewLogoutTokenService(nil, provider, LogoutTokenServiceOptions{Issuer: "https://idp.test", TTL: time.Minute})
	mux := http.NewServeMux()
	mux.HandleFunc("/logout", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	srv := httptest.NewServer(mux)
	repo := newDeliveryRepo()
	delivery := NewBackchannelLogoutService(nil, tokens, BackchannelLogoutServiceOptions{
		HTTPClient:     &http.Client{Timeout: time.Second},
		AllowPlainHTTP: true,
	}).WithDeliveryRepository(repo).WithRetryPolicy(1, time.Millisecond)
	if client != nil {
		client.BackchannelLogoutURI = srv.URL + "/logout"
	}
	admin := NewBackchannelDeliveryAdminService(nil, repo, delivery, &fakeAdminClientLookup{client: client})
	return admin, repo, srv
}

// ---------- Construction ----------

func TestNewBackchannelDeliveryAdminService_NilRepoPanics(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("nil repo did not panic")
		}
	}()
	_ = NewBackchannelDeliveryAdminService(nil, nil, nil, nil)
}

// ---------- List + Get ----------

func TestAdmin_ListEmptyReturnsEmpty(t *testing.T) {
	admin, _, srv := newAdminHarness(t, &domain.Client{ClientID: "cli-1"})
	defer srv.Close()
	rows, err := admin.List(context.Background(), ListBackchannelDeliveriesInput{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("rows = %d", len(rows))
	}
}

func TestAdmin_ListFilterByStatus(t *testing.T) {
	admin, repo, srv := newAdminHarness(t, &domain.Client{ClientID: "cli-1"})
	defer srv.Close()
	_ = repo.Insert(context.Background(), &domain.BackchannelLogoutDelivery{
		ID:       uuid.New(),
		ClientID: "cli-1",
		Status:   domain.BackchannelLogoutDeliveryPending,
	})
	_ = repo.Insert(context.Background(), &domain.BackchannelLogoutDelivery{
		ID:       uuid.New(),
		ClientID: "cli-1",
		Status:   domain.BackchannelLogoutDeliveryDelivered,
	})
	rows, _ := admin.List(context.Background(), ListBackchannelDeliveriesInput{Status: "delivered"})
	if len(rows) != 1 || rows[0].Status != domain.BackchannelLogoutDeliveryDelivered {
		t.Errorf("filter mismatch: %+v", rows)
	}
}

func TestAdmin_GetNotFound(t *testing.T) {
	admin, _, srv := newAdminHarness(t, &domain.Client{ClientID: "cli-1"})
	defer srv.Close()
	_, err := admin.Get(context.Background(), uuid.New())
	if !errors.Is(err, ErrBackchannelAdminNotFound) {
		t.Errorf("err = %v", err)
	}
}

func TestAdmin_GetReturnsRow(t *testing.T) {
	admin, repo, srv := newAdminHarness(t, &domain.Client{ClientID: "cli-1"})
	defer srv.Close()
	id := uuid.New()
	_ = repo.Insert(context.Background(), &domain.BackchannelLogoutDelivery{ID: id, ClientID: "cli-1", Status: "pending"})
	row, err := admin.Get(context.Background(), id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if row.ID != id {
		t.Errorf("id mismatch")
	}
}

// ---------- Replay ----------

func TestAdmin_ReplayHappyPath(t *testing.T) {
	client := &domain.Client{ClientID: "cli-1"}
	admin, repo, srv := newAdminHarness(t, client)
	defer srv.Close()
	uid := uuid.New()
	id := uuid.New()
	_ = repo.Insert(context.Background(), &domain.BackchannelLogoutDelivery{
		ID:       id,
		ClientID: "cli-1",
		UserID:   &uid,
		Status:   "failed",
	})
	res, err := admin.Replay(context.Background(), id)
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if !res.Delivered {
		t.Errorf("not delivered: %+v", res)
	}
	if res.HTTPStatus != http.StatusNoContent {
		t.Errorf("status = %d", res.HTTPStatus)
	}
}

func TestAdmin_ReplayClientGone(t *testing.T) {
	admin, repo, srv := newAdminHarness(t, nil) // client gone
	defer srv.Close()
	id := uuid.New()
	_ = repo.Insert(context.Background(), &domain.BackchannelLogoutDelivery{
		ID:       id,
		ClientID: "cli-1",
		Status:   "failed",
	})
	_, err := admin.Replay(context.Background(), id)
	if !errors.Is(err, ErrBackchannelAdminClientGone) {
		t.Errorf("err = %v", err)
	}
}

func TestAdmin_ReplayMissingClientLookupSentinel(t *testing.T) {
	repo := newDeliveryRepo()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	pkPEM, _ := x509.MarshalPKCS8PrivateKey(priv)
	provider := &inMemoryKeyProvider{keys: []domain.SigningKey{{
		KID: "kid-eddsa", Algorithm: domain.KeyAlgorithmEdDSA,
		PrivateKey: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkPEM})),
		State:      domain.KeyStateActive,
	}}}
	tokens := NewLogoutTokenService(nil, provider, LogoutTokenServiceOptions{Issuer: "https://idp.test"})
	delivery := NewBackchannelLogoutService(nil, tokens, BackchannelLogoutServiceOptions{})
	admin := NewBackchannelDeliveryAdminService(nil, repo, delivery, nil)
	id := uuid.New()
	_ = repo.Insert(context.Background(), &domain.BackchannelLogoutDelivery{
		ID:       id,
		ClientID: "cli-1",
	})
	_, err := admin.Replay(context.Background(), id)
	if !errors.Is(err, ErrBackchannelAdminClientLookupMissing) {
		t.Errorf("err = %v", err)
	}
}

// ---------- ProcessDueDeliveries (cleanup-tick path) ----------

func TestProcessDueDeliveries_RetriesDueRows(t *testing.T) {
	repo := newDeliveryRepo()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	pkPEM, _ := x509.MarshalPKCS8PrivateKey(priv)
	provider := &inMemoryKeyProvider{keys: []domain.SigningKey{{
		KID: "kid-eddsa", Algorithm: domain.KeyAlgorithmEdDSA,
		PrivateKey: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkPEM})),
		State:      domain.KeyStateActive,
	}}}
	tokens := NewLogoutTokenService(nil, provider, LogoutTokenServiceOptions{Issuer: "https://idp.test"})
	mux := http.NewServeMux()
	mux.HandleFunc("/logout", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	delivery := NewBackchannelLogoutService(nil, tokens, BackchannelLogoutServiceOptions{
		HTTPClient:     &http.Client{Timeout: time.Second},
		AllowPlainHTTP: true,
	}).WithDeliveryRepository(repo).WithRetryPolicy(1, time.Millisecond).
		WithDueProcessorClientLookup(&fakeAdminClientLookup{client: &domain.Client{
			ClientID:             "cli-1",
			BackchannelLogoutURI: srv.URL + "/logout",
		}})

	past := time.Now().Add(-time.Minute)
	uid := uuid.New()
	_ = repo.Insert(context.Background(), &domain.BackchannelLogoutDelivery{
		ID:            uuid.New(),
		ClientID:      "cli-1",
		UserID:        &uid,
		Status:        domain.BackchannelLogoutDeliveryPending,
		NextAttemptAt: &past,
	})

	n, err := delivery.ProcessDueDeliveries(context.Background(), 10)
	if err != nil {
		t.Fatalf("process: %v", err)
	}
	if n != 1 {
		t.Errorf("processed = %d", n)
	}
}

func TestProcessDueDeliveries_NoClientLookupReturnsZero(t *testing.T) {
	repo := newDeliveryRepo()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	pkPEM, _ := x509.MarshalPKCS8PrivateKey(priv)
	provider := &inMemoryKeyProvider{keys: []domain.SigningKey{{
		KID: "kid-eddsa", Algorithm: domain.KeyAlgorithmEdDSA,
		PrivateKey: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkPEM})),
		State:      domain.KeyStateActive,
	}}}
	tokens := NewLogoutTokenService(nil, provider, LogoutTokenServiceOptions{Issuer: "https://idp.test"})
	delivery := NewBackchannelLogoutService(nil, tokens, BackchannelLogoutServiceOptions{}).
		WithDeliveryRepository(repo)
	n, _ := delivery.ProcessDueDeliveries(context.Background(), 10)
	if n != 0 {
		t.Errorf("expected 0 without lookup wired, got %d", n)
	}
}
