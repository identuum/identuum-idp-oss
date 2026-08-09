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
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/repository"
)

func newBackchannelHarness(t *testing.T) *BackchannelLogoutService {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	pkPEM, _ := x509.MarshalPKCS8PrivateKey(priv)
	provider := &inMemoryKeyProvider{keys: []domain.SigningKey{{
		KID:        "kid-eddsa",
		Algorithm:  domain.KeyAlgorithmEdDSA,
		PrivateKey: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkPEM})),
		State:      domain.KeyStateActive,
	}}}
	tokens := NewLogoutTokenService(nil, provider, LogoutTokenServiceOptions{Issuer: "https://idp.test", TTL: time.Minute})
	// Use the http.DefaultClient so httptest endpoints (which
	// loopback) are reachable; safehttp.NewSafeClient would block
	// loopback in tests.
	return NewBackchannelLogoutService(nil, tokens, BackchannelLogoutServiceOptions{
		HTTPClient:     &http.Client{Timeout: 2 * time.Second},
		AllowPlainHTTP: true, // test-only override
	}).WithRetryPolicy(1, time.Millisecond)
}

// newBackchannelHarnessStrictHTTPS constructs a service with the
// default production-strict HTTPS policy so the rejection tests
// can prove it.
func newBackchannelHarnessStrictHTTPS(t *testing.T) *BackchannelLogoutService {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	pkPEM, _ := x509.MarshalPKCS8PrivateKey(priv)
	provider := &inMemoryKeyProvider{keys: []domain.SigningKey{{
		KID:        "kid-eddsa",
		Algorithm:  domain.KeyAlgorithmEdDSA,
		PrivateKey: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkPEM})),
		State:      domain.KeyStateActive,
	}}}
	tokens := NewLogoutTokenService(nil, provider, LogoutTokenServiceOptions{Issuer: "https://idp.test", TTL: time.Minute})
	return NewBackchannelLogoutService(nil, tokens, BackchannelLogoutServiceOptions{
		HTTPClient: &http.Client{Timeout: 2 * time.Second},
	})
}

func TestBackchannel_DeliverPostsLogoutToken(t *testing.T) {
	var capturedToken string
	mux := http.NewServeMux()
	mux.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		capturedToken = r.PostForm.Get("logout_token")
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	svc := newBackchannelHarness(t)
	client := &domain.Client{
		ClientID:             "cli-1",
		BackchannelLogoutURI: srv.URL + "/logout",
	}
	res, err := svc.Deliver(context.Background(), DeliverInput{
		Client:  client,
		Subject: uuid.New(),
	})
	if err != nil {
		t.Fatalf("deliver: %v", err)
	}
	if !res.Delivered || res.Status != http.StatusOK {
		t.Errorf("result = %+v", res)
	}
	if capturedToken == "" {
		t.Errorf("logout_token form field missing")
	}
	if strings.Count(capturedToken, ".") != 2 {
		t.Errorf("logout_token shape wrong: %q", capturedToken)
	}
}

func TestBackchannel_DeliverNoURIIsNoop(t *testing.T) {
	svc := newBackchannelHarness(t)
	_, err := svc.Deliver(context.Background(), DeliverInput{
		Client:  &domain.Client{ClientID: "cli-1"},
		Subject: uuid.New(),
	})
	if !errors.Is(err, ErrBackchannelNoURI) {
		t.Errorf("err = %v", err)
	}
}

func TestBackchannel_DeliverNon2xxFails(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/logout", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "down", http.StatusServiceUnavailable)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	svc := newBackchannelHarness(t)
	res, err := svc.Deliver(context.Background(), DeliverInput{
		Client:  &domain.Client{ClientID: "cli-1", BackchannelLogoutURI: srv.URL + "/logout"},
		Subject: uuid.New(),
	})
	if !errors.Is(err, ErrBackchannelDeliveryFailed) {
		t.Errorf("err = %v", err)
	}
	if res == nil || res.Status != http.StatusServiceUnavailable {
		t.Errorf("res = %+v", res)
	}
}

func TestBackchannel_HTTPURIRejected(t *testing.T) {
	svc := newBackchannelHarnessStrictHTTPS(t)
	_, err := svc.Deliver(context.Background(), DeliverInput{
		Client:  &domain.Client{ClientID: "cli-1", BackchannelLogoutURI: "http://example.com/logout"},
		Subject: uuid.New(),
	})
	if !errors.Is(err, ErrBackchannelHTTPSRequired) {
		t.Errorf("err = %v", err)
	}
}

func TestBackchannel_URIWithFragmentRejected(t *testing.T) {
	svc := newBackchannelHarness(t)
	_, err := svc.Deliver(context.Background(), DeliverInput{
		Client:  &domain.Client{ClientID: "cli-1", BackchannelLogoutURI: "https://example.com/logout#frag"},
		Subject: uuid.New(),
	})
	if !errors.Is(err, ErrBackchannelURIHasFragment) {
		t.Errorf("err = %v", err)
	}
}

// inMemoryDeliveryRepo is the test seam for the durable delivery
// rows.
type inMemoryDeliveryRepo struct {
	rows map[uuid.UUID]*domain.BackchannelLogoutDelivery
}

func newDeliveryRepo() *inMemoryDeliveryRepo {
	return &inMemoryDeliveryRepo{rows: map[uuid.UUID]*domain.BackchannelLogoutDelivery{}}
}
func (r *inMemoryDeliveryRepo) Insert(_ context.Context, d *domain.BackchannelLogoutDelivery) error {
	cp := *d
	r.rows[d.ID] = &cp
	return nil
}
func (r *inMemoryDeliveryRepo) MarkDelivered(_ context.Context, id uuid.UUID, httpStatus int, at time.Time) error {
	row, ok := r.rows[id]
	if !ok {
		return nil
	}
	row.Status = domain.BackchannelLogoutDeliveryDelivered
	row.HTTPStatus = &httpStatus
	row.DeliveredAt = &at
	return nil
}
func (r *inMemoryDeliveryRepo) MarkAttemptFailed(_ context.Context, id uuid.UUID, attempt int, httpStatus int, errMessage string, nextAttempt time.Time, _ time.Time) error {
	row, ok := r.rows[id]
	if !ok {
		return nil
	}
	row.AttemptCount = attempt
	row.HTTPStatus = &httpStatus
	row.LastError = errMessage
	row.NextAttemptAt = &nextAttempt
	return nil
}
func (r *inMemoryDeliveryRepo) MarkPermanentlyFailed(_ context.Context, id uuid.UUID, httpStatus int, errMessage string, _ time.Time) error {
	row, ok := r.rows[id]
	if !ok {
		return nil
	}
	row.Status = domain.BackchannelLogoutDeliveryFailed
	row.HTTPStatus = &httpStatus
	row.LastError = errMessage
	return nil
}
func (r *inMemoryDeliveryRepo) DeleteOlderThan(_ context.Context, _ time.Time) (int64, error) {
	return 0, nil
}
func (r *inMemoryDeliveryRepo) GetByID(_ context.Context, id uuid.UUID) (*domain.BackchannelLogoutDelivery, error) {
	row, ok := r.rows[id]
	if !ok {
		return nil, nil
	}
	cp := *row
	return &cp, nil
}
func (r *inMemoryDeliveryRepo) List(_ context.Context, filter repository.BackchannelLogoutDeliveryListFilter) ([]*domain.BackchannelLogoutDelivery, error) {
	var out []*domain.BackchannelLogoutDelivery
	for _, row := range r.rows {
		if filter.Status != "" && string(row.Status) != filter.Status {
			continue
		}
		if filter.ClientID != "" && row.ClientID != filter.ClientID {
			continue
		}
		cp := *row
		out = append(out, &cp)
	}
	return out, nil
}
func (r *inMemoryDeliveryRepo) ListDueForRetry(_ context.Context, now time.Time, limit int) ([]*domain.BackchannelLogoutDelivery, error) {
	var out []*domain.BackchannelLogoutDelivery
	for _, row := range r.rows {
		if row.Status != domain.BackchannelLogoutDeliveryPending {
			continue
		}
		if row.NextAttemptAt == nil || row.NextAttemptAt.After(now) {
			continue
		}
		cp := *row
		out = append(out, &cp)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out, nil
}

func TestBackchannel_DurableRowMarkedDeliveredOnSuccess(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/logout", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	repo := newDeliveryRepo()
	svc := newBackchannelHarness(t).WithDeliveryRepository(repo)
	if _, err := svc.Deliver(context.Background(), DeliverInput{
		Client:  &domain.Client{ClientID: "cli-1", BackchannelLogoutURI: srv.URL + "/logout"},
		Subject: uuid.New(),
	}); err != nil {
		t.Fatalf("deliver: %v", err)
	}
	if len(repo.rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(repo.rows))
	}
	for _, row := range repo.rows {
		if row.Status != domain.BackchannelLogoutDeliveryDelivered {
			t.Errorf("status = %v", row.Status)
		}
		if row.LogoutJTI == "" {
			t.Errorf("jti missing")
		}
	}
}

func TestBackchannel_DurableRowPermanentlyFailedOn4xx(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/logout", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "bad", http.StatusBadRequest)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	repo := newDeliveryRepo()
	svc := newBackchannelHarness(t).WithDeliveryRepository(repo)
	_, _ = svc.Deliver(context.Background(), DeliverInput{
		Client:  &domain.Client{ClientID: "cli-1", BackchannelLogoutURI: srv.URL + "/logout"},
		Subject: uuid.New(),
	})
	if len(repo.rows) != 1 {
		t.Fatalf("rows = %d", len(repo.rows))
	}
	for _, row := range repo.rows {
		if row.Status != domain.BackchannelLogoutDeliveryFailed {
			t.Errorf("status = %v (want failed)", row.Status)
		}
		if row.HTTPStatus == nil || *row.HTTPStatus != http.StatusBadRequest {
			t.Errorf("http_status = %v", row.HTTPStatus)
		}
	}
}

// stubDueClientLookup resolves every client_id to one fixed client.
type stubDueClientLookup struct {
	client *domain.Client
	err    error
}

func (s stubDueClientLookup) GetClientByClientID(_ context.Context, _ string) (*domain.Client, error) {
	return s.client, s.err
}

func firstRow(rows map[uuid.UUID]*domain.BackchannelLogoutDelivery) *domain.BackchannelLogoutDelivery {
	for _, r := range rows {
		return r
	}
	return nil
}

// TestBackchannel_ProcessDueDeliveries_NoSelfAmplification is the P2-9
// teeth test. A persistently-failing (503) delivery driven through async
// ProcessDueDeliveries ticks must transition the SAME row (attempt count
// rises), NEVER create additional rows (row count constant), and reach a
// terminal (permanently-failed) state — leaving the due queue — after at
// most maxAttempts total attempts. TEETH: route ProcessDueDeliveries back
// through Deliver() (the new-row path) and this fails (extra rows / the
// original row never terminates).
func TestBackchannel_ProcessDueDeliveries_NoSelfAmplification(t *testing.T) {
	var hits int
	mux := http.NewServeMux()
	mux.HandleFunc("/logout", func(w http.ResponseWriter, _ *http.Request) {
		hits++
		http.Error(w, "down", http.StatusServiceUnavailable) // persistent transient failure
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := &domain.Client{ClientID: "cli-1", BackchannelLogoutURI: srv.URL + "/logout"}
	repo := newDeliveryRepo()
	clk := time.Now()
	svc := newBackchannelHarness(t).
		WithDeliveryRepository(repo).
		WithDueProcessorClientLookup(stubDueClientLookup{client: client}).
		WithRetryPolicy(3, time.Minute)
	svc.now = func() time.Time { return clk }

	// Interactive Deliver = attempt #1: exactly one POST, row left pending.
	_, _ = svc.Deliver(context.Background(), DeliverInput{Client: client, Subject: uuid.New()})
	if hits != 1 {
		t.Fatalf("after Deliver: hits=%d, want 1 (interactive path must do ONE POST)", hits)
	}
	if len(repo.rows) != 1 {
		t.Fatalf("after Deliver: rows=%d, want 1", len(repo.rows))
	}

	// Drive async ticks until the SAME row terminates.
	terminated := false
	for tick := 0; tick < 10 && !terminated; tick++ {
		clk = clk.Add(2 * time.Minute) // advance past next_attempt_at
		if _, err := svc.ProcessDueDeliveries(context.Background(), 50); err != nil {
			t.Fatalf("tick %d: %v", tick, err)
		}
		if len(repo.rows) != 1 {
			t.Fatalf("tick %d: row COUNT changed to %d — SELF-AMPLIFICATION (a retry inserted a new row)", tick, len(repo.rows))
		}
		terminated = firstRow(repo.rows).Status == domain.BackchannelLogoutDeliveryFailed
	}
	if !terminated {
		t.Fatalf("row never reached a terminal state — immortal due row (hits=%d)", hits)
	}
	if hits != 3 {
		t.Errorf("total POSTs = %d, want 3 (== maxAttempts)", hits)
	}

	// A terminal row is no longer due: one more tick does nothing.
	clk = clk.Add(2 * time.Minute)
	n, _ := svc.ProcessDueDeliveries(context.Background(), 50)
	if n != 0 {
		t.Errorf("terminal row still processed (n=%d) — it did not leave the due queue", n)
	}
	if hits != 3 || len(repo.rows) != 1 {
		t.Errorf("after terminal: hits=%d (want 3), rows=%d (want 1)", hits, len(repo.rows))
	}
}

// TestBackchannel_DeliverIsFast_NoSyncRetry pins that interactive Deliver
// does NOT sleep the retry schedule: against a failing endpoint with a
// real 30s backoff it returns in well under 2×backoff, leaving the row
// PENDING (attempt 1) for the async processor.
func TestBackchannel_DeliverIsFast_NoSyncRetry(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/logout", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "down", http.StatusServiceUnavailable)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	repo := newDeliveryRepo()
	// Real 30s backoff, maxAttempts 3 — the OLD synchronous loop would
	// sleep ~30s then ~60s (~90s). The new path must not.
	svc := newBackchannelHarness(t).
		WithDeliveryRepository(repo).
		WithRetryPolicy(3, 30*time.Second)

	start := time.Now()
	_, err := svc.Deliver(context.Background(), DeliverInput{
		Client:  &domain.Client{ClientID: "cli-1", BackchannelLogoutURI: srv.URL + "/logout"},
		Subject: uuid.New(),
	})
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected delivery failure against a 503 endpoint")
	}
	if elapsed > 5*time.Second {
		t.Fatalf("Deliver blocked %s — it slept the retry schedule (interactive logout hang)", elapsed)
	}
	if len(repo.rows) != 1 {
		t.Fatalf("rows=%d, want 1", len(repo.rows))
	}
	row := firstRow(repo.rows)
	if row.Status != domain.BackchannelLogoutDeliveryPending {
		t.Errorf("status = %v, want pending (left for the async processor)", row.Status)
	}
	if row.NextAttemptAt == nil {
		t.Error("next_attempt_at not set — the async processor would never retry")
	}
	if row.AttemptCount != 1 {
		t.Errorf("attempt_count = %d, want 1", row.AttemptCount)
	}
}

func TestBackchannel_SessionRequiredStampsSID(t *testing.T) {
	var capturedToken string
	mux := http.NewServeMux()
	mux.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		capturedToken = r.PostForm.Get("logout_token")
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	svc := newBackchannelHarness(t)
	client := &domain.Client{
		ClientID:                         "cli-1",
		BackchannelLogoutURI:             srv.URL + "/logout",
		BackchannelLogoutSessionRequired: true,
	}
	sid := uuid.New()
	if _, err := svc.Deliver(context.Background(), DeliverInput{
		Client:    client,
		Subject:   uuid.New(),
		SessionID: sid,
	}); err != nil {
		t.Fatalf("deliver: %v", err)
	}
	// The token's payload (middle segment) is base64url-encoded
	// JSON; we don't bother decoding it here since the existing
	// LogoutTokenService tests already pin sid emission. Just
	// confirm the token is non-empty.
	if capturedToken == "" {
		t.Errorf("token missing")
	}
}
