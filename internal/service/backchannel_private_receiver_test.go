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
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// OSS-BACKCHANNEL-TEST-SEAM: the shipped delivery client refuses a receiver
// on loopback or a private network (the SSRF guard) and requires https. Only
// the TEST options wired by IDENTUUM_IDP_TEST_ALLOW_PRIVATE_BACKCHANNEL_RECEIVER
// reach such a receiver; the default is unchanged.

func newBackchannelLogoutTokens(t *testing.T) *LogoutTokenService {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	pkPEM, _ := x509.MarshalPKCS8PrivateKey(priv)
	provider := &inMemoryKeyProvider{keys: []domain.SigningKey{{
		KID:        "kid-eddsa",
		Algorithm:  domain.KeyAlgorithmEdDSA,
		PrivateKey: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkPEM})),
		State:      domain.KeyStateActive,
	}}}
	return NewLogoutTokenService(nil, provider, LogoutTokenServiceOptions{Issuer: "https://idp.test", TTL: time.Minute})
}

// The guard of the default: with no test options, a delivery to a receiver on
// loopback is refused before the receiver is reached, and the row is not
// delivered. This holds before and after the seam.
func TestBackchannel_DefaultClientRefusesLoopbackReceiver(t *testing.T) {
	var hits int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	repo := newDeliveryRepo()
	svc := NewBackchannelLogoutService(nil, newBackchannelLogoutTokens(t), BackchannelLogoutServiceOptions{Timeout: 2 * time.Second}).
		WithDeliveryRepository(repo).
		WithRetryPolicy(1, time.Millisecond)
	res, err := svc.Deliver(context.Background(), DeliverInput{
		Client:  &domain.Client{ClientID: "cli-1", BackchannelLogoutURI: srv.URL + "/backchannel-logout"},
		Subject: uuid.New(),
	})
	if !errors.Is(err, ErrBackchannelDeliveryFailed) {
		t.Fatalf("default client delivered to a loopback receiver: err=%v res=%+v", err, res)
	}
	if res == nil || res.Delivered {
		t.Fatalf("result = %+v; want not delivered", res)
	}
	if n := atomic.LoadInt32(&hits); n != 0 {
		t.Errorf("the loopback receiver was reached %d time(s); the SSRF guard must refuse the dial", n)
	}
	if len(repo.rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(repo.rows))
	}
	for _, row := range repo.rows {
		if row.Status == domain.BackchannelLogoutDeliveryDelivered {
			t.Errorf("row status = delivered; want a failed or pending row")
		}
	}
}

// With the test options a delivery reaches a plain-http receiver on loopback
// and the row is recorded as delivered.
func TestBackchannel_PrivateReceiverOptionsReachLoopback(t *testing.T) {
	var hits int32
	var gotToken string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		_ = r.ParseForm()
		gotToken = r.PostForm.Get("logout_token")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	opts := BackchannelPrivateReceiverOptions(2 * time.Second)
	if !opts.AllowPlainHTTP || opts.HTTPClient == nil || opts.Timeout != 2*time.Second {
		t.Fatalf("options = %+v; want the plain-http client with the https rule off", opts)
	}
	repo := newDeliveryRepo()
	svc := NewBackchannelLogoutService(nil, newBackchannelLogoutTokens(t), opts).
		WithDeliveryRepository(repo).
		WithRetryPolicy(1, time.Millisecond)
	res, err := svc.Deliver(context.Background(), DeliverInput{
		Client:  &domain.Client{ClientID: "cli-1", BackchannelLogoutURI: srv.URL + "/backchannel-logout"},
		Subject: uuid.New(),
	})
	if err != nil {
		t.Fatalf("deliver: %v", err)
	}
	if res == nil || !res.Delivered || res.Status != http.StatusOK {
		t.Fatalf("result = %+v; want delivered with 200", res)
	}
	if n := atomic.LoadInt32(&hits); n != 1 {
		t.Errorf("receiver hits = %d, want 1", n)
	}
	if gotToken == "" {
		t.Errorf("the receiver got no logout_token")
	}
	if len(repo.rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(repo.rows))
	}
	for _, row := range repo.rows {
		if row.Status != domain.BackchannelLogoutDeliveryDelivered {
			t.Errorf("row status = %v, want delivered", row.Status)
		}
	}
}

// The test options never follow a redirect: a POST carrying a logout token
// is answered by the registered receiver or not at all, as with the default
// client's redirect policy.
func TestBackchannel_PrivateReceiverOptionsFollowNoRedirect(t *testing.T) {
	var redirectedTo int32
	mux := http.NewServeMux()
	mux.HandleFunc("/elsewhere", func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&redirectedTo, 1)
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/backchannel-logout", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/elsewhere", http.StatusTemporaryRedirect)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	svc := NewBackchannelLogoutService(nil, newBackchannelLogoutTokens(t), BackchannelPrivateReceiverOptions(2*time.Second)).
		WithRetryPolicy(1, time.Millisecond)
	_, err := svc.Deliver(context.Background(), DeliverInput{
		Client:  &domain.Client{ClientID: "cli-1", BackchannelLogoutURI: srv.URL + "/backchannel-logout"},
		Subject: uuid.New(),
	})
	if !errors.Is(err, ErrBackchannelDeliveryFailed) {
		t.Fatalf("a redirecting receiver counted as delivered: %v", err)
	}
	if n := atomic.LoadInt32(&redirectedTo); n != 0 {
		t.Errorf("the redirect target was reached %d time(s); a logout token must not follow a redirect", n)
	}
}
