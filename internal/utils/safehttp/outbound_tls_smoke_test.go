package safehttp_test

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/identuum/identuum-idp-oss/internal/utils/safehttp"
)

// P2-22 — THE OUTBOUND-TLS SMOKE.
//
// Nothing in the gates exercised egress. OIDC discovery and JWKS are the
// product's only outbound path, so a broken CA bundle or a transport that
// silently accepts anything would pass every gate and fail in production —
// the same shape of hole as a missing concurrency test.
//
// OWNER POLICY (THE-EMPTY-QUEUE order D): "the TLS smoke reaches ONLY a
// loopback listener the test itself starts. No gate gets external egress."
// So this starts a real TLS server on 127.0.0.1 with a self-signed
// certificate, and drives the REAL client the product uses. It needs no
// network, no fixture host, and no CA bundle from the image — which is
// precisely why it can run in every gate.
//
// What it proves, in order of what would actually break:
//  1. a genuine TLS handshake completes and a JSON body is read, over the
//     INTERNAL client (the sidecar/loopback path)
//  2. the SafeClient REFUSES that same loopback target — the SSRF control is
//     live, and a smoke test that used the permissive client would have hidden
//     that entirely
//  3. TLS verification is real: an UNTRUSTED self-signed certificate is
//     rejected. A client that accepted anything would pass (1) and protect
//     nothing.
func TestOutboundTLS_SmokeAgainstALoopbackListener(t *testing.T) {
	t.Parallel()

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"issuer":"https://loopback.test","jwks_uri":"https://loopback.test/jwks"}`))
	}))
	defer srv.Close()

	// 1. A REAL handshake, with the server's certificate trusted explicitly.
	//    This is the discovery fetch the product performs.
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())

	client := safehttp.NewInternalClient()
	tr, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("SafeClient transport is %T, want *http.Transport", client.Transport)
	}
	if tr.Proxy != nil {
		t.Error("the internal client has a Proxy set: HTTP(S)_PROXY would redirect sidecar " +
			"traffic off-host")
	}
	tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}

	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("outbound TLS to a loopback listener FAILED: %v — this is the product's only "+
			"egress path (OIDC discovery / JWKS)", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("discovery fetch → HTTP %d, want 200", resp.StatusCode)
	}
	var doc map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatalf("the TLS body did not decode as JSON: %v", err)
	}
	if doc["issuer"] != "https://loopback.test" {
		t.Errorf("issuer = %v, want the loopback listener's", doc["issuer"])
	}
	if resp.TLS == nil {
		t.Fatal("the response carries no TLS state — the request did not actually go over TLS, " +
			"so this test would pass against a plaintext server")
	}

	// 2. The SafeClient — the EXTERNAL path — must REFUSE this same loopback
	//    target. Egress control is not decoration: a smoke test written against
	//    the permissive client would have proven TLS while hiding the fact that
	//    the SSRF guard had stopped working.
	safe := safehttp.NewSafeClient()
	safeTr, ok := safe.Transport.(*http.Transport)
	if !ok || safeTr.DialContext == nil {
		t.Fatal("SafeClient has no DialContext: the SSRF dialer hook is gone, so external egress " +
			"is unfiltered")
	}
	if safeTr.Proxy != nil {
		t.Error("SafeClient has a Proxy set: HTTP(S)_PROXY would tunnel CONNECT past the dialer " +
			"hook, silently bypassing the SSRF control")
	}
	if _, err := safe.Get(srv.URL); err == nil {
		t.Fatal("the SafeClient REACHED a loopback address — the SSRF control is not blocking " +
			"private targets")
	} else if !strings.Contains(err.Error(), "SSRF") && !strings.Contains(err.Error(), "restricted") {
		t.Errorf("SafeClient refused loopback for the WRONG reason (%v); it must be the SSRF "+
			"guard, not a transport error that would vanish on a different host", err)
	}

	// 3. TLS verification is real: the same internal client, WITHOUT the
	//    server's certificate trusted, must refuse it.
	untrusting := safehttp.NewInternalClient()
	if _, err := untrusting.Get(srv.URL); err == nil {
		t.Fatal("an UNTRUSTED self-signed certificate was accepted — verification is disabled " +
			"somewhere, and every outbound fetch is open to interception")
	} else if !strings.Contains(err.Error(), "certificate") && !strings.Contains(err.Error(), "x509") {
		t.Errorf("the untrusted certificate was refused for the wrong reason: %v", err)
	}
}
