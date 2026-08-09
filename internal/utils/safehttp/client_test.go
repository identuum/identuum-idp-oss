package safehttp

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"net/url"

	"github.com/identuum/identuum-idp-oss/logger"
	"github.com/stretchr/testify/assert"
)

func TestMain(m *testing.M) {
	logger.InitializeZapLogger()
	os.Exit(m.Run())
}

func TestNewSafeClient(t *testing.T) {
	client := NewSafeClient()
	assert.NotNil(t, client)
	assert.Equal(t, 10*time.Second, client.Timeout)

	// Security invariant: NewSafeClient must NEVER inherit http.ProxyFromEnvironment.
	// A nil Proxy field on the underlying *http.Transport prevents an env-var proxy
	// SSRF bypass where HTTP_PROXY/HTTPS_PROXY could route NewSafeClient traffic
	// through an attacker-controlled proxy that forwards to internal addresses.
	transport, ok := client.Transport.(*http.Transport)
	assert.True(t, ok, "client.Transport must be a *http.Transport")
	assert.Nil(t, transport.Proxy, "NewSafeClient transport.Proxy must be nil to prevent env-var proxy SSRF bypass")
}

func TestNewInternalClient(t *testing.T) {
	client := NewInternalClient()
	assert.NotNil(t, client)
	assert.Equal(t, 15*time.Second, client.Timeout)

	// Security invariant (D-4.3-A): NewInternalClient must explicitly set
	// Proxy: nil — internal sidecar calls must never route through an egress
	// proxy even if HTTP_PROXY/HTTPS_PROXY are set in the environment.
	transport, ok := client.Transport.(*http.Transport)
	assert.True(t, ok, "client.Transport must be a *http.Transport")
	assert.Nil(t, transport.Proxy, "NewInternalClient transport.Proxy must be nil to prevent sidecar traffic from traversing an egress proxy")
}

// containsErrBlockedIP unwraps the layered error chain produced by http.Client
// (url.Error → net.OpError → *net.OpError.Err → ErrBlockedIP) and returns true
// only if ErrBlockedIP is present. This prevents silent regressions where a
// different error (e.g. connection timeout) passes assert.Error but the SSRF
// control hook is no longer firing.
func containsErrBlockedIP(err error) bool {
	return errors.Is(err, ErrBlockedIP)
}

func TestSafeClient_BlockLoopback(t *testing.T) {
	client := NewSafeClient()

	// 127.0.0.1 must be blocked by SafeDialer's control hook.
	req, _ := http.NewRequestWithContext(context.Background(), "GET", "http://127.0.0.1:8080/test", nil)
	resp, err := client.Do(req)
	if resp != nil {
		defer resp.Body.Close()
	}
	assert.True(t, containsErrBlockedIP(err), "expected ErrBlockedIP for 127.0.0.1, got: %v", err)

	// localhost resolves to 127.0.0.1 (or ::1) — both are blocked.
	req, _ = http.NewRequestWithContext(context.Background(), "GET", "http://localhost:8080/test", nil)
	_, err = client.Do(req)
	assert.True(t, containsErrBlockedIP(err), "expected ErrBlockedIP for localhost, got: %v", err)
}

func TestIsRestrictedIP(t *testing.T) {
	// Loopback
	assert.True(t, isRestrictedIP(net.ParseIP("127.0.0.1")))
	assert.True(t, isRestrictedIP(net.ParseIP("::1")))

	// Private
	assert.True(t, isRestrictedIP(net.ParseIP("10.0.0.1")))
	assert.True(t, isRestrictedIP(net.ParseIP("172.16.0.1")))
	assert.True(t, isRestrictedIP(net.ParseIP("192.168.1.1")))
	assert.True(t, isRestrictedIP(net.ParseIP("fc00::1")))

	// Link Local
	assert.True(t, isRestrictedIP(net.ParseIP("169.254.169.254"))) // AWS Metadata
	assert.True(t, isRestrictedIP(net.ParseIP("fe80::1")))

	// Unspecified
	assert.True(t, isRestrictedIP(net.ParseIP("0.0.0.0")))
	assert.True(t, isRestrictedIP(net.ParseIP("::")))

	// Multicast
	assert.True(t, isRestrictedIP(net.ParseIP("224.0.0.1")))
	assert.True(t, isRestrictedIP(net.ParseIP("ff01::1"))) // Interface-Local Multicast
	assert.True(t, isRestrictedIP(net.ParseIP("ff02::1"))) // Link-Local Multicast

	// Public
	assert.False(t, isRestrictedIP(net.ParseIP("8.8.8.8")))
	assert.False(t, isRestrictedIP(net.ParseIP("2606:4700:4700::1111")))
}

func TestSafeDialer_Control(t *testing.T) {
	dialer := SafeDialer()

	// Valid public IP should pass control
	err := dialer.Control("tcp", "8.8.8.8:443", nil)
	assert.NoError(t, err)

	// Blocked IP should fail
	err = dialer.Control("tcp", "10.0.0.1:80", nil)
	assert.ErrorIs(t, err, ErrBlockedIP)

	// Invalid IP format
	err = dialer.Control("tcp", "not-an-ip:80", nil)
	assert.ErrorContains(t, err, "invalid IP format")

	// IPv6 with zone
	err = dialer.Control("tcp", "[fe80::1%eth0]:80", nil)
	assert.ErrorIs(t, err, ErrBlockedIP)
}

func TestNewProxiedExternalClient(t *testing.T) {
	proxyURL, _ := url.Parse("http://proxy.corp.example:3128")
	client := NewProxiedExternalClient(nil, proxyURL)

	assert.NotNil(t, client)
	assert.Equal(t, 10*time.Second, client.Timeout)

	// Transport must be an explicit *http.Transport with a non-nil Proxy function.
	transport, ok := client.Transport.(*http.Transport)
	assert.True(t, ok, "client.Transport must be a *http.Transport")
	assert.NotNil(t, transport.Proxy, "NewProxiedExternalClient transport.Proxy must be non-nil (egress proxy wired)")
}

func TestNewProxiedExternalClient_NilPanic(t *testing.T) {
	// Passing nil must panic with a descriptive guard message to prevent
	// silent misconfiguration (e.g. calling this when EgressProxyURL was not set).
	assert.NotPanics(t, func() { NewProxiedExternalClient(nil, nil) })
}
