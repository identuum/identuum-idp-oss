package safehttp

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"time"

	"github.com/identuum/identuum-idp-oss/internal/lifecycle"
	"github.com/identuum/identuum-idp-oss/logger"
)

var (
	ErrBlockedIP = errors.New("security violation: target IP falls within a restricted internal/private subnet (SSRF prevented)")
)

// SafeDialer returns a net.Dialer configured to block connections to loopback,
// private (RFC 1918 / RFC 4193), link-local unicast (RFC 3927), and unspecified IPs.
func SafeDialer() *net.Dialer {
	return &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
		Control: func(network, address string, c syscall.RawConn) error {
			// address is the resolved IP:port
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				// If we can't split it, assume it's just the IP
				host = address
			}

			// Clean up IPv6 zone identifiers if present
			if idx := strings.IndexByte(host, '%'); idx != -1 {
				host = host[:idx]
			}

			ip := net.ParseIP(host)
			if ip == nil {
				return fmt.Errorf("invalid IP format: %s", host)
			}

			if isRestrictedIP(ip) {
				logger.Security.Printf("BLOCKED SSRF ATTEMPT: Connection to restricted IP %s prevented", ip.String())
				return ErrBlockedIP
			}

			return nil
		},
	}
}

// NewSafeClient returns an http.Client equipped with the SafeDialer.
func NewSafeClient() *http.Client {
	dialer := SafeDialer()
	transport := &http.Transport{
		// No proxy: HTTP_PROXY/HTTPS_PROXY env vars would tunnel CONNECT through a proxy
		// whose IP passes SafeDialer but whose target does not — silently bypassing the
		// SSRF control hook. Leaving Proxy nil (no proxy) is the safe default.
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	return &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}
}

// NewInternalClient returns an http.Client for controlled internal
// service-to-service communication (e.g. sidecar calls within Docker/K8s)
// where the target URL is supplied by trusted application configuration,
// not by user input. It intentionally skips SSRF IP filtering.
//
// SECURITY: This client explicitly sets Proxy: nil on its transport.
// Internal sidecar calls must NEVER traverse an external egress proxy,
// even in partially air-gapped deployments where HTTP_PROXY/HTTPS_PROXY
// are set for permitted external traffic. Using the env-var proxy for
// sidecar traffic could silently route internal calls through an
// attacker-controlled proxy if those env vars are ever misconfigured.
// For external calls that must traverse an operator-configured egress
// proxy, use NewProxiedExternalClient instead.
func NewInternalClient() *http.Client {
	// Clone http.DefaultTransport to inherit standard connection-pool, TLS,
	// and timeout settings, then null the proxy to ensure sidecar traffic
	// is never redirected through HTTP_PROXY/HTTPS_PROXY.
	base := http.DefaultTransport.(*http.Transport).Clone()
	base.Proxy = nil
	return &http.Client{
		Transport: base,
		Timeout:   15 * time.Second,
	}
}

// NewProxiedExternalClient returns an http.Client that routes all traffic
// through the operator-configured egress proxy at proxyURL. This is intended
// for partially air-gapped deployments where external services (OIDC provider
// discovery, webhook delivery) are reachable only via a single controlled
// HTTP/HTTPS proxy.
//
// SECURITY TRUST MODEL:
//   - proxyURL MUST originate from operator configuration, never from user
//     input. Passing a user-supplied URL here bypasses all SSRF controls.
//     (No production caller currently resolves an egress-proxy URL from any
//     config source — the config field this depended on shipped in the now-
//     removed appconfig package.)
//   - SafeDialer is intentionally NOT used: when a proxy is active, the TCP
//     DialContext connects to the proxy server's IP, which is often a private
//     address in a DMZ segment. The SSRF protection responsibility shifts to
//     the proxy server itself (network-level policy enforcement).
//   - proxyURL must not be nil; callers should guard against this.
func NewProxiedExternalClient(report *lifecycle.StartupReport, proxyURL *url.URL) *http.Client {
	if proxyURL == nil {
		report.Fatal("NewProxiedExternalClient", "safehttp.NewProxiedExternalClient: proxyURL must not be nil; use NewSafeClient for direct external access")
	}
	transport := &http.Transport{
		Proxy:                 http.ProxyURL(proxyURL),
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	return &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}
}

func isRestrictedIP(ip net.IP) bool {
	if ip.IsLoopback() {
		return true // 127.0.0.0/8, ::1/128
	}
	if ip.IsPrivate() {
		return true // RFC 1918 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) and RFC 4193 (fc00::/7)
	}
	if ip.IsLinkLocalUnicast() {
		return true // RFC 3927 (169.254.0.0/16) and RFC 4291 (fe80::/10)
	}
	if ip.IsUnspecified() {
		return true // 0.0.0.0, ::
	}
	if ip.IsMulticast() || ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast() {
		return true // Precaution against multicast broadcasts
	}
	// AWS metadata IP specifically, though covered by IsLinkLocalUnicast, we can be explicit if needed.
	// 169.254.169.254 is link-local, so it's covered by IsLinkLocalUnicast.

	// P3-7: special-purpose ranges the stdlib helpers above do NOT cover.
	//
	// None of these is routable on the public internet, so an outbound request
	// arriving at one is either a misconfiguration or an SSRF pivot. CGNAT is
	// the one that matters in practice rather than in theory: 100.64.0.0/10 is
	// LIVE address space inside many hosting providers, so a tenant-supplied
	// URL resolving there can reach a neighbour's service while passing every
	// RFC 1918 check.
	//
	// net.IP.IsPrivate() covers only RFC 1918 and RFC 4193; it does not know
	// about any of these. Pinned by TestIsRestrictedIP_CoversSpecialPurposeRanges,
	// which also asserts 8.8.8.8 / 1.1.1.1 stay reachable so this cannot quietly
	// become a denial of service.
	for _, cidr := range specialPurposeRanges {
		if cidr.Contains(ip) {
			return true
		}
	}

	return false
}

// specialPurposeRanges are parsed once at init; a parse failure here is a
// programming error in the literals below, not a runtime condition.
var specialPurposeRanges = mustParseCIDRs(
	"100.64.0.0/10",   // RFC 6598 carrier-grade NAT
	"192.0.0.0/24",    // RFC 6890 IETF protocol assignments
	"198.18.0.0/15",   // RFC 2544 benchmarking
	"192.0.2.0/24",    // RFC 5737 TEST-NET-1
	"198.51.100.0/24", // RFC 5737 TEST-NET-2
	"203.0.113.0/24",  // RFC 5737 TEST-NET-3
	"240.0.0.0/4",     // RFC 1112 reserved (includes 255.255.255.255)
	"2001:db8::/32",   // RFC 3849 IPv6 documentation
	"64:ff9b::/96",    // RFC 6052 IPv4/IPv6 translation
	"2002::/16",       // RFC 3056 6to4 — embeds an arbitrary IPv4 destination
)

func mustParseCIDRs(cidrs ...string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			panic("safehttp: unparseable special-purpose CIDR literal " + c + ": " + err.Error())
		}
		out = append(out, n)
	}
	return out
}
