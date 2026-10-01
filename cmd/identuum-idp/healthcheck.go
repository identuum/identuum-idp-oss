package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// runHealthcheck is the container's health probe (`identuum-idp
// healthcheck [base-url]`). The runtime image is distroless — no shell, no
// curl — so Docker's HEALTHCHECK can only run the binary itself. It asks
// this process's own GET /healthz (liveness) and then GET /readyz (the
// store answers a ping), and exits 0 only when both answer 200, 1 on
// anything else (including nothing listening), each within a short bound.
// OSS-POLISH: /healthz alone stayed 200 with the database stopped, so the
// container read healthy while it could serve nothing. Without an argument
// it targets the listen address the appliance serves on.
func runHealthcheck(rest []string, stdout, stderr io.Writer) int {
	base := ""
	if len(rest) > 0 {
		base = rest[0]
	}
	target := healthcheckTarget(base)
	client := &http.Client{Timeout: 3 * time.Second}
	for _, probe := range []string{target, strings.TrimSuffix(target, "/healthz") + "/readyz"} {
		resp, err := client.Get(probe)
		if err != nil {
			fmt.Fprintln(stderr, "identuum-idp healthcheck: no answer from", probe)
			return 1
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			fmt.Fprintf(stderr, "identuum-idp healthcheck: %s answered %d\n", probe, resp.StatusCode)
			return 1
		}
	}
	fmt.Fprintln(stdout, "healthy")
	return 0
}

// healthcheckTarget is base + "/healthz", or, without a base, the /healthz
// of the address the appliance listens on (IDENTUUM_IDP_LISTEN, then
// IDENTUUM_IDP_OSS_LISTEN, then 0.0.0.0:7113 — internal/appliance's
// precedence), reached over loopback when it binds every interface.
func healthcheckTarget(base string) string {
	if base != "" {
		return strings.TrimRight(base, "/") + "/healthz"
	}
	listen := os.Getenv("IDENTUUM_IDP_LISTEN")
	if listen == "" {
		listen = os.Getenv("IDENTUUM_IDP_OSS_LISTEN")
	}
	if listen == "" {
		listen = "0.0.0.0:7113"
	}
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		host, port = "", "7113"
	}
	switch host {
	case "", "0.0.0.0":
		host = "127.0.0.1"
	case "::":
		// IPv6 wildcard (D-020): reachable on IPv4 only where the OS gives a
		// dual-stack socket; [::1] always is.
		host = "::1"
	}
	return "http://" + net.JoinHostPort(host, port) + "/healthz"
}
