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

// runHealthcheck is the container's liveness probe (`identuum-idp
// healthcheck [base-url]`). The runtime image is distroless — no shell, no
// curl — so Docker's HEALTHCHECK can only run the binary itself. It asks
// this process's own GET /healthz and exits 0 on 200, 1 on anything else
// (including nothing listening), within a short bound. Without an argument
// it targets the listen address the appliance serves on.
func runHealthcheck(rest []string, stdout, stderr io.Writer) int {
	base := ""
	if len(rest) > 0 {
		base = rest[0]
	}
	target := healthcheckTarget(base)
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(target)
	if err != nil {
		fmt.Fprintln(stderr, "identuum-idp healthcheck: no answer from", target)
		return 1
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(stderr, "identuum-idp healthcheck: %s answered %d\n", target, resp.StatusCode)
		return 1
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
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	return "http://" + net.JoinHostPort(host, port) + "/healthz"
}
