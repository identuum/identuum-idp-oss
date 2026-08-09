package runtime

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

// P2-4: the metrics listener binds exactly the address it is handed — loopback
// stays loopback (the new default), an explicit 0.0.0.0 exposes all interfaces,
// and the disabled ("") config (what the "-" sentinel resolves to) binds nothing.
func TestStartMetricsListener_BindScope(t *testing.T) {
	stop := func(r *Runtime) {
		if r.metricsSrv != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_ = r.metricsSrv.Shutdown(ctx)
		}
	}
	hostOf := func(r *Runtime) string {
		host, _, err := net.SplitHostPort(r.metricsListener.Addr().String())
		if err != nil {
			t.Fatalf("SplitHostPort(%q): %v", r.metricsListener.Addr().String(), err)
		}
		return host
	}

	// Disabled: empty MetricsAddr binds NO listener (the "-" disable path).
	rDisabled := &Runtime{cfg: Config{MetricsAddr: "", Stdout: io.Discard, Stderr: io.Discard}}
	rDisabled.startMetricsListener()
	if rDisabled.metricsListener != nil {
		stop(rDisabled)
		t.Error(`empty MetricsAddr must not bind a metrics listener (the "-" disable path)`)
	}

	// Loopback default: 127.0.0.1 binds a loopback address, NOT all interfaces.
	rLoop := &Runtime{cfg: Config{MetricsAddr: "127.0.0.1:0", Stdout: io.Discard, Stderr: io.Discard}}
	rLoop.startMetricsListener()
	t.Cleanup(func() { stop(rLoop) })
	if rLoop.metricsListener == nil {
		t.Fatal("loopback MetricsAddr must bind a listener")
	}
	if host := hostOf(rLoop); !net.ParseIP(host).IsLoopback() {
		t.Errorf("loopback config bound host = %q, want a loopback address (not reachable off-box)", host)
	}

	// Explicit expose: 0.0.0.0 binds the unspecified (all-interfaces) address.
	rAll := &Runtime{cfg: Config{MetricsAddr: "0.0.0.0:0", Stdout: io.Discard, Stderr: io.Discard}}
	rAll.startMetricsListener()
	t.Cleanup(func() { stop(rAll) })
	if rAll.metricsListener == nil {
		t.Fatal("0.0.0.0 MetricsAddr must bind a listener (explicit expose)")
	}
	if host := hostOf(rAll); !net.ParseIP(host).IsUnspecified() {
		t.Errorf("0.0.0.0 config bound host = %q, want the unspecified all-interfaces address", host)
	}
}
