package main

import "testing"

// P2-4: the metrics-listener default is LOOPBACK, an explicit routable address
// opts into exposure, the flag wins over the env, and "-" disables the listener.
func TestResolveMetricsAddr(t *testing.T) {
	cases := []struct {
		name, flag, env, want string
	}{
		{"default is loopback", "", "", "127.0.0.1:9090"},
		{"env sets the address", "", "0.0.0.0:9090", "0.0.0.0:9090"},
		{"flag sets the address", "127.0.0.1:9999", "", "127.0.0.1:9999"},
		{"flag wins over env", "127.0.0.1:9999", "0.0.0.0:9090", "127.0.0.1:9999"},
		{"explicit 0.0.0.0 exposes (flag)", "0.0.0.0:9090", "", "0.0.0.0:9090"},
		{"'-' flag disables", "-", "", ""},
		{"'-' env disables", "", "-", ""},
		{"'-' flag wins over an env address", "-", "0.0.0.0:9090", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := resolveMetricsAddr(tc.flag, tc.env); got != tc.want {
				t.Errorf("resolveMetricsAddr(%q, %q) = %q, want %q", tc.flag, tc.env, got, tc.want)
			}
		})
	}
}

// The default must NOT be an all-interfaces bind — that was the P2-4 defect.
func TestResolveMetricsAddr_DefaultNotAllInterfaces(t *testing.T) {
	got := resolveMetricsAddr("", "")
	if got == "0.0.0.0:9090" || got == ":9090" {
		t.Fatalf("default metrics addr = %q — must be loopback, never all-interfaces", got)
	}
	if got != "127.0.0.1:9090" {
		t.Errorf("default metrics addr = %q, want 127.0.0.1:9090", got)
	}
	if defaultMetricsAddr != "127.0.0.1:9090" {
		t.Errorf("defaultMetricsAddr = %q, want 127.0.0.1:9090", defaultMetricsAddr)
	}
}
