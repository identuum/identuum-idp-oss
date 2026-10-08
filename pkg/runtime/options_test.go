package runtime

import (
	"bytes"
	"reflect"
	"testing"
	"time"

	internalruntime "github.com/identuum/identuum-idp-oss/internal/runtime"
)

// optionToConfig names, for every Options field, the private Config field it
// maps to. A field added on either side without an entry here fails the test.
var optionToConfig = map[string]string{
	"Addr":                      "Addr",
	"Issuer":                    "Issuer",
	"DatabaseURL":               "JWKSDBURL",
	"RevocationCleanupInterval": "RevocationCleanupInterval",
	"Version":                   "Version",
	"Stdout":                    "Stdout",
	"Stderr":                    "Stderr",
	"Getenv":                    "Getenv",
	"DataDir":                   "DataDir",
	"UIPublicBaseURL":           "UIPublicBaseURL",
	"UIStaticDir":               "UIStaticDir",
	"MetricsAddr":               "MetricsAddr",
	"CORSAllowedOrigins":        "CORSAllowedOrigins",
	"TrustedProxies":            "TrustedProxies",
}

// OSS-SEAM-1 proof 2: every configuration option is mapped, one to one, and
// nothing is dropped or invented.
func TestOptions_MapEveryConfigField(t *testing.T) {
	ot, ct := reflect.TypeOf(Options{}), reflect.TypeOf(internalruntime.Config{})
	if ot.NumField() != len(optionToConfig) || ct.NumField() != len(optionToConfig) {
		t.Fatalf("Options has %d fields, Config %d, the mapping table %d: every field needs exactly one entry",
			ot.NumField(), ct.NumField(), len(optionToConfig))
	}
	seen := map[string]bool{}
	for o, c := range optionToConfig {
		of, ok1 := ot.FieldByName(o)
		cf, ok2 := ct.FieldByName(c)
		if !ok1 || !ok2 || of.Type != cf.Type {
			t.Fatalf("Options.%s -> Config.%s: present %v/%v, types must match", o, c, ok1, ok2)
		}
		if seen[c] {
			t.Fatalf("Config.%s is mapped twice", c)
		}
		seen[c] = true
	}

	// Every field set to a distinct value arrives in its own Config field.
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	getenvCalled := ""
	opts := Options{
		Addr: "addr", Issuer: "issuer", DatabaseURL: "db", RevocationCleanupInterval: 7 * time.Second,
		Version: "version", Stdout: stdout, Stderr: stderr,
		Getenv:  func(k string) string { getenvCalled = k; return "" },
		DataDir: "data", UIPublicBaseURL: "ui-url", UIStaticDir: "ui-dir", MetricsAddr: "metrics",
		CORSAllowedOrigins: []string{"https://a.test"}, TrustedProxies: []string{"10.0.0.1"},
	}
	cfg := opts.config()
	ov, cv := reflect.ValueOf(opts), reflect.ValueOf(cfg)
	for o, c := range optionToConfig {
		got, want := cv.FieldByName(c), ov.FieldByName(o)
		if got.IsZero() {
			t.Errorf("Config.%s is empty: Options.%s was not mapped", c, o)
			continue
		}
		switch want.Kind() {
		case reflect.Func:
			got.Interface().(func(string) string)("probe")
			if getenvCalled != "probe" {
				t.Errorf("Config.%s is not the Options.%s function", c, o)
			}
		default:
			if !reflect.DeepEqual(got.Interface(), want.Interface()) {
				t.Errorf("Config.%s differs from Options.%s", c, o)
			}
		}
	}

	// The slices are copies: a caller's later change does not reach the runtime.
	opts.CORSAllowedOrigins[0], opts.TrustedProxies[0] = "changed", "changed"
	if cfg.CORSAllowedOrigins[0] != "https://a.test" || cfg.TrustedProxies[0] != "10.0.0.1" {
		t.Error("Config shares the caller's slices")
	}
}
