package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// These release-input tests use the same cached, offline dependency files as
// generation. They do not contact a server or use operator credentials.
func TestGoCompiledSubpackageLicenses(t *testing.T) {
	t.Setenv("GOPROXY", "off")
	repo := os.Getenv("NOTICES_TEST_REPO")
	if repo == "" {
		repo = "../.."
	}
	in, dirs, err := inputs(repo)
	if err != nil {
		t.Fatal(err)
	}
	comps, err := goComponents(in.BuildList, dirs)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		module, version, file, spdx string
	}{
		{"github.com/go-webauthn/x", "v0.3.0", "crypto/secp256k1/LICENSE", "ISC"},
		{"github.com/go-webauthn/x", "v0.3.0", "revoke/LICENSE", "BSD-2-Clause"},
		{"github.com/prometheus/client_golang", "v1.24.1", "internal/github.com/golang/gddo/LICENSE", "BSD-3-Clause"},
	} {
		t.Run(tc.file, func(t *testing.T) {
			cache, err := exec.Command("go", "env", "GOMODCACHE").Output()
			if err != nil {
				t.Fatal(err)
			}
			raw, err := os.ReadFile(filepath.Join(strings.TrimSpace(string(cache)), tc.module+"@"+tc.version, tc.file))
			if err != nil {
				t.Fatal(err)
			}
			for _, c := range comps {
				if c.Name != tc.module {
					continue
				}
				for _, text := range c.Texts {
					if text.File != tc.file {
						continue
					}
					if text.Text != string(raw) {
						t.Error("licence bytes differ from dependency file")
					}
					if !strings.Contains(c.SPDX, tc.spdx) {
						t.Errorf("SPDX = %s, missing %s", c.SPDX, tc.spdx)
					}
					if !strings.Contains(Render(in, []Component{c}), string(raw)) {
						t.Error("rendered notice omits exact licence bytes")
					}
					return
				}
				t.Fatalf("%s: compiled subpackage licence %s omitted", c.Name, tc.file)
			}
			t.Fatalf("module %s not in build list", tc.module)
		})
	}
	// A recursive scan of every file would incorrectly add the logo policy.
	for _, c := range comps {
		if c.Name == "github.com/quic-go/quic-go" {
			for _, text := range c.Texts {
				if strings.HasPrefix(text.File, "assets/") {
					t.Fatal("uncompiled brand-asset licence included")
				}
			}
		}
	}
}

func TestLicenseTextBytesPreserved(t *testing.T) {
	dir := t.TempDir()
	raw := "Copyright fixture\r\nLicence fixture\r\n\r\n"
	if err := os.WriteFile(filepath.Join(dir, "LICENSE"), []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	texts, err := licenseFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(texts) != 1 || texts[0].Text != raw {
		t.Fatal("licence reader changed CRLF or trailing bytes")
	}
	if !strings.Contains(Render(Inputs{}, []Component{{Texts: texts}}), raw) {
		t.Fatal("renderer changed licence bytes")
	}
}
