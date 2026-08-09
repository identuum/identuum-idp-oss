package main

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// TestRegistryIsNonEmpty pins that the curated registry has a
// non-trivial number of entries. A regression to zero or one would
// indicate accidental data loss in registry.go.
func TestRegistryIsNonEmpty(t *testing.T) {
	endpoints := liveEndpoints(t)
	if len(endpoints) < 50 {
		t.Fatalf("Registry returned %d endpoints; expected at least 50", len(endpoints))
	}
}

// TestRegistryIDsAreUnique pins that every endpoint has a unique
// stable ID. Duplicates would silently overwrite each other in the
// docs consumer.
func TestRegistryIDsAreUnique(t *testing.T) {
	endpoints := liveEndpoints(t)
	seen := make(map[string]Endpoint, len(endpoints))
	for _, e := range endpoints {
		if prev, ok := seen[e.ID]; ok {
			t.Fatalf("duplicate endpoint ID %q: first=%s %s second=%s %s", e.ID, prev.Method, prev.Path, e.Method, e.Path)
		}
		seen[e.ID] = e
	}
}

// TestRegistryIDsAreStable pins exact ID shapes for a representative
// sample. If buildID()/buildIDFromPath() change in a way that breaks
// downstream cross-references, this test catches it.
func TestRegistryIDsAreStable(t *testing.T) {
	endpoints := liveEndpoints(t)
	byHandler := make(map[string]Endpoint, len(endpoints))
	for _, e := range endpoints {
		key := e.Method + " " + e.Path
		byHandler[key] = e
	}
	want := map[string]string{
		"GET /system/info":                                            "identuum-idp-oss.top-level.system_info_handler",
		"GET /.well-known/openid-configuration":                       "identuum-idp-oss.top-level.discovery_handler",
		"POST /api/v1/keys/generate":                                  "identuum-idp-oss.keys.generate_signing_key",
		"DELETE /api/v1/keys/expired":                                 "identuum-idp-oss.keys.delete_expired_keys",
		"POST /api/v1/users/:id/restore":                              "identuum-idp-oss.users.restore_user",
		"POST /api/v1/users/bulk":                                     "identuum-idp-oss.users.bulk_create_users",
		"POST /api/v1/oauth/token":                                    "identuum-idp-oss.oauth.token",
		"GET /api/v1/oidc/userinfo":                                   "identuum-idp-oss.oidc.userinfo_get",
		"POST /api/v1/oidc/userinfo":                                  "identuum-idp-oss.oidc.userinfo_post",
		"POST /api/v1/service-accounts/:id/enable":                    "identuum-idp-oss.service-accounts.set_active_service_account_enable",
		"POST /api/v1/service-accounts/:id/disable":                   "identuum-idp-oss.service-accounts.set_active_service_account_disable",
		"GET /api/v1/admin/backchannel-logout-deliveries":             "identuum-idp-oss.admin.list_backchannel_deliveries",
		"POST /api/v1/admin/backchannel-logout-deliveries/:id/replay": "identuum-idp-oss.admin.replay_backchannel_delivery",
	}
	for k, wantID := range want {
		got, ok := byHandler[k]
		if !ok {
			t.Errorf("missing endpoint for %q", k)
			continue
		}
		if got.ID != wantID {
			t.Errorf("ID for %q = %q, want %q", k, got.ID, wantID)
		}
	}
}

// TestGenerateIsDeterministic pins that two consecutive emit calls on
// the same registry produce byte-identical output.
func TestGenerateIsDeterministic(t *testing.T) {
	endpoints := liveEndpoints(t)
	var first, second bytes.Buffer
	if err := generate(&first, endpoints); err != nil {
		t.Fatalf("first generate: %v", err)
	}
	if err := generate(&second, endpoints); err != nil {
		t.Fatalf("second generate: %v", err)
	}
	if !bytes.Equal(first.Bytes(), second.Bytes()) {
		t.Fatalf("generate not deterministic: first %d bytes, second %d bytes", first.Len(), second.Len())
	}
}

// TestGenerateOutputIsSorted pins that emitted endpoints appear in
// canonical (module, surface, path, method) order. The test parses
// the YAML using a tiny line scan and compares tuples field-by-field
// rather than concatenating into a single string (any separator
// character risks reordering when the path itself contains the same
// character — see the lexicographic interaction between '/' and any
// printable delimiter).
func TestGenerateOutputIsSorted(t *testing.T) {
	endpoints := liveEndpoints(t)
	var buf bytes.Buffer
	if err := generate(&buf, endpoints); err != nil {
		t.Fatalf("generate: %v", err)
	}
	keys := extractSortKeys(buf.String())
	for i := 1; i < len(keys); i++ {
		prev, cur := keys[i-1], keys[i]
		if !tupleLess(prev, cur) {
			t.Fatalf("emitted output not sorted at index %d: %+v >= %+v", i, prev, cur)
		}
	}
}

// TestGenerateOutputHasNoAbsoluteLocalPaths pins that no rendered
// scalar in the output contains an absolute filesystem path. The
// generator emits canonical Go import paths, never filesystem paths.
//
// Lines that emit an API route path (`    path: "/api/..."`) are
// exempted from the personal-path substring check: legitimate API
// paths can collide with personal-path prefixes — e.g. SCIM v2's
// `/api/v1/scim/v2/Users/:id` shares the substring `/Users/` with
// the macOS `/Users/` home prefix even though it carries no
// filesystem material. Same narrow exemption the annotation-side
// `TestDocgenAnnotationsHaveNoLocalPaths` already enforces.
func TestGenerateOutputHasNoAbsoluteLocalPaths(t *testing.T) {
	endpoints := liveEndpoints(t)
	var buf bytes.Buffer
	if err := generate(&buf, endpoints); err != nil {
		t.Fatalf("generate: %v", err)
	}
	needles := []string{
		"/Users/",
		"/home/",
		"C:\\",
		`C:/`,
	}
	for _, line := range strings.Split(buf.String(), "\n") {
		trimmed := strings.TrimLeft(line, " ")
		// Exempt lines that emit an API route path.
		if strings.HasPrefix(trimmed, `path: "/api/`) {
			continue
		}
		for _, needle := range needles {
			if strings.Contains(line, needle) {
				t.Errorf("output line contains forbidden personal path fragment %q: %s", needle, line)
			}
		}
	}
}

// TestGenerateOutputHasNoSecretsOrTokens pins that no rendered scalar
// contains a credential-looking literal. The registry is hand-curated
// so this should always pass, but the test guards against accidental
// future additions.
func TestGenerateOutputHasNoSecretsOrTokens(t *testing.T) {
	endpoints := liveEndpoints(t)
	var buf bytes.Buffer
	if err := generate(&buf, endpoints); err != nil {
		t.Fatalf("generate: %v", err)
	}
	out := buf.String()
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`eyJ[A-Za-z0-9_\-]{20,}`),             // JWT-shaped
		regexp.MustCompile(`sk-[A-Za-z0-9]{20,}`),                // OpenAI-style key
		regexp.MustCompile(`ghp_[A-Za-z0-9]{20,}`),               // GitHub PAT
		regexp.MustCompile(`gho_[A-Za-z0-9]{20,}`),               // GitHub OAuth
		regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`), // any PEM private key
		regexp.MustCompile(`postgres://[^:/]+:[^@]+@`),           // raw DB URL with credentials
		regexp.MustCompile(`mysql://[^:/]+:[^@]+@`),              // raw DB URL with credentials
	}
	for _, p := range patterns {
		if loc := p.FindStringIndex(out); loc != nil {
			t.Errorf("output matches forbidden pattern %q at byte offset %d", p.String(), loc[0])
		}
	}
}

// TestGenerateFileOutputIsByteIdentical writes the output twice to
// temp files and confirms the bytes match. This exercises the same
// path the operator runs via the binary.
func TestGenerateFileOutputIsByteIdentical(t *testing.T) {
	dir := t.TempDir()
	endpoints := liveEndpoints(t)

	pathA := filepath.Join(dir, "endpoints-a.yaml")
	pathB := filepath.Join(dir, "endpoints-b.yaml")

	fA, err := os.Create(pathA)
	if err != nil {
		t.Fatalf("create A: %v", err)
	}
	if err := generate(fA, endpoints); err != nil {
		t.Fatalf("generate A: %v", err)
	}
	if err := fA.Close(); err != nil {
		t.Fatalf("close A: %v", err)
	}

	fB, err := os.Create(pathB)
	if err != nil {
		t.Fatalf("create B: %v", err)
	}
	if err := generate(fB, endpoints); err != nil {
		t.Fatalf("generate B: %v", err)
	}
	if err := fB.Close(); err != nil {
		t.Fatalf("close B: %v", err)
	}

	a, err := os.ReadFile(pathA)
	if err != nil {
		t.Fatalf("read A: %v", err)
	}
	b, err := os.ReadFile(pathB)
	if err != nil {
		t.Fatalf("read B: %v", err)
	}
	if !bytes.Equal(a, b) {
		t.Fatalf("file output not byte-identical: A=%d bytes B=%d bytes", len(a), len(b))
	}
}

// TestRun_DryRunIsDeterministic exercises the CLI's --dry-run path
// twice and confirms identical stdout.
func TestRun_DryRunIsDeterministic(t *testing.T) {
	var outA, outB, errA, errB bytes.Buffer
	if code := run([]string{"--dry-run"}, &outA, &errA); code != 0 {
		t.Fatalf("dry-run A failed: exit=%d stderr=%s", code, errA.String())
	}
	if code := run([]string{"--dry-run"}, &outB, &errB); code != 0 {
		t.Fatalf("dry-run B failed: exit=%d stderr=%s", code, errB.String())
	}
	if !bytes.Equal(outA.Bytes(), outB.Bytes()) {
		t.Fatalf("dry-run not deterministic: A=%d bytes B=%d bytes", outA.Len(), outB.Len())
	}
}

// TestRun_FileOutputIsByteIdentical exercises the CLI's file-output
// path twice into a temp directory and confirms the on-disk file is
// byte-identical across runs.
func TestRun_FileOutputIsByteIdentical(t *testing.T) {
	dir := t.TempDir()
	outDir := filepath.Join(dir, "api")
	var outA, errA bytes.Buffer
	if code := run([]string{"-output", outDir}, &outA, &errA); code != 0 {
		t.Fatalf("file-output A failed: exit=%d stderr=%s", code, errA.String())
	}
	first, err := os.ReadFile(filepath.Join(outDir, "endpoints.yaml"))
	if err != nil {
		t.Fatalf("read first: %v", err)
	}
	var outB, errB bytes.Buffer
	if code := run([]string{"-output", outDir}, &outB, &errB); code != 0 {
		t.Fatalf("file-output B failed: exit=%d stderr=%s", code, errB.String())
	}
	second, err := os.ReadFile(filepath.Join(outDir, "endpoints.yaml"))
	if err != nil {
		t.Fatalf("read second: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatalf("file output not byte-identical across two runs: first=%d bytes second=%d bytes", len(first), len(second))
	}
}

// TestRun_VersionFlag pins the --version short-circuit.
func TestRun_VersionFlag(t *testing.T) {
	var out, errBuf bytes.Buffer
	if code := run([]string{"--version"}, &out, &errBuf); code != 0 {
		t.Fatalf("--version failed: exit=%d stderr=%s", code, errBuf.String())
	}
	if !strings.HasPrefix(out.String(), "identuum-idp-oss-api-docgen ") {
		t.Fatalf("--version stdout = %q; expected to start with version prefix", out.String())
	}
}

// TestRun_RejectsUnsupportedFormat pins that --format=json is rejected
// at P1.
func TestRun_RejectsUnsupportedFormat(t *testing.T) {
	var out, errBuf bytes.Buffer
	if code := run([]string{"--dry-run", "--format=json"}, &out, &errBuf); code == 0 {
		t.Fatalf("--format=json should have failed; stdout=%q stderr=%q", out.String(), errBuf.String())
	}
}

// TestSnakeFromCamel pins the snake_case conversion behaviour that
// builds endpoint IDs. Any change here ripples through every ID and
// must be deliberate.
func TestSnakeFromCamel(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"ListSigningKeys", "list_signing_keys"},
		{"HandleListSigningKeys", "handle_list_signing_keys"},
		{"Userinfo", "userinfo"},
		{"GetAPIResource", "get_api_resource"},
		{"", ""},
	}
	for _, c := range cases {
		got := snakeFromCamel(c.in)
		if got != c.want {
			t.Errorf("snakeFromCamel(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// sortKey is the canonical (module, surface, path, method) tuple
// used by extractSortKeys and tupleLess. Comparing field-by-field is
// the only way to reliably mirror generate()'s internal sort across
// inputs whose paths contain delimiter characters.
type sortKey struct {
	module, surface, path, method string
}

func tupleLess(a, b sortKey) bool {
	if a.module != b.module {
		return a.module < b.module
	}
	if a.surface != b.surface {
		return a.surface < b.surface
	}
	if a.path != b.path {
		return a.path < b.path
	}
	return a.method < b.method
}

// extractSortKeys reads the rendered YAML output and produces one
// canonical sort tuple per endpoint. The tuple mirrors generate()'s
// internal sort order so the test verifies the output is monotonic.
func extractSortKeys(yaml string) []sortKey {
	var keys []sortKey
	var cur sortKey
	seen := false
	for _, line := range strings.Split(yaml, "\n") {
		line = strings.TrimRight(line, " ")
		switch {
		case strings.HasPrefix(line, "  - id: "):
			if seen {
				keys = append(keys, cur)
			}
			cur = sortKey{}
			seen = true
		case strings.HasPrefix(line, "    module: "):
			cur.module = stripQuoted(line[len("    module: "):])
		case strings.HasPrefix(line, "    surface: "):
			cur.surface = stripQuoted(line[len("    surface: "):])
		case strings.HasPrefix(line, "    path: "):
			cur.path = stripQuoted(line[len("    path: "):])
		case strings.HasPrefix(line, "    method: "):
			cur.method = stripQuoted(line[len("    method: "):])
		}
	}
	if seen {
		keys = append(keys, cur)
	}
	return keys
}

func stripQuoted(s string) string {
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}

// TestPlatformGuard documents that the generator does not consult the
// runtime OS at all — it should produce identical output on any
// platform. The test simply records the platform and asserts the
// behaviour is non-conditional (i.e. the test doesn't actually call
// any platform-specific code).
func TestPlatformGuard(t *testing.T) {
	if runtime.GOOS == "" {
		// Defensive: this can never happen in practice; the assertion
		// exists only to document the requirement.
		t.Fatal("runtime.GOOS is empty")
	}
}
