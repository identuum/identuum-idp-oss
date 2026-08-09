package main

import (
	"sort"
	"strings"
	"testing"
)

// scanDocgenAnnotations is the test-side convenience that uses the
// same scanner the production extractor (extract.go) uses, anchored
// at the OSS module root's default source roots.
//
// Kept as a thin wrapper so the existing test bodies can call it
// without an arguments list and continue to read the same docgen
// blocks the production binary consumes.
func scanDocgenAnnotations() ([]annotationBlock, error) {
	roots, err := defaultSourceRoots()
	if err != nil {
		return nil, err
	}
	return scanDocgenAnnotationsAt(roots)
}

// docgenAllowedKeys enumerates every `docgen:` key the annotation
// format accepts. New keys MUST be added here AND to the format spec
// in identuum-idp/docs/open-core/IDP_API_DOCGEN_P2_OSS_SOURCE_ANNOTATIONS.md.
var docgenAllowedKeys = map[string]bool{
	"endpoint":     true, // anchor (no value)
	"surface":      true,
	"method":       true,
	"path":         true,
	"summary":      true,
	"tier":         true,
	"auth":         true,
	"request":      true,
	"response":     true,
	"errors":       true,
	"deferred":     true,
	"feature_gate": true,
	"notes":        true,
	"status":       true, // terminal-success HTTP status (3 digits); absent => 200
}

// docgenRequiredKeys is the set of keys every `docgen:endpoint`
// block must declare.
var docgenRequiredKeys = []string{"surface", "method", "path", "summary", "tier", "auth"}

// docgenAllowedAuths enumerates the values the `auth` key may carry.
//
// The `authenticated` value (added in B3) represents "any authenticated
// principal — middleware accepts either a session cookie OR a bearer
// JWT, with no role check beyond the presence of a principal" and is
// the right value when the route middleware is `mw.RequireAuthenticated`
// or `mw.RequireSiteAdminOrPrincipalOrg` (which short-circuits when
// either the principal is site_admin OR carries an organization id).
//
// Pipe-separated alternatives (added in B3, e.g. `site_admin|org_admin`)
// represent "the middleware accepts EITHER role". Each pipe-separated
// component must be one of the values in this map.
var docgenAllowedAuths = map[string]bool{
	"public":        true,
	"session":       true,
	"bearer":        true,
	"oauth_client":  true,
	"site_admin":    true,
	"org_admin":     true,
	"authenticated": true,
	"unknown":       true,
}

// isAllowedAuthValue accepts either a single value from docgenAllowedAuths
// or a pipe-separated list of single values (e.g. "site_admin|org_admin"),
// returning true iff every component is in the allow-list. The order of
// components is not normalised by this checker — the docs site can
// canonicalise on render if it wants alphabetical alternatives.
func isAllowedAuthValue(v string) bool {
	if v == "" {
		return false
	}
	for _, part := range strings.Split(v, "|") {
		part = strings.TrimSpace(part)
		if !docgenAllowedAuths[part] {
			return false
		}
	}
	return true
}

// docgenAllowedMethods enumerates the values the `method` key may
// carry. HTTP methods are recorded in upper-case form.
var docgenAllowedMethods = map[string]bool{
	"GET":    true,
	"POST":   true,
	"PUT":    true,
	"DELETE": true,
	"PATCH":  true,
}

// TestDocgenAnnotationsAreWellFormed walks the OSS source roots and
// validates every `// docgen:endpoint` anchor produces a well-formed
// block:
//   - each subsequent `// docgen:KEY=VALUE` line uses a key from the
//     allow-list (docgenAllowedKeys),
//   - the block contains every required key (docgenRequiredKeys),
//   - method ∈ {GET, POST, PUT, DELETE, PATCH},
//   - tier == "oss" || tier == "unknown" || tier starts with "oss-feature-gated:",
//   - auth ∈ docgenAllowedAuths,
//   - deferred ∈ {true, false} when present,
//   - no duplicate (method, path) pairs across the whole repository.
//
// The test does NOT run gograph; it does NOT depend on any external
// service. It is safe to run inside `go test ./...`.
func TestDocgenAnnotationsAreWellFormed(t *testing.T) {
	blocks, err := scanDocgenAnnotations()
	if err != nil {
		t.Fatalf("scan docgen annotations: %v", err)
	}
	if len(blocks) == 0 {
		t.Fatal("scan returned zero docgen:endpoint blocks; the annotation slice should produce at least one")
	}

	pairs := make(map[string]annotationBlock, len(blocks))
	for _, b := range blocks {
		// Required keys present?
		for _, k := range docgenRequiredKeys {
			if _, ok := b.values[k]; !ok {
				t.Errorf("%s:%d-%d: missing required docgen key %q (block: %+v)",
					b.file, b.startLine, b.endLine, k, b.values)
			}
		}

		// All keys in the allow-list?
		for k := range b.values {
			if !docgenAllowedKeys[k] {
				t.Errorf("%s:%d-%d: unknown docgen key %q (allow-list: %v)",
					b.file, b.startLine, b.endLine, k, sortedKeys(docgenAllowedKeys))
			}
		}

		// method
		method := b.values["method"]
		if method != "" && !docgenAllowedMethods[method] {
			t.Errorf("%s:%d-%d: invalid docgen:method %q (allowed: %v)",
				b.file, b.startLine, b.endLine, method, sortedKeys(docgenAllowedMethods))
		}

		// auth — single value from the allow-list OR a pipe-separated
		// composition of allow-list values (e.g. "site_admin|org_admin").
		auth := b.values["auth"]
		if auth != "" && !isAllowedAuthValue(auth) {
			t.Errorf("%s:%d-%d: invalid docgen:auth %q (allowed values: %v; pipe-separated composition also allowed)",
				b.file, b.startLine, b.endLine, auth, sortedKeys(docgenAllowedAuths))
		}

		// tier
		tier := b.values["tier"]
		switch {
		case tier == "oss":
		case tier == "unknown":
		case strings.HasPrefix(tier, "oss-feature-gated:") && len(tier) > len("oss-feature-gated:"):
		default:
			t.Errorf("%s:%d-%d: invalid docgen:tier %q (allowed: \"oss\", \"unknown\", or \"oss-feature-gated:<feature>\")",
				b.file, b.startLine, b.endLine, tier)
		}

		// deferred
		if d, ok := b.values["deferred"]; ok && d != "true" && d != "false" {
			t.Errorf("%s:%d-%d: invalid docgen:deferred %q (allowed: true, false)",
				b.file, b.startLine, b.endLine, d)
		}

		// status — when present and non-empty, must be a 3-digit HTTP
		// status code. Empty (a bare `// docgen:status`) is allowed and
		// is treated as the default 200 by the extractor. This catches a
		// garbled/typo'd annotation (e.g. "20", "2xx") before it reaches
		// the public spec.
		if s, ok := b.values["status"]; ok && s != "" && !isThreeDigitStatus(s) {
			t.Errorf("%s:%d-%d: invalid docgen:status %q (must be a 3-digit HTTP status code, e.g. 201, 204)",
				b.file, b.startLine, b.endLine, s)
		}

		// (method, path) uniqueness
		path := b.values["path"]
		if method != "" && path != "" {
			key := method + " " + path
			if prev, dup := pairs[key]; dup {
				t.Errorf("%s:%d-%d: duplicate docgen endpoint (%s) — first defined at %s:%d-%d",
					b.file, b.startLine, b.endLine, key, prev.file, prev.startLine, prev.endLine)
			}
			pairs[key] = b
		}
	}
}

// TestDocgenAnnotationsHaveNoSecrets pins that no docgen comment
// contains a value that looks like a secret. The annotation format is
// human-written, so this guard catches accidental future additions
// (raw JWTs, PEM blocks, credentialed DB URLs).
func TestDocgenAnnotationsHaveNoSecrets(t *testing.T) {
	blocks, err := scanDocgenAnnotations()
	if err != nil {
		t.Fatalf("scan docgen annotations: %v", err)
	}
	forbidden := []string{
		"-----BEGIN ",
		"eyJ", // JWT prefix; will produce false positives only on intentionally-evil annotations
		"postgres://",
		"mysql://",
		"sk-live_",
		"ghp_",
		"gho_",
	}
	for _, b := range blocks {
		for k, v := range b.values {
			for _, needle := range forbidden {
				if strings.Contains(v, needle) {
					t.Errorf("%s:%d-%d: docgen:%s contains forbidden substring %q (value=%q)",
						b.file, b.startLine, b.endLine, k, needle, v)
				}
			}
		}
	}
}

// TestDocgenAnnotationsHaveNoLocalPaths pins that no docgen comment
// embeds a personal filesystem path. The `path` key is exempted from
// the check because legitimate API paths can collide with personal
// path fragments — e.g. SCIM v2's `/api/v1/scim/v2/Users/:id` matches
// the `/Users/` macOS home prefix even though it carries no
// filesystem material. The exemption is narrow: only the `path`
// value is skipped, and only when it starts with `/api/`.
func TestDocgenAnnotationsHaveNoLocalPaths(t *testing.T) {
	blocks, err := scanDocgenAnnotations()
	if err != nil {
		t.Fatalf("scan docgen annotations: %v", err)
	}
	for _, b := range blocks {
		for k, v := range b.values {
			if k == "path" && strings.HasPrefix(v, "/api/") {
				// Exempt: an API mount path is allowed to share a
				// substring with a personal path prefix.
				continue
			}
			for _, needle := range []string{"/Users/", "/home/", `C:\`, "C:/"} {
				if strings.Contains(v, needle) {
					t.Errorf("%s:%d-%d: docgen:%s contains personal path fragment %q (value=%q)",
						b.file, b.startLine, b.endLine, k, needle, v)
				}
			}
		}
	}
}

// isThreeDigitStatus reports whether s is exactly three ASCII digits
// with a leading digit in 1–5 (the HTTP status-code range). Used by
// the well-formed check to reject a typo'd docgen:status value.
func isThreeDigitStatus(s string) bool {
	if len(s) != 3 {
		return false
	}
	if s[0] < '1' || s[0] > '5' {
		return false
	}
	return s[1] >= '0' && s[1] <= '9' && s[2] >= '0' && s[2] <= '9'
}

// sortedKeys returns the keys of m as a stable sorted slice. Used for
// deterministic error messages.
func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
