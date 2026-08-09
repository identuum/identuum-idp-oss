package main

// id_helpers.go owns the deterministic Endpoint.ID derivation
// helpers used by the annotation-driven extractor (extract.go).
// These helpers were lifted out of the now-retired registry.go
// fixture so the extractor can keep producing exactly the IDs
// the docs site already references.
//
// The functions in this file are intentionally side-effect free
// and deterministic: two invocations with identical inputs
// produce identical outputs. Any change to the rules here is a
// breaking change for the docs catalog and MUST regenerate
// `tools/api-docgen/testdata/endpoints.golden.yaml`.

// buildID composes the stable identifier from surface + handler.
// Handler is converted to snake_case (HandleListSigningKeys →
// list_signing_keys); the leading "Handle" prefix is stripped if
// present.
func buildID(surface, handler string) string {
	return moduleName + "." + surface + "." + snakeFromCamel(stripHandlePrefix(handler))
}

// buildIDFromPath is used for endpoints whose handler symbol is a
// generic wrapper (e.g. "userDeferred") that does not uniquely
// identify the route. The fallback is surface + method + the
// trailing non-parameter path segment in snake_case so the ID
// remains stable and human-readable.
func buildIDFromPath(surface, method, path string) string {
	tail := lastNonParamSegment(path)
	return moduleName + "." + surface + "." + sanitizeIDSeg(method) + "_" + sanitizeIDSeg(tail)
}

// stripHandlePrefix removes a leading "Handle" prefix from a Go
// symbol name when present.
func stripHandlePrefix(s string) string {
	const p = "Handle"
	if len(s) > len(p) && s[:len(p)] == p {
		return s[len(p):]
	}
	return s
}

// snakeFromCamel converts a CamelCase Go identifier into
// snake_case. Multi-letter acronyms (e.g. "API") collapse to a
// single segment ("api").
func snakeFromCamel(s string) string {
	if s == "" {
		return ""
	}
	var out []byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		isUpper := c >= 'A' && c <= 'Z'
		prevUpper := i > 0 && s[i-1] >= 'A' && s[i-1] <= 'Z'
		nextLower := i+1 < len(s) && s[i+1] >= 'a' && s[i+1] <= 'z'
		if isUpper && i > 0 && (!prevUpper || nextLower) {
			out = append(out, '_')
		}
		if isUpper {
			out = append(out, c+('a'-'A'))
		} else {
			out = append(out, c)
		}
	}
	return string(out)
}

// lastNonParamSegment returns the last path segment that is NOT
// a gin parameter (":name"). For "/api/v1/users/:id/recovery/
// reset-mfa" it returns "reset-mfa".
func lastNonParamSegment(path string) string {
	last := ""
	cur := ""
	for i := 0; i < len(path); i++ {
		if path[i] == '/' {
			if cur != "" && cur[0] != ':' {
				last = cur
			}
			cur = ""
			continue
		}
		cur += string(path[i])
	}
	if cur != "" && cur[0] != ':' {
		last = cur
	}
	if last == "" {
		return "root"
	}
	return last
}

// sanitizeIDSeg lowercases and replaces non-alphanumeric runes
// with underscores so the result is safe to embed in an ID.
func sanitizeIDSeg(s string) string {
	var out []byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z':
			out = append(out, c+('a'-'A'))
		case (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'):
			out = append(out, c)
		default:
			out = append(out, '_')
		}
	}
	return string(out)
}
