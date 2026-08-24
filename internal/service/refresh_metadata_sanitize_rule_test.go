package service

import "testing"

// TestSanitizeRefreshMetadata_AllowlistAndCRLF pins the refresh-token metadata
// sanitizer that runs at token issue: only the allowlisted keys (client_id,
// client_kind, reason, grant_type) survive, any string value bearing a CR or LF
// is dropped before it can reach a persisted refresh token, and a map that
// empties out (or starts empty) collapses to nil rather than an empty map.
// RULE: REFRESH-METADATA-SANITIZE-1
func TestSanitizeRefreshMetadata_AllowlistAndCRLF(t *testing.T) {
	// Allowlisted keys with clean values are kept verbatim; a non-allowlisted
	// key is dropped.
	got := sanitizeRefreshMetadata(map[string]any{
		"client_id":  "abc",
		"grant_type": "refresh_token",
		"secret":     "should-be-dropped", // not on the allowlist
	})
	if got["client_id"] != "abc" || got["grant_type"] != "refresh_token" {
		t.Fatalf("allowlisted clean keys must survive, got %+v", got)
	}
	if _, ok := got["secret"]; ok {
		t.Errorf("a non-allowlisted key must be dropped, got %+v", got)
	}

	// A CR/LF-bearing string value on an allowlisted key is dropped (header/log
	// injection defense); with only that key present the result collapses to nil.
	if r := sanitizeRefreshMetadata(map[string]any{"reason": "ok\r\ninjected"}); r != nil {
		t.Errorf("a CR/LF-bearing value must be dropped, got %+v", r)
	}

	// An empty input yields nil, not an empty map.
	if r := sanitizeRefreshMetadata(map[string]any{}); r != nil {
		t.Errorf("empty input must yield nil, got %+v", r)
	}
	// A map of only non-allowlisted keys collapses to nil.
	if r := sanitizeRefreshMetadata(map[string]any{"x": "y"}); r != nil {
		t.Errorf("an all-dropped input must yield nil, got %+v", r)
	}
}
