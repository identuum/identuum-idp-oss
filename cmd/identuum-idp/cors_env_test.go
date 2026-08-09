package main

import (
	"reflect"
	"testing"
)

// parseCORSAllowedOrigins turns the operator-supplied
// IDENTUUM_IDP_CORS_ALLOWED_ORIGINS value into the exact-match allowlist.
// Deny-by-default: unset/blank yields nil (no cross-origin access).
func TestParseCORSAllowedOrigins(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want []string
	}{
		{"unset", "", nil},
		{"blank", "   ", nil},
		{"single", "https://a.example.com", []string{"https://a.example.com"}},
		{
			"multiple with spaces",
			" https://a.example.com , https://b.example.com ",
			[]string{"https://a.example.com", "https://b.example.com"},
		},
		{"empty entries dropped", "https://a.example.com,,, ,", []string{"https://a.example.com"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseCORSAllowedOrigins(tc.raw)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("parseCORSAllowedOrigins(%q) = %#v, want %#v", tc.raw, got, tc.want)
			}
		})
	}
}
