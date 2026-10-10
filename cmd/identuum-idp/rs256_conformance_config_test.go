package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestConformanceRS256OptionAndFloor(t *testing.T) {
	compose, err := os.ReadFile("../../conformance/compose.appliance.yml")
	if err != nil {
		t.Fatal("conformance appliance config unavailable")
	}
	if !strings.Contains(string(compose), `IDENTUUM_IDP_ADVERTISE_RS256: "true"`) {
		t.Fatal("conformance appliance must explicitly enable RS256 advertisement")
	}
	raw, err := os.ReadFile("../../conformance/expected-failures-config.json")
	if err != nil {
		t.Fatal("conformance expected-failure config unavailable")
	}
	var rows []json.RawMessage
	if err := json.Unmarshal(raw, &rows); err != nil || len(rows) != 0 {
		t.Fatal("config conformance must allow no expected failures with RS256 enabled")
	}
	var help strings.Builder
	printUsage(&help)
	if !strings.Contains(help.String(), "IDENTUUM_IDP_ADVERTISE_RS256") || !strings.Contains(help.String(), "default false") {
		t.Fatal("help must list the RS256 option and default")
	}
}
