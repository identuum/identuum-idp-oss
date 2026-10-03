package main

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

// OSS-NOTICES-TIDY: the binary carries its third-party notices and prints
// them, byte for byte the THIRD_PARTY_NOTICES file at the repository root.
func TestRun_LicensesPrintsTheEmbeddedNotices(t *testing.T) {
	want, err := os.ReadFile("../../THIRD_PARTY_NOTICES")
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"licenses"}, &stdout, &stderr); code != 0 {
		t.Fatalf("licenses exit = %d, stderr %q", code, stderr.String())
	}
	if stdout.String() != string(want) {
		t.Fatalf("licenses printed %d bytes that are not THIRD_PARTY_NOTICES (%d bytes)", stdout.Len(), len(want))
	}
	if !strings.HasPrefix(stdout.String(), "THIRD-PARTY NOTICES — identuum-idp-oss\n") || !strings.Contains(stdout.String(), "\ngo github.com/jackc/pgx/v5 ") {
		t.Fatal("the printed notices lack their header or a module the binary is built from")
	}

	var help bytes.Buffer
	run([]string{"help"}, &help, &stderr)
	if !strings.Contains(help.String(), "  licenses ") {
		t.Fatalf("help does not list the licenses subcommand: %q", help.String())
	}
}
