package main

import (
	"bytes"
	"testing"
)

// TestExtractorDryRunIsByteIdentical pins that running `--dry-run`
// twice produces byte-identical stdout. This is the strongest
// deterministic invariant for the extractor — any non-determinism
// in source-walking, map iteration, or sorting would fail here.
func TestExtractorDryRunIsByteIdentical(t *testing.T) {
	var aOut, bOut, errBuf bytes.Buffer
	if code := run([]string{"--dry-run"}, &aOut, &errBuf); code != 0 {
		t.Fatalf("first dry-run failed: exit=%d stderr=%s", code, errBuf.String())
	}
	errBuf.Reset()
	if code := run([]string{"--dry-run"}, &bOut, &errBuf); code != 0 {
		t.Fatalf("second dry-run failed: exit=%d stderr=%s", code, errBuf.String())
	}
	if !bytes.Equal(aOut.Bytes(), bOut.Bytes()) {
		t.Fatalf("extractor dry-run not deterministic: first=%d bytes second=%d bytes", aOut.Len(), bOut.Len())
	}
}

// TestExtractorRejectsUnsupportedFormat confirms the --format
// validation still runs in the extractor-driven CLI.
func TestExtractorRejectsUnsupportedFormat(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"--dry-run", "--format=json"}, &stdout, &stderr); code == 0 {
		t.Fatalf("--format=json should have failed; stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}
