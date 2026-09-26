package main

// e2e_record_tiers_test.go — the -e2e-record mode (the wiki's witness-ui-e2e
// judge) takes the same tiers as the mint decision (GATE-TIERS, 2026-09-26):
// a stale e2e-full record stands for a none-tier change, stands for a
// quick-tier change only beside a green e2e-quick record at these heads, and
// never for a full-tier change.

import (
	"os"
	"strings"
	"testing"
)

func TestE2ERecordMode_TakesTheSameTiers(t *testing.T) {
	const compose = "# header\n#   curl -fsSLO https://example.test/old.yml\nservices:\n  idp:\n    image: ghcr.io/x/y:v1@sha256:aaa\n"
	base := []tierCommit{{"oss", "deployment/docker-compose.yml", compose}}
	for _, tc := range []struct {
		name   string
		change []tierCommit
		quick  bool
		want   int
	}{
		{"comment-only compose → accepted", []tierCommit{{"oss", "deployment/docker-compose.yml", strings.Replace(compose, "old.yml", "new.yml", 1)}}, false, ExitSkippable},
		{"ui component with a green quick record → accepted", []tierCommit{{"ui", "src/components/x.tsx", "export {}\n"}}, true, ExitSkippable},
		{"ui component without a quick record → refused", []tierCommit{{"ui", "src/components/x.tsx", "export {}\n"}}, false, ExitRequired},
		{"claim service with a quick record → refused", []tierCommit{{"oss", "internal/service/claim_service.go", "package service\n"}}, true, ExitRequired},
	} {
		t.Run(tc.name, func(t *testing.T) {
			record, oss, ui := tierFixture(t, base, tc.change, tc.quick)
			// judgeE2ERecord prints to stdout; silence it, the exit code is the verdict.
			stdout := os.Stdout
			devnull, err := os.Open(os.DevNull)
			if err != nil {
				t.Fatal(err)
			}
			os.Stdout = devnull
			got := judgeE2ERecord(record, oss, ui)
			os.Stdout = stdout
			devnull.Close()
			if got != tc.want {
				t.Fatalf("exit %d, want %d", got, tc.want)
			}
		})
	}
}
