// Package migrations bundles the OSS PostgreSQL migration history as an
// embed.FS so the OSS bootstrap path can pass it to goose without any
// dependency on the monolith repository. The OSS history is a clean,
// fresh consolidation — see docs/open-core/PHASE1_IDP_SEAMS.md for the
// derivation from the monolith migration set.
package migrations

import (
	"embed"
	"io/fs"
	"strconv"
	"strings"
)

//go:embed *.sql
var EmbedFS embed.FS

// Current returns the highest migration version number embedded in the
// binary, zero-padded to four digits to match the filename convention
// (e.g. "0005"). Returns "0000" if no migrations are embedded (which
// should never happen — the migrations_test.go lint guarantees at least
// one).
func Current() string {
	entries, err := fs.ReadDir(EmbedFS, ".")
	if err != nil {
		return "0000"
	}

	highest := 0
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		name := entry.Name()
		underscoreIdx := strings.Index(name, "_")
		if underscoreIdx < 0 {
			continue
		}
		v, err := strconv.Atoi(name[:underscoreIdx])
		if err != nil || v <= 0 {
			continue
		}
		if v > highest {
			highest = v
		}
	}

	return padVersion(highest)
}

func padVersion(v int) string {
	s := strconv.Itoa(v)
	for len(s) < 4 {
		s = "0" + s
	}
	return s
}
