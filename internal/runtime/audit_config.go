package runtime

import (
	"strings"
	"time"

	"github.com/identuum/identuum-idp-oss/internal/postgres"
)

// resolveAuditRetention resolves the OSS audit-log retention window (L-2) from
// IDENTUUM_IDP_AUDIT_RETENTION, following the runtime's env convention
// (time.ParseDuration, same shape as the rate-limit *_WINDOW vars).
//
// Semantics:
//   - unset / blank  → DefaultAuditRetention (30 days).
//   - a value that fails to parse → DefaultAuditRetention (misconfiguration
//     keeps the safe default rather than silently changing behaviour).
//   - a value that parses, INCLUDING zero or negative → used verbatim. A
//     non-positive retention is the DELIBERATE "disable pruning" signal: the
//     audit repo then never deletes, but writes are unaffected. This differs
//     from the rate-limit convention (where non-positive keeps the default)
//     because here "keep everything, prune nothing" is a legitimate operator
//     choice, not misconfiguration.
func resolveAuditRetention(getenv func(string) string) time.Duration {
	if getenv == nil {
		return postgres.DefaultAuditRetention
	}
	raw := strings.TrimSpace(getenv("IDENTUUM_IDP_AUDIT_RETENTION"))
	if raw == "" {
		return postgres.DefaultAuditRetention
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return postgres.DefaultAuditRetention
	}
	return d
}
