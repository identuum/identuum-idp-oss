// logger.go — stdout-backed implementation of service.CleanupLogger
// used by the OSS runtime cleanup goroutine.

package runtime

import (
	"fmt"
	"io"
)

// stdoutCleanupLogger satisfies service.CleanupLogger by writing
// terse, structured-but-plain-text emissions to the supplied
// stdout writer. It deliberately does NOT echo any kv value that
// is not int / int64 — the cleanup driver only passes a count, so
// anything else would be a contract violation.
type stdoutCleanupLogger struct {
	w io.Writer
}

func (l *stdoutCleanupLogger) Info(msg string, kv ...any) {
	count := extractIntKV(kv, "count")
	if count > 0 {
		fmt.Fprintf(l.w, "identuum-idp: %s count=%d\n", msg, count)
		return
	}
	fmt.Fprintf(l.w, "identuum-idp: %s\n", msg)
}

func (l *stdoutCleanupLogger) Warn(msg string, _ ...any) {
	fmt.Fprintf(l.w, "identuum-idp: WARN %s\n", msg)
}

func extractIntKV(kv []any, key string) int64 {
	for i := 0; i+1 < len(kv); i += 2 {
		k, _ := kv[i].(string)
		if k != key {
			continue
		}
		switch v := kv[i+1].(type) {
		case int:
			return int64(v)
		case int64:
			return v
		}
	}
	return 0
}
