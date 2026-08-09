package postgres

import (
	"context"
	"testing"
	"time"
)

// TestNewPool_EmptyURL verifies the helper rejects an empty database URL
// rather than passing it to pgxpool.ParseConfig which would surface a
// less obvious error.
func TestNewPool_EmptyURL(t *testing.T) {
	pool, err := NewPool(context.Background(), "", nil)
	if err == nil {
		if pool != nil {
			pool.Close()
		}
		t.Fatal("NewPool(\"\") returned nil error; expected explicit empty-URL error")
	}
	if pool != nil {
		t.Errorf("NewPool returned non-nil pool on error: %v", pool)
	}
}

// TestNewPool_InvalidURL verifies the helper surfaces a parse error
// (not a panic) when the URL is malformed. The exact error message is
// pgxpool's; we only assert non-nil to avoid coupling to its wording.
func TestNewPool_InvalidURL(t *testing.T) {
	pool, err := NewPool(context.Background(), "::not-a-url::", nil)
	if err == nil {
		if pool != nil {
			pool.Close()
		}
		t.Fatal("NewPool(invalid URL) returned nil error; expected parse error")
	}
	if pool != nil {
		t.Errorf("NewPool returned non-nil pool on error: %v", pool)
	}
}

// TestNewPool_ErrorMessageOmitsURL guards against credential leakage in
// error strings. The URL contains a sentinel that must NOT appear in
// the returned error message.
func TestNewPool_ErrorMessageOmitsURL(t *testing.T) {
	const sentinel = "SECRETSENTINEL"
	const badURL = "postgres://user:" + sentinel + "@host:5432/db?invalid="

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	_, err := NewPool(ctx, badURL, nil)
	if err == nil {
		t.Fatal("NewPool with unreachable host returned nil error")
	}
	msg := err.Error()
	if containsSentinel(msg, sentinel) {
		t.Errorf("NewPool error message leaks URL sentinel: %s", msg)
	}
}

func containsSentinel(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
