// Package uuidgen provides safe, retrying UUID v7 generation.
// All UUIDs in this service MUST be v7 (time-ordered). This package
// enforces that constraint with explicit retry logic and hard-failure
// semantics — never panicking the process.
package uuidgen

import (
	"fmt"
	"time"

	"github.com/google/uuid"
)

const maxRetries = 3

// newV7Func is the function used to generate a UUID v7.
// It is a package-level variable so tests can replace it with a stub
// that always fails, exercising the retry-exhaustion branch.
var newV7Func = uuid.NewV7

// NewV7 attempts to generate a UUID v7 up to maxRetries times,
// sleeping 1ms between attempts. Returns an error if all attempts fail.
// This preserves the strict v7 invariant required for time-ordered persistence.
func NewV7() (uuid.UUID, error) {
	var lastErr error
	for i := range maxRetries {
		id, err := newV7Func()
		if err == nil {
			return id, nil
		}
		lastErr = err
		if i < maxRetries-1 {
			time.Sleep(time.Millisecond)
		}
	}
	return uuid.Nil, fmt.Errorf("uuid v7 generation failed after %d attempts: %w", maxRetries, lastErr)
}

// NewV7String is a convenience wrapper that returns the UUID as a string.
func NewV7String() (string, error) {
	id, err := NewV7()
	if err != nil {
		return "", err
	}
	return id.String(), nil
}
