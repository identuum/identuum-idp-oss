package postgres

import (
	"context"
	"strings"
	"testing"
)

// TestRunMigrations_NilDB verifies the helper returns an explicit error
// when called with a nil *sql.DB instead of panicking inside goose.
func TestRunMigrations_NilDB(t *testing.T) {
	results, err := RunMigrations(context.Background(), nil)
	if err == nil {
		t.Fatal("RunMigrations(nil) returned nil error; expected explicit nil-DB error")
	}
	if results != nil {
		t.Errorf("RunMigrations(nil) returned non-nil results: %v", results)
	}
	if !strings.Contains(err.Error(), "nil *sql.DB") {
		t.Errorf("error message did not mention nil DB: %q", err.Error())
	}
}
