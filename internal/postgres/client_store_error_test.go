package postgres

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// C1 (OSS v0.9.12, rule CLIENT-MUTATION-COMMIT-1): a client change that could
// not be saved right now — the lock wait ended, a deadlock, a serialization
// failure, a lost connection, a cancelled or timed-out request — is "store
// unavailable" (503, try again). A value the database refuses (classes 22 and
// 23) is the request's fault and stays a plain error (400). Both keep the
// cause for errors.Is / errors.As.
func TestClientMutation_PgLockErrorsMapToStoreUnavailable(t *testing.T) {
	wrap := func(err error) error { return fmt.Errorf("failed to update client: %w", err) }
	for _, tc := range []struct {
		name  string
		err   error
		store bool
	}{
		{"lock_not_available 55P03", &pgconn.PgError{Code: "55P03"}, true},
		{"deadlock_detected 40P01", &pgconn.PgError{Code: "40P01"}, true},
		{"serialization_failure 40001", &pgconn.PgError{Code: "40001"}, true},
		{"connection_failure 08006", &pgconn.PgError{Code: "08006"}, true},
		{"query_canceled 57014", &pgconn.PgError{Code: "57014"}, true},
		{"context canceled", context.Canceled, true},
		{"context deadline", context.DeadlineExceeded, true},
		{"plain driver error", errors.New("conn closed"), true},
		{"check_violation 23514", &pgconn.PgError{Code: "23514"}, false},
		{"foreign_key_violation 23503", &pgconn.PgError{Code: "23503"}, false},
		{"string_data_right_truncation 22001", &pgconn.PgError{Code: "22001"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := clientStoreError(wrap(tc.err))
			if domain.IsAuthStoreUnavailable(got) != tc.store {
				t.Errorf("store unavailable = %v; want %v", domain.IsAuthStoreUnavailable(got), tc.store)
			}
			if !errors.Is(got, tc.err) {
				t.Error("the cause is lost")
			}
		})
	}
}
