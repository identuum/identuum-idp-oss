package repository

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// BackchannelLogoutDeliveryListFilter parameterises List. Empty
// values mean "no filter on that field". Limit defaults to 50 and
// is hard-capped at 200 by the repository.
type BackchannelLogoutDeliveryListFilter struct {
	Status   string // exact match; empty = any status
	ClientID string // exact match; empty = any client
	Limit    int
}

// BackchannelLogoutDeliveryRepository persists delivery rows for
// audit + bounded retry + operator admin.
type BackchannelLogoutDeliveryRepository interface {
	// Insert persists a fresh row.
	Insert(ctx context.Context, d *domain.BackchannelLogoutDelivery) error

	// GetByID returns the row by primary key. (nil, nil) on not
	// found.
	GetByID(ctx context.Context, id uuid.UUID) (*domain.BackchannelLogoutDelivery, error)

	// List returns rows matching the supplied filter, ordered by
	// created_at DESC.
	List(ctx context.Context, filter BackchannelLogoutDeliveryListFilter) ([]*domain.BackchannelLogoutDelivery, error)

	// ListDueForRetry returns pending rows whose `next_attempt_at`
	// is <= now, ordered by next_attempt_at ASC. Used by the
	// due-delivery processor on the cleanup tick.
	ListDueForRetry(ctx context.Context, now time.Time, limit int) ([]*domain.BackchannelLogoutDelivery, error)

	// MarkDelivered flips the row's status to delivered and
	// stamps delivered_at + http_status.
	MarkDelivered(ctx context.Context, id uuid.UUID, httpStatus int, at time.Time) error

	// MarkAttemptFailed records a non-fatal attempt failure +
	// schedules `next_attempt_at`. Increments attempt_count. The
	// row stays in `pending` status unless the caller bumps it
	// to `failed` after exhausting retries.
	MarkAttemptFailed(ctx context.Context, id uuid.UUID, attempt int, httpStatus int, errMessage string, nextAttempt time.Time, at time.Time) error

	// MarkPermanentlyFailed flips the row to `failed`.
	MarkPermanentlyFailed(ctx context.Context, id uuid.UUID, httpStatus int, errMessage string, at time.Time) error

	// DeleteOlderThan prunes rows older than cutoff. Returns the
	// number of rows pruned.
	DeleteOlderThan(ctx context.Context, cutoff time.Time) (int64, error)
}
