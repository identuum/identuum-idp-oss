package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/repository"
)

type PgxBackchannelLogoutDeliveryRepository struct {
	db DBTX
}

func NewPgxBackchannelLogoutDeliveryRepository(db DBTX) *PgxBackchannelLogoutDeliveryRepository {
	return &PgxBackchannelLogoutDeliveryRepository{db: db}
}

var _ repository.BackchannelLogoutDeliveryRepository = (*PgxBackchannelLogoutDeliveryRepository)(nil)

func (r *PgxBackchannelLogoutDeliveryRepository) Insert(ctx context.Context, d *domain.BackchannelLogoutDelivery) error {
	if d == nil {
		return errors.New("postgres: nil BackchannelLogoutDelivery")
	}
	if d.ID == uuid.Nil {
		return errors.New("postgres: delivery.ID required")
	}
	const q = `
INSERT INTO backchannel_logout_deliveries (
    id, client_id, session_id, user_id, logout_jti, status,
    http_status, attempt_count, last_error, next_attempt_at,
    delivered_at, created_at, updated_at
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,NOW(),NOW())
`
	_, err := r.db.Exec(ctx, q,
		d.ID, d.ClientID, d.SessionID, d.UserID, d.LogoutJTI, string(d.Status),
		d.HTTPStatus, d.AttemptCount, d.LastError, d.NextAttemptAt,
		d.DeliveredAt,
	)
	return err
}

func (r *PgxBackchannelLogoutDeliveryRepository) MarkDelivered(ctx context.Context, id uuid.UUID, httpStatus int, at time.Time) error {
	const q = `
UPDATE backchannel_logout_deliveries
SET status = 'delivered',
    http_status = $2,
    delivered_at = $3,
    next_attempt_at = NULL,
    updated_at = NOW()
WHERE id = $1
`
	_, err := r.db.Exec(ctx, q, id, httpStatus, at)
	return err
}

func (r *PgxBackchannelLogoutDeliveryRepository) MarkAttemptFailed(ctx context.Context, id uuid.UUID, attempt int, httpStatus int, errMessage string, nextAttempt time.Time, at time.Time) error {
	const q = `
UPDATE backchannel_logout_deliveries
SET attempt_count = $2,
    http_status = $3,
    last_error = $4,
    next_attempt_at = $5,
    updated_at = $6
WHERE id = $1
`
	_, err := r.db.Exec(ctx, q, id, attempt, httpStatus, errMessage, nextAttempt, at)
	return err
}

func (r *PgxBackchannelLogoutDeliveryRepository) MarkPermanentlyFailed(ctx context.Context, id uuid.UUID, httpStatus int, errMessage string, at time.Time) error {
	const q = `
UPDATE backchannel_logout_deliveries
SET status = 'failed',
    http_status = $2,
    last_error = $3,
    next_attempt_at = NULL,
    updated_at = $4
WHERE id = $1
`
	_, err := r.db.Exec(ctx, q, id, httpStatus, errMessage, at)
	return err
}

func (r *PgxBackchannelLogoutDeliveryRepository) GetByID(ctx context.Context, id uuid.UUID) (*domain.BackchannelLogoutDelivery, error) {
	const q = `
SELECT id, client_id, session_id, user_id, logout_jti, status,
       http_status, attempt_count, last_error, next_attempt_at,
       delivered_at, created_at, updated_at
FROM backchannel_logout_deliveries
WHERE id = $1
`
	row := r.db.QueryRow(ctx, q, id)
	out, err := scanBackchannelDelivery(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return out, err
}

func (r *PgxBackchannelLogoutDeliveryRepository) List(ctx context.Context, filter repository.BackchannelLogoutDeliveryListFilter) ([]*domain.BackchannelLogoutDelivery, error) {
	limit := filter.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	q := `
SELECT id, client_id, session_id, user_id, logout_jti, status,
       http_status, attempt_count, last_error, next_attempt_at,
       delivered_at, created_at, updated_at
FROM backchannel_logout_deliveries
WHERE 1=1
`
	args := []any{}
	if filter.Status != "" {
		q += " AND status = $1"
		args = append(args, filter.Status)
	}
	if filter.ClientID != "" {
		q += " AND client_id = $" + itoa(len(args)+1)
		args = append(args, filter.ClientID)
	}
	q += " ORDER BY created_at DESC LIMIT $" + itoa(len(args)+1)
	args = append(args, limit)

	rows, err := r.db.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*domain.BackchannelLogoutDelivery
	for rows.Next() {
		d, scanErr := scanBackchannelDelivery(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (r *PgxBackchannelLogoutDeliveryRepository) ListDueForRetry(ctx context.Context, now time.Time, limit int) ([]*domain.BackchannelLogoutDelivery, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	const q = `
SELECT id, client_id, session_id, user_id, logout_jti, status,
       http_status, attempt_count, last_error, next_attempt_at,
       delivered_at, created_at, updated_at
FROM backchannel_logout_deliveries
WHERE status = 'pending' AND next_attempt_at IS NOT NULL AND next_attempt_at <= $1
ORDER BY next_attempt_at ASC
LIMIT $2
`
	rows, err := r.db.Query(ctx, q, now, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*domain.BackchannelLogoutDelivery
	for rows.Next() {
		d, scanErr := scanBackchannelDelivery(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// scanBackchannelDelivery scans a single row.
func scanBackchannelDelivery(row interface {
	Scan(dest ...any) error
}) (*domain.BackchannelLogoutDelivery, error) {
	var d domain.BackchannelLogoutDelivery
	var statusStr string
	if err := row.Scan(
		&d.ID, &d.ClientID, &d.SessionID, &d.UserID, &d.LogoutJTI, &statusStr,
		&d.HTTPStatus, &d.AttemptCount, &d.LastError, &d.NextAttemptAt,
		&d.DeliveredAt, &d.CreatedAt, &d.UpdatedAt,
	); err != nil {
		return nil, err
	}
	d.Status = domain.BackchannelLogoutDeliveryStatus(statusStr)
	return &d, nil
}

// itoa is a tiny inline helper to keep this file free of strconv
// imports in the query-building loop.
func itoa(n int) string {
	if n < 10 {
		return string(rune('0' + n))
	}
	// Slow path — should rarely hit because we cap LIMIT at 200
	// and arg counts at <10. Falls through to a fmt.Sprintf-style
	// build.
	const digits = "0123456789"
	buf := make([]byte, 0, 4)
	for n > 0 {
		buf = append([]byte{digits[n%10]}, buf...)
		n /= 10
	}
	return string(buf)
}

func (r *PgxBackchannelLogoutDeliveryRepository) DeleteOlderThan(ctx context.Context, cutoff time.Time) (int64, error) {
	const q = `DELETE FROM backchannel_logout_deliveries WHERE created_at < $1`
	cmd, err := r.db.Exec(ctx, q, cutoff)
	if err != nil {
		return 0, err
	}
	return cmd.RowsAffected(), nil
}
