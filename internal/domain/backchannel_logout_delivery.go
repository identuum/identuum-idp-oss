package domain

import (
	"time"

	"github.com/google/uuid"
)

// BackchannelLogoutDeliveryStatus enumerates the lifecycle states
// of a `backchannel_logout_deliveries` row.
type BackchannelLogoutDeliveryStatus string

const (
	BackchannelLogoutDeliveryPending   BackchannelLogoutDeliveryStatus = "pending"
	BackchannelLogoutDeliveryDelivered BackchannelLogoutDeliveryStatus = "delivered"
	BackchannelLogoutDeliveryFailed    BackchannelLogoutDeliveryStatus = "failed"
)

// BackchannelLogoutDelivery is one row in the
// `backchannel_logout_deliveries` table. Raw logout_token bytes are
// NEVER written here — only the jti (random JWT ID, safe per
// RFC 7519 §4.1.7).
type BackchannelLogoutDelivery struct {
	ID            uuid.UUID
	ClientID      string
	SessionID     *uuid.UUID
	UserID        *uuid.UUID
	LogoutJTI     string
	Status        BackchannelLogoutDeliveryStatus
	HTTPStatus    *int
	AttemptCount  int
	LastError     string
	NextAttemptAt *time.Time
	DeliveredAt   *time.Time
	CreatedAt     time.Time
	UpdatedAt     time.Time
}
