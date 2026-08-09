package types

import (
	"time"

	"github.com/google/uuid"
)

// Anomaly represents a detected security threat or irregularity
type Anomaly struct {
	CreatedAt       time.Time      `json:"created_at" db:"created_at"`
	Metadata        map[string]any `json:"metadata" db:"metadata"`
	DetectionMethod string         `json:"detection_method" db:"detection_method"`
	Score           float64        `json:"score" db:"score"`
	ID              uuid.UUID      `json:"id" db:"id"`
	AuditEventID    uuid.UUID      `json:"audit_event_id" db:"audit_event_id"`
	OrganizationID  uuid.UUID      `json:"organization_id" db:"organization_id"`
}

// AnomalyFilter defines criteria for listing anomalies
type AnomalyFilter struct {
	OrganizationID *uuid.UUID
	StartDate      *time.Time
	EndDate        *time.Time
	Limit          int
	Offset         int
}

// AnomalyScore is the per-fingerprint score envelope returned by
// AnomalyScoringService.GetScore and consumed by the scoring middleware.
// Shape ported from legacy auth-service internal/domain/anomaly.go.
type AnomalyScore struct {
	PrimaryReason      string
	Score              float64
	TenantJumpingCount int
	ErrorDensityCount  int
	VelocityCount      int
	IsAnomaly          bool
}
