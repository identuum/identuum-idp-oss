package domain

import (
	"time"

	"github.com/google/uuid"
)

const (
	// AttestationTypeExternalAuditPrune is used when an administrator declares they have manually pruned the external DB.
	// This is a one-time declaration; the 3-day alert cycle will resume when new logs exceed the retention threshold.
	AttestationTypeExternalAuditPrune = "external_audit_prune"

	// AttestationTypeAuthorizeAutoDelete is used when an administrator explicitly delegates log pruning to Identuum.
	// Once submitted, Identuum will automatically delete expired audit logs and the 3-day alert cycle is permanently disabled.
	AttestationTypeAuthorizeAutoDelete = "authorize_auto_delete"

	// DeclarationManualPrune is the exact legally binding string required for a manual prune attestation.
	DeclarationManualPrune = "I, hereby declare that I deleted the unnecessary audit logs from the external database that Identuum stack cannot perform a delete operation"

	// DeclarationAuthorizeAutoDelete is the exact legally binding string required to authorize Identuum auto-deletion.
	DeclarationAuthorizeAutoDelete = "I authorize Identuum to automatically delete ongoing expired audit logs in accordance with our GDPR data retention policy, and I take full legal responsibility for this delegation"
)

// ComplianceAttestation represents a legally binding declaration from an administrator.
type ComplianceAttestation struct {
	ID              uuid.UUID  // unique ID of the attestation record
	AttestationType string     // e.g., 'external_audit_prune'
	ActorEmail      string     // the specific admin's email making the attestation
	ActorIP         *string    // IP address of the actor
	DeclarationText string     // Exact phrasing they agreed to
	TargetDate      *time.Time // Optional contextual date (e.g., pruned records older than X)
	CreatedAt       time.Time  // timestamp of attestation
}
