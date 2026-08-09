package domain

import (
	"time"

	"github.com/google/uuid"
)

// WebAuthnCredential represents a registered passkey/FIDO2 credential
// It maps to the webauthn_credentials table
type WebAuthnCredential struct {
	UpdatedAt       time.Time
	CreatedAt       time.Time
	AAGUID          *uuid.UUID
	DeletedAt       *time.Time
	LastUsedAt      *time.Time
	AttestationType string
	Nickname        string
	PublicKey       []byte
	Transport       []string
	CredentialID    []byte
	SignCount       uint32
	ID              uuid.UUID
	OrganizationID  uuid.UUID
	UserID          uuid.UUID
	CloneWarning    bool
	BackupEligible  bool
	BackupState     bool
}

// WebAuthnUser interface is required by the go-webauthn library.
// We implement it on a wrapper struct in the service layer usually,
// but our domain.User can also satisfy parts of it if needed.
// For clean architecture, we'll keep domain.User pure and adapt it in service.
