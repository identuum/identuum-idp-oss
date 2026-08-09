package domain

import (
	"time"

	"github.com/google/uuid"
)

// OrgBackupRestoreJobStatus is the state machine for a restore job.
// Values match the CHECK constraint in migration 0045.
type OrgBackupRestoreJobStatus string

const (
	OrgBackupRestoreJobPending   OrgBackupRestoreJobStatus = "pending"
	OrgBackupRestoreJobRunning   OrgBackupRestoreJobStatus = "running"
	OrgBackupRestoreJobCompleted OrgBackupRestoreJobStatus = "completed"
	OrgBackupRestoreJobFailed    OrgBackupRestoreJobStatus = "failed"
)

// OrgBackupRestoreJobSource identifies where a restore payload came from.
type OrgBackupRestoreJobSource string

const (
	OrgBackupRestoreJobSourceStored OrgBackupRestoreJobSource = "stored"
	OrgBackupRestoreJobSourceUpload OrgBackupRestoreJobSource = "upload"
)

// OrgBackup is the metadata row for a stored org-scoped backup file.
// The physical payload lives on disk at FilePath, encrypted with a user-supplied password.
type OrgBackup struct {
	ID              uuid.UUID
	OrganizationID  uuid.UUID
	CreatedAt       time.Time
	CreatedByUserID *uuid.UUID
	SchemaVersion   string
	IdentuumVersion string
	FilePath        string
	FileSizeBytes   int64
	// RowCounts is the per-table row count at backup time. Keys are table names
	// from §8.1 of the design doc. Decoded from the row_counts JSONB column.
	RowCounts map[string]int
}

// OrgBackupRestoreJob represents an in-flight or historical restore operation.
type OrgBackupRestoreJob struct {
	ID                uuid.UUID
	OrganizationID    uuid.UUID
	Source            OrgBackupRestoreJobSource
	SourceBackupID    *uuid.UUID
	Status            OrgBackupRestoreJobStatus
	Error             string
	RequestedByUserID *uuid.UUID
	CreatedAt         time.Time
	StartedAt         *time.Time
	CompletedAt       *time.Time
}

// OrgBackupKDFParams captures the argon2id parameters embedded in the plaintext
// file header. Validated against hard bounds on restore before any key derivation
// attempt to prevent a hostile header from triggering pathological argon2 params.
type OrgBackupKDFParams struct {
	Time      uint32 `json:"time"`
	MemoryKiB uint32 `json:"memory_kib"`
	Threads   uint8  `json:"threads"`
	KeyLen    uint32 `json:"key_len"`
}

// OrgBackupHeader is the plaintext JSON header written in front of the
// AES-256-GCM ciphertext. It MUST NOT contain any organization identifier,
// timestamp, row count, or actor detail — a file leaked without the password
// must only reveal "this is an Identuum org backup and these are the KDF params."
type OrgBackupHeader struct {
	Format    string             `json:"format"`
	Version   int                `json:"version"`
	KDF       string             `json:"kdf"`
	KDFParams OrgBackupKDFParams `json:"kdf_params"`
	Salt      string             `json:"salt"`  // base64(16 random bytes)
	Nonce     string             `json:"nonce"` // base64(12 random bytes)
	Cipher    string             `json:"cipher"`
}

// OrgBackupEnvelope is the inner plaintext that is gzipped then AES-256-GCM
// encrypted. Every restore validates this envelope's organization_id against
// the actor's tenant and its schema_version against the running binary's
// migration number before any DB write.
type OrgBackupEnvelope struct {
	EnvelopeVersion int    `json:"envelope_version"`
	SchemaVersion   string `json:"schema_version"`
	IdentuumVersion string `json:"identuum_version"`
	OrganizationID  string `json:"organization_id"`
	CreatedAt       string `json:"created_at"`
	// Tables maps table name → ordered slice of row maps. Row maps are
	// column-name keyed; values are native JSON types with BYTEA columns
	// base64-encoded. Row order MUST honour FK dependencies for restore.
	Tables map[string][]map[string]any `json:"tables"`
}

// Expected header constants. Mismatches on restore produce ErrOrgBackupCorrupt
// (or ErrOrgBackupIncompatibleVersion for envelope_version specifically).
//
// OrgBackupEnvelopeVersion is the explicit envelope-format schema version. Bump
// this on any envelope-shape change that affects backup-readability (a column
// drop the deserializer would otherwise silently lose, a structural reshuffle,
// a tag rename). It is INDEPENDENT of bump2version's app-level VERSION: a
// 0.6.x build can ship a v2 envelope; a 1.0.x build can still ship v1. v0 is
// the implicit pre-versioning legacy and is rejected as
// ErrOrgBackupIncompatibleVersion because Go's encoding/json defaults
// missing fields to the int zero value.
const (
	OrgBackupFormatID        = "identuum_org_backup"
	OrgBackupFormatVersion   = 1
	OrgBackupEnvelopeVersion = 1
	OrgBackupKDFName         = "argon2id"
	OrgBackupCipherName      = "aes-256-gcm"
)

// Argon2id hard bounds for header parameters. Enforced on decrypt before any
// key derivation. See §7.6 of docs/ImplementationPlan-OrgBackups.md.
const (
	OrgBackupKDFTimeMin    uint32 = 1
	OrgBackupKDFTimeMax    uint32 = 10
	OrgBackupKDFMemoryMin  uint32 = 32 * 1024  // 32 MiB
	OrgBackupKDFMemoryMax  uint32 = 256 * 1024 // 256 MiB
	OrgBackupKDFThreadsMin uint8  = 1
	OrgBackupKDFThreadsMax uint8  = 8
	OrgBackupKDFKeyLen     uint32 = 32
)

// Default argon2id parameters used when producing a new backup.
const (
	OrgBackupKDFTimeDefault    uint32 = 3
	OrgBackupKDFMemoryDefault  uint32 = 65536 // 64 MiB in KiB
	OrgBackupKDFThreadsDefault uint8  = 4
	OrgBackupSaltLen                  = 16
	OrgBackupNonceLen                 = 12
)
