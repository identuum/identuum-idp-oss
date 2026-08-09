// webauthn_repository_pgx.go — pgx-backed implementation of
// repository.WebAuthnCredentialRepository. Structurally ported from
// the monolith (identuum-idp/internal/postgres/webauthn_repository_pgx.go);
// no monolith code is imported. The OSS migration 0001 already creates
// the `webauthn_credentials` table with the columns this file reads
// and writes — see identuum-idp-oss/migrations/0001_identity_credentials.sql.
//
// Safety:
//   - Primary key is UUIDv7 (uuidgen.NewV7) so the B-Tree index stays
//     time-ordered; falling back to UUIDv4 would silently degrade
//     range-scan performance and is explicitly NOT allowed.
//   - public_key / credential_id are persisted as bytea exactly as
//     supplied by the upstream go-webauthn library. They are never
//     base64-encoded into a text column (which would allow accidental
//     log leakage) and never logged.
//   - All errors wrap the underlying pgx error with a short Go-side
//     prefix; raw row contents are never echoed in the error string.

package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/repository"
	"github.com/identuum/identuum-idp-oss/internal/utils/uuidgen"
)

// PgxWebAuthnCredentialRepository is the OSS pgx implementation of
// repository.WebAuthnCredentialRepository.
type PgxWebAuthnCredentialRepository struct {
	db DBTX
}

// NewPgxWebAuthnCredentialRepository constructs a pgx-backed
// WebAuthn credential repository.
func NewPgxWebAuthnCredentialRepository(db DBTX) *PgxWebAuthnCredentialRepository {
	return &PgxWebAuthnCredentialRepository{db: db}
}

// Create persists a new credential row. Generates a UUIDv7 id when
// cred.ID is the zero value. Sets created_at + updated_at to the
// repo's now.
func (r *PgxWebAuthnCredentialRepository) Create(ctx context.Context, cred *domain.WebAuthnCredential) (*domain.WebAuthnCredential, error) {
	if cred == nil {
		return nil, errors.New("webauthn credential: nil")
	}
	if cred.ID == uuid.Nil {
		// Service-wide UUIDv7 invariant. uuidgen.NewV7 can return
		// an error on retry-exhausted clock regression; propagate
		// rather than fall back to v4.
		id, err := uuidgen.NewV7()
		if err != nil {
			return nil, fmt.Errorf("webauthn credential: generate id: %w", err)
		}
		cred.ID = id
	}
	now := time.Now().UTC()
	cred.CreatedAt = now
	cred.UpdatedAt = now

	nickname := cred.Nickname
	if nickname == "" {
		// Match the DEFAULT defined in migration 0001 so the row
		// shape matches what the UI expects when no operator-supplied
		// label is available.
		nickname = "Device passkey"
		cred.Nickname = nickname
	}
	const query = `
		INSERT INTO webauthn_credentials (
			id, user_id, organization_id, credential_id, public_key,
			attestation_type, transport, aaguid, sign_count, clone_warning,
			backup_eligible, backup_state, nickname, created_at, updated_at, deleted_at
		) VALUES (
			$1, $2, $3, $4, $5,
			$6, $7, $8, $9, $10,
			$11, $12, $13, $14, $15, NULL
		) RETURNING id
	`
	err := r.db.QueryRow(ctx, query,
		cred.ID,
		cred.UserID,
		cred.OrganizationID,
		cred.CredentialID,
		cred.PublicKey,
		cred.AttestationType,
		cred.Transport,
		cred.AAGUID,
		cred.SignCount,
		cred.CloneWarning,
		cred.BackupEligible,
		cred.BackupState,
		nickname,
		cred.CreatedAt,
		cred.UpdatedAt,
	).Scan(&cred.ID)
	if err != nil {
		return nil, fmt.Errorf("webauthn credential: insert: %w", err)
	}
	return cred, nil
}

// GetByCredentialID retrieves a credential by its raw authenticator
// id. Returns ErrWebAuthnCredentialNotFound when no live row matches.
func (r *PgxWebAuthnCredentialRepository) GetByCredentialID(ctx context.Context, credentialID []byte) (*domain.WebAuthnCredential, error) {
	const query = `
		SELECT id, user_id, organization_id, credential_id, public_key,
		       attestation_type, transport, aaguid, sign_count, clone_warning,
		       backup_eligible, backup_state, nickname, created_at, updated_at, last_used_at, deleted_at
		FROM webauthn_credentials
		WHERE credential_id = $1 AND deleted_at IS NULL
	`
	cred := &domain.WebAuthnCredential{}
	var aaguid *uuid.UUID
	err := r.db.QueryRow(ctx, query, credentialID).Scan(
		&cred.ID,
		&cred.UserID,
		&cred.OrganizationID,
		&cred.CredentialID,
		&cred.PublicKey,
		&cred.AttestationType,
		&cred.Transport,
		&aaguid,
		&cred.SignCount,
		&cred.CloneWarning,
		&cred.BackupEligible,
		&cred.BackupState,
		&cred.Nickname,
		&cred.CreatedAt,
		&cred.UpdatedAt,
		&cred.LastUsedAt,
		&cred.DeletedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, repository.ErrWebAuthnCredentialNotFound
		}
		return nil, fmt.Errorf("webauthn credential: get: %w", err)
	}
	cred.AAGUID = aaguid
	return cred, nil
}

// ListByUser returns all live credentials for a user, newest first.
func (r *PgxWebAuthnCredentialRepository) ListByUser(ctx context.Context, userID uuid.UUID) ([]*domain.WebAuthnCredential, error) {
	const query = `
		SELECT id, user_id, organization_id, credential_id, public_key,
		       attestation_type, transport, aaguid, sign_count, clone_warning,
		       backup_eligible, backup_state, nickname, created_at, updated_at, last_used_at, deleted_at
		FROM webauthn_credentials
		WHERE user_id = $1 AND deleted_at IS NULL
		ORDER BY created_at DESC
	`
	rows, err := r.db.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("webauthn credential: list: %w", err)
	}
	defer rows.Close()

	var creds []*domain.WebAuthnCredential
	for rows.Next() {
		cred := &domain.WebAuthnCredential{}
		var aaguid *uuid.UUID
		if err := rows.Scan(
			&cred.ID,
			&cred.UserID,
			&cred.OrganizationID,
			&cred.CredentialID,
			&cred.PublicKey,
			&cred.AttestationType,
			&cred.Transport,
			&aaguid,
			&cred.SignCount,
			&cred.CloneWarning,
			&cred.BackupEligible,
			&cred.BackupState,
			&cred.Nickname,
			&cred.CreatedAt,
			&cred.UpdatedAt,
			&cred.LastUsedAt,
			&cred.DeletedAt,
		); err != nil {
			return nil, fmt.Errorf("webauthn credential: scan: %w", err)
		}
		cred.AAGUID = aaguid
		creds = append(creds, cred)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("webauthn credential: rows: %w", err)
	}
	return creds, nil
}

// UpdateSignCount updates the signature counter and last-used
// timestamp atomically.
func (r *PgxWebAuthnCredentialRepository) UpdateSignCount(ctx context.Context, id uuid.UUID, newCount uint32) error {
	const query = `
		UPDATE webauthn_credentials
		SET sign_count = $2, last_used_at = $3, updated_at = $3
		WHERE id = $1 AND deleted_at IS NULL
	`
	_, err := r.db.Exec(ctx, query, id, newCount, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("webauthn credential: update sign_count: %w", err)
	}
	return nil
}

// UpdateLastUsed bumps last_used_at + updated_at on the credential
// row without changing the sign counter.
func (r *PgxWebAuthnCredentialRepository) UpdateLastUsed(ctx context.Context, id uuid.UUID) error {
	const query = `
		UPDATE webauthn_credentials
		SET last_used_at = $2, updated_at = $2
		WHERE id = $1 AND deleted_at IS NULL
	`
	_, err := r.db.Exec(ctx, query, id, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("webauthn credential: update last_used: %w", err)
	}
	return nil
}

// Delete soft-deletes the credential row (sets deleted_at = NOW()).
// Ownership enforcement happens in the service layer; this repo is
// strictly a SQL operator.
func (r *PgxWebAuthnCredentialRepository) Delete(ctx context.Context, id uuid.UUID) error {
	const query = `UPDATE webauthn_credentials SET deleted_at = NOW() WHERE id = $1`
	_, err := r.db.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("webauthn credential: delete: %w", err)
	}
	return nil
}

// UpdateCloneWarning flips the clone-warning flag (used when the
// upstream go-webauthn library reports a backward-moving sign
// counter — the credential is permanently disabled until the user
// deletes and re-registers it).
func (r *PgxWebAuthnCredentialRepository) UpdateCloneWarning(ctx context.Context, id uuid.UUID, warning bool) error {
	const query = `
		UPDATE webauthn_credentials
		SET clone_warning = $2, updated_at = $3
		WHERE id = $1 AND deleted_at IS NULL
	`
	_, err := r.db.Exec(ctx, query, id, warning, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("webauthn credential: update clone_warning: %w", err)
	}
	return nil
}

// Static interface assertion.
var _ repository.WebAuthnCredentialRepository = (*PgxWebAuthnCredentialRepository)(nil)
