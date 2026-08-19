package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/mappers"
	"github.com/identuum/identuum-idp-oss/internal/metrics"
	"github.com/identuum/identuum-idp-oss/internal/repository"
	"github.com/identuum/identuum-idp-oss/logger"
	"github.com/identuum/identuum-idp-oss/types"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/prometheus/client_golang/prometheus"
)

// PrivateKeyCipher is the at-rest encryption seam the key repository uses to
// protect signing_keys.private_key (P3-5). It is satisfied AS-IS by
// *crypto.CryptoService (AES-256-GCM, versioned "v2:<keyID>:<b64>") — the
// same primitive that protects every other OSS at-rest secret. The public
// key is PUBLIC and is never passed through this seam.
type PrivateKeyCipher interface {
	Encrypt(plaintext string) (string, error)
	Decrypt(ciphertext string) (string, error)
}

// pemPrefix marks a plaintext PEM private key. A stored private_key value
// beginning with it is a LEGACY (pre-P3-5) plaintext row and is read back
// verbatim; any other value is a CryptoService ciphertext.
const pemPrefix = "-----BEGIN"

// PgxKeyRepository implements KeyRepository with PostgreSQL using pgx
type PgxKeyRepository struct {
	db DBTX
	// cipher encrypts private_key at rest (P3-5). Nil-tolerant + FAIL-CLOSED:
	// production key WRITERS (the serving runtime + bootstrap) inject a real
	// cipher, so private keys are never stored in plaintext. Non-writer
	// callers (the db-check / recover-site-admin one-shot diagnostics, which
	// never create or read signing keys) may pass nil — and a nil cipher can
	// NEVER silently write plaintext: CreateSigningKey with a nil cipher
	// ERRORS, and reading a ciphertext row with a nil cipher ERRORS. Only a
	// legacy plaintext PEM read passes through without a cipher (so a
	// cipher-less diagnostic can still construct the aggregate).
	cipher PrivateKeyCipher
}

// NewPgxKeyRepository creates a new PgxKeyRepository. cipher encrypts
// private_key at rest; see the field doc for the nil-tolerant fail-closed
// contract. Production writers MUST pass a real cipher.
func NewPgxKeyRepository(db DBTX, cipher PrivateKeyCipher) *PgxKeyRepository {
	return &PgxKeyRepository{
		db:     db,
		cipher: cipher,
	}
}

var _ repository.KeyRepository = (*PgxKeyRepository)(nil)

// decryptPrivateKey turns a stored private_key value into a PEM for the
// mapper: a legacy plaintext PEM passes through verbatim; anything else is
// decrypted via the cipher. FAIL-CLOSED — a ciphertext with no cipher
// configured, a cipher-decrypt failure, or a value that is neither a PEM nor
// decryptable-to-PEM returns an error, so the signer is NEVER handed
// ciphertext or garbage.
func (r *PgxKeyRepository) decryptPrivateKey(stored string) (string, error) {
	if stored == "" {
		return "", nil // no private material (e.g. a verify-only public key)
	}
	if strings.HasPrefix(stored, pemPrefix) {
		return stored, nil // legacy plaintext PEM — passthrough (zero-downtime)
	}
	if r.cipher == nil {
		return "", fmt.Errorf("signing-key private material is encrypted but no cipher is configured")
	}
	pemStr, err := r.cipher.Decrypt(stored)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt signing-key private material: %w", err)
	}
	// A decrypted EMPTY value is a valid "no private material"; a non-empty
	// value that is not a PEM is garbage and must never reach the signer.
	if pemStr != "" && !strings.HasPrefix(pemStr, pemPrefix) {
		return "", fmt.Errorf("decrypted signing-key private material is not a PEM")
	}
	return pemStr, nil
}

// GetActiveSigningKeys returns all keys that can validate tokens (active + rotating)
// GetActiveSigningKeys returns all keys that can validate tokens (active + rotating)
func (r *PgxKeyRepository) GetActiveSigningKeys(ctx context.Context) ([]domain.SigningKey, error) {
	timer := prometheus.NewTimer(metrics.DBQueryDuration.WithLabelValues("key_repo", "get_active", "all"))
	defer timer.ObserveDuration()

	query := `
		SELECT 
			id, kid, algorithm, public_key, private_key, state, 
			created_at, activated_at, rotated_at, expires_at, created_by
		FROM signing_keys
		WHERE state IN ('active', 'rotating')
		ORDER BY 
			CASE state
				WHEN 'active' THEN 1
				WHEN 'rotating' THEN 2
			END,
			activated_at DESC NULLS LAST
	`

	rows, err := r.db.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query signing keys: %w", err)
	}
	defer rows.Close()

	var keys []types.SigningKey
	for rows.Next() {
		var key types.SigningKey
		err := rows.Scan(
			&key.ID, &key.KID, &key.Algorithm, &key.PublicKey, &key.PrivateKey,
			&key.State, &key.CreatedAt, &key.ActivatedAt, &key.RotatedAt,
			&key.ExpiresAt, &key.CreatedBy,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan signing key: %w", err)
		}
		// P3-5: SKIP (log) a row whose private material cannot be decrypted
		// rather than failing the ENTIRE active-key load — a single
		// corrupt/foreign row must not disable ALL token signing +
		// verification (availability). The skipped row is NEVER handed to the
		// signer (fail-closed for that row). GetSigningKeyByKID keeps the hard
		// error for the targeted-lookup case.
		if key.PrivateKey, err = r.decryptPrivateKey(key.PrivateKey); err != nil {
			logger.Error.WithFields(map[string]any{
				"kid":   key.KID,
				"error": err.Error(),
			}).Print("P3-5: skipping active signing key with undecryptable private material")
			continue
		}
		keys = append(keys, key)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating signing keys: %w", err)
	}

	logger.Debug.WithFields(map[string]any{
		"count": len(keys),
	}).Print("Loaded signing keys from database")

	return mappers.ToDomainSigningKeys(keys), nil
}

// CountActiveSigningKeyRows counts signing_keys rows in an active/rotating
// state WITHOUT decrypting them (SIGNING-KEY-SEAL-1). GetActiveSigningKeys
// returns only the USABLE (decryptable) subset — comparing the two tells a
// caller whether active keys exist that cannot be decrypted, which is a silent
// brick: tokens cannot be signed and every login fails while /health, reading
// only decryptable keys elsewhere, stays green.
func (r *PgxKeyRepository) CountActiveSigningKeyRows(ctx context.Context) (int, error) {
	var n int
	err := r.db.QueryRow(ctx,
		`SELECT count(*) FROM signing_keys WHERE state IN ('active', 'rotating')`,
	).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("failed to count active signing keys: %w", err)
	}
	return n, nil
}

// GetAllSigningKeys returns all keys including deprecated
// GetAllSigningKeys returns all keys including deprecated
func (r *PgxKeyRepository) GetAllSigningKeys(ctx context.Context) ([]domain.SigningKey, error) {
	timer := prometheus.NewTimer(metrics.DBQueryDuration.WithLabelValues("key_repo", "get_all", "all"))
	defer timer.ObserveDuration()

	query := `
		SELECT 
			id, kid, algorithm, public_key, private_key, state, 
			created_at, activated_at, rotated_at, expires_at, created_by
		FROM signing_keys
		ORDER BY created_at DESC
	`

	rows, err := r.db.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query all signing keys: %w", err)
	}
	defer rows.Close()

	var keys []types.SigningKey
	for rows.Next() {
		var key types.SigningKey
		err := rows.Scan(
			&key.ID, &key.KID, &key.Algorithm, &key.PublicKey, &key.PrivateKey,
			&key.State, &key.CreatedAt, &key.ActivatedAt, &key.RotatedAt,
			&key.ExpiresAt, &key.CreatedBy,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan signing key: %w", err)
		}
		// P3-5: SKIP (log) an undecryptable row rather than failing the whole
		// list — see GetActiveSigningKeys.
		if key.PrivateKey, err = r.decryptPrivateKey(key.PrivateKey); err != nil {
			logger.Error.WithFields(map[string]any{
				"kid":   key.KID,
				"error": err.Error(),
			}).Print("P3-5: skipping signing key with undecryptable private material")
			continue
		}
		keys = append(keys, key)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating all signing keys: %w", err)
	}

	return mappers.ToDomainSigningKeys(keys), nil
}

// GetSigningKeyByKID retrieves a specific key by its Key ID
// GetSigningKeyByKID retrieves a specific key by its Key ID
func (r *PgxKeyRepository) GetSigningKeyByKID(ctx context.Context, kid string) (*domain.SigningKey, error) {
	timer := prometheus.NewTimer(metrics.DBQueryDuration.WithLabelValues("key_repo", "get_by_kid", "all"))
	defer timer.ObserveDuration()

	query := `
		SELECT 
			id, kid, algorithm, public_key, private_key, state, 
			created_at, activated_at, rotated_at, expires_at, created_by
		FROM signing_keys
		WHERE kid = $1
	`

	var key types.SigningKey
	err := r.db.QueryRow(ctx, query, kid).Scan(
		&key.ID, &key.KID, &key.Algorithm, &key.PublicKey, &key.PrivateKey,
		&key.State, &key.CreatedAt, &key.ActivatedAt, &key.RotatedAt,
		&key.ExpiresAt, &key.CreatedBy,
	)

	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("signing key not found: %s (%w)", kid, err)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get signing key: %w", err)
	}

	if key.PrivateKey, err = r.decryptPrivateKey(key.PrivateKey); err != nil {
		return nil, fmt.Errorf("signing key %s: %w", kid, err)
	}

	domainKey := mappers.ToDomainSigningKey(key)
	return &domainKey, nil
}

// CreateSigningKey inserts a new signing key into the database
// CreateSigningKey inserts a new signing key into the database
func (r *PgxKeyRepository) CreateSigningKey(ctx context.Context, key *domain.SigningKey) error {
	timer := prometheus.NewTimer(metrics.DBQueryDuration.WithLabelValues("key_repo", "create", "all"))
	defer timer.ObserveDuration()

	keyDTO := mappers.ToDTOSigningKey(*key)

	// P3-5: encrypt the private key at rest. FAIL-CLOSED — a writer with no
	// cipher configured refuses rather than storing REAL private material in
	// plaintext. An EMPTY private key (a verify-only public key) carries no
	// material to protect, so it is stored empty without a cipher. public_key
	// is PUBLIC and stays plaintext.
	encPrivateKey := keyDTO.PrivateKey
	if encPrivateKey != "" {
		if r.cipher == nil {
			return fmt.Errorf("cannot create signing key %s: private-key encryption cipher not configured", keyDTO.KID)
		}
		enc, encErr := r.cipher.Encrypt(encPrivateKey)
		if encErr != nil {
			return fmt.Errorf("failed to encrypt signing-key private material: %w", encErr)
		}
		encPrivateKey = enc
	}

	query := `
		INSERT INTO signing_keys (kid, algorithm, public_key, private_key, state, created_by)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id, created_at
	`

	err := r.db.QueryRow(
		ctx,
		query,
		keyDTO.KID, keyDTO.Algorithm, keyDTO.PublicKey, encPrivateKey, keyDTO.State, keyDTO.CreatedBy,
	).Scan(&keyDTO.ID, &keyDTO.CreatedAt)

	// Update domain object with generated fields
	key.ID = keyDTO.ID
	key.CreatedAt = keyDTO.CreatedAt

	if err != nil {
		return fmt.Errorf("failed to create signing key: %w", err)
	}

	logger.Info.WithFields(map[string]any{
		"kid":       key.KID,
		"algorithm": key.Algorithm,
		"state":     key.State,
	}).Print("Created new signing key")

	return nil
}

// ReEncryptPlaintextKeys migrates LEGACY plaintext-PEM private_key rows to
// ciphertext at rest (P3-5). It finds every row whose private_key still
// begins with the PEM header, encrypts it via the cipher, and UPDATEs it in
// place — actively purging plaintext rather than waiting for the next
// rotation. Returns the number of rows re-encrypted. Idempotent: an
// already-encrypted row never matches the prefix, so a second run affects
// zero rows. Requires a configured cipher (it is only ever invoked from a
// writer boot path). public_key is untouched.
func (r *PgxKeyRepository) ReEncryptPlaintextKeys(ctx context.Context) (int, error) {
	if r.cipher == nil {
		return 0, fmt.Errorf("cannot re-encrypt signing keys: private-key encryption cipher not configured")
	}
	timer := prometheus.NewTimer(metrics.DBQueryDuration.WithLabelValues("key_repo", "reencrypt", "all"))
	defer timer.ObserveDuration()

	// Collect the plaintext rows first — pgx cannot run UPDATEs while the
	// SELECT's rows are still open on the same connection.
	rows, err := r.db.Query(ctx, `SELECT id, private_key FROM signing_keys WHERE private_key LIKE '-----BEGIN%'`)
	if err != nil {
		return 0, fmt.Errorf("failed to query plaintext signing keys: %w", err)
	}
	type plaintextRow struct {
		id  string
		pem string
	}
	var pending []plaintextRow
	for rows.Next() {
		var pr plaintextRow
		if err := rows.Scan(&pr.id, &pr.pem); err != nil {
			rows.Close()
			return 0, fmt.Errorf("failed to scan plaintext signing key: %w", err)
		}
		pending = append(pending, pr)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, fmt.Errorf("error iterating plaintext signing keys: %w", err)
	}
	rows.Close()

	count := 0
	for _, pr := range pending {
		enc, err := r.cipher.Encrypt(pr.pem)
		if err != nil {
			return count, fmt.Errorf("failed to encrypt legacy signing key %s: %w", pr.id, err)
		}
		if _, err := r.db.Exec(ctx, `UPDATE signing_keys SET private_key = $1 WHERE id = $2`, enc, pr.id); err != nil {
			return count, fmt.Errorf("failed to update re-encrypted signing key %s: %w", pr.id, err)
		}
		count++
	}
	if count > 0 {
		logger.Info.WithFields(map[string]any{
			"count": count,
		}).Print("Re-encrypted legacy plaintext signing-key private material at rest")
	}
	return count, nil
}

// ActivateSigningKey activates a key (makes it the primary signing key)
func (r *PgxKeyRepository) ActivateSigningKey(ctx context.Context, kid string) error {
	timer := prometheus.NewTimer(metrics.DBQueryDuration.WithLabelValues("key_repo", "activate", "all"))
	defer timer.ObserveDuration()

	query := `
		UPDATE signing_keys
		SET state = 'active', activated_at = CURRENT_TIMESTAMP
		WHERE kid = $1 AND state != 'deprecated'
	`

	result, err := r.db.Exec(ctx, query, kid)
	if err != nil {
		return fmt.Errorf("failed to activate signing key: %w", err)
	}

	affected := result.RowsAffected()
	if affected == 0 {
		return fmt.Errorf("signing key not found or already deprecated: %s", kid)
	}

	logger.Info.WithFields(map[string]any{
		"kid": kid,
	}).Print("Activated signing key")

	return nil
}

// RotateSigningKey performs atomic key rotation
func (r *PgxKeyRepository) RotateSigningKey(ctx context.Context, oldKID, newKID string, expiresAt *time.Time) error {
	timer := prometheus.NewTimer(metrics.DBQueryDuration.WithLabelValues("key_repo", "rotate", "all"))
	defer timer.ObserveDuration()

	// Use DBTX.Begin to start a transaction (works for pool or nested tx)
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	now := time.Now()

	// Step 1: Mark old key as rotating with optional expiration
	var result pgconn.CommandTag

	if expiresAt != nil {
		result, err = tx.Exec(ctx, `
			UPDATE signing_keys
			SET state = 'rotating', rotated_at = $1, expires_at = $2
			WHERE kid = $3 AND state = 'active'
		`, now, expiresAt, oldKID)
	} else {
		result, err = tx.Exec(ctx, `
			UPDATE signing_keys
			SET state = 'rotating', rotated_at = $1
			WHERE kid = $2 AND state = 'active'
		`, now, oldKID)
	}

	if err != nil {
		return fmt.Errorf("failed to rotate old key: %w", err)
	}

	if result.RowsAffected() == 0 {
		return fmt.Errorf("old key not found or not active: %s", oldKID)
	}

	// Step 2: Activate new key
	result, err = tx.Exec(ctx, `
		UPDATE signing_keys
		SET state = 'active', activated_at = $1
		WHERE kid = $2 AND state != 'deprecated'
	`, now, newKID)

	if err != nil {
		return fmt.Errorf("failed to activate new key: %w", err)
	}

	if result.RowsAffected() == 0 {
		return fmt.Errorf("new key not found or deprecated: %s", newKID)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("failed to commit rotation transaction: %w", err)
	}

	logger.Info.WithFields(map[string]any{
		"old_kid":    oldKID,
		"new_kid":    newKID,
		"expires_at": expiresAt,
	}).Print("Rotated signing keys")

	return nil
}

// DeprecateSigningKey marks a key as deprecated with expiration timestamp
func (r *PgxKeyRepository) DeprecateSigningKey(ctx context.Context, kid string, expiresAt time.Time) error {
	timer := prometheus.NewTimer(metrics.DBQueryDuration.WithLabelValues("key_repo", "deprecate", "all"))
	defer timer.ObserveDuration()

	query := `
		UPDATE signing_keys
		SET state = 'deprecated', expires_at = $1
		WHERE kid = $2 AND state = 'rotating'
	`

	result, err := r.db.Exec(ctx, query, expiresAt, kid)
	if err != nil {
		return fmt.Errorf("failed to deprecate signing key: %w", err)
	}

	if result.RowsAffected() == 0 {
		return fmt.Errorf("key not found or not in rotating state: %s", kid)
	}

	logger.Info.WithFields(map[string]any{
		"kid":        kid,
		"expires_at": expiresAt.Format(time.RFC3339),
	}).Print("Deprecated signing key")

	return nil
}

// DeleteExpiredKeys removes deprecated keys past their expiration timestamp
func (r *PgxKeyRepository) DeleteExpiredKeys(ctx context.Context) (int, error) {
	timer := prometheus.NewTimer(metrics.DBQueryDuration.WithLabelValues("key_repo", "delete_expired", "all"))
	defer timer.ObserveDuration()

	query := `
		DELETE FROM signing_keys
		WHERE state = 'deprecated' AND expires_at < CURRENT_TIMESTAMP
	`

	result, err := r.db.Exec(ctx, query)
	if err != nil {
		metrics.DBQueryDuration.WithLabelValues("key_repo", "delete_expired", "error").Observe(timer.ObserveDuration().Seconds())
		return 0, fmt.Errorf("failed to delete expired keys: %w", err)
	}
	metrics.DBQueryDuration.WithLabelValues("key_repo", "delete_expired", "success").Observe(timer.ObserveDuration().Seconds())

	affected := result.RowsAffected()

	if affected > 0 {
		logger.Info.WithFields(map[string]any{
			"count": affected,
		}).Print("Deleted expired signing keys")
	}

	return int(affected), nil
}
