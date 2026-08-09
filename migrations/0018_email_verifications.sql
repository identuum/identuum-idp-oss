-- +goose Up
-- +goose StatementBegin
--
-- `email_verifications` — single-use email verification tokens.
--
-- Mirrors `password_resets` in shape: token_hash is the primary key (lookup
-- on consume) + holds the SHA-256 of the operator-shown raw token; the raw
-- token is NEVER stored. expires_at is enforced by the service layer (24h
-- TTL); used_at flips on consume so a replay attempt finds a non-NULL
-- used_at and is rejected even if the row has not yet been DeleteExpired'd.
--
-- Why a dedicated table (instead of using `users.verification_token_hash`):
--   - `password_resets` already follows this pattern — we keep the two
--     account-lifecycle token surfaces symmetrical so service / repo code
--     reads the same way.
--   - Adding a per-user `verification_token_expires_at` column would
--     require updating every SELECT projection across the user repo
--     for a flow that is otherwise self-contained.
--   - A dedicated table lets us hold multiple in-flight tokens per user
--     (operator hits "resend verification" twice in 30 seconds) without
--     racing on a single column.
--
CREATE TABLE email_verifications (
    token_hash VARCHAR(64) PRIMARY KEY,
    user_id    UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at    TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_email_verifications_user_id    ON email_verifications(user_id);
CREATE INDEX idx_email_verifications_expires_at ON email_verifications(expires_at);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_email_verifications_expires_at;
DROP INDEX IF EXISTS idx_email_verifications_user_id;
DROP TABLE IF EXISTS email_verifications;
-- +goose StatementEnd
