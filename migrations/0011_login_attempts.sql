-- +goose Up
-- +goose StatementBegin

-- login_attempts records ONLY the safe projection of each
-- credential-exchange attempt:
--
--   email_hash  SHA-256 hex of lowercased email (never raw).
--   ip_hash     SHA-256 hex of the client IP (never raw).
--   purpose     "password" / "mfa" / etc.
--   success     true|false
--   created_at  TIMESTAMPTZ
--   metadata    small JSONB allowlist (no passwords / TOTP / tokens).
--
-- Rate-limit decisions are made by counting non-success rows in a
-- sliding window keyed by (email_hash, ip_hash, purpose). Hashing
-- before storage means the table is GDPR-friendly: there is no
-- raw PII to leak.
CREATE TABLE login_attempts (
    id          UUID PRIMARY KEY,
    email_hash  TEXT NOT NULL,
    ip_hash     TEXT NOT NULL,
    purpose     TEXT NOT NULL,
    success     BOOLEAN NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    metadata    JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX idx_login_attempts_email_purpose_time
    ON login_attempts(email_hash, purpose, created_at DESC);

CREATE INDEX idx_login_attempts_ip_purpose_time
    ON login_attempts(ip_hash, purpose, created_at DESC);

CREATE INDEX idx_login_attempts_created_at
    ON login_attempts(created_at);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS login_attempts;
-- +goose StatementEnd
