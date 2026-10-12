-- identuum-idp-oss — a verification link proves only the address it was
-- mailed to (OSS-0912-C2-FIX, review OSS-0912-C2-REVIEW R1, 2026-10-12).
--
-- email_hash is the hex SHA-256 of the address the link was mailed to,
-- lower-cased and trimmed (domain.EmailAddressHash); the address itself is
-- not stored a second time. Opening a link whose email_hash differs from the
-- user's current address proves nothing. An unused row written before this
-- migration names no address, so it is spent here: a link mailed before the
-- upgrade can no longer prove an address that changed since. A user who
-- still needs one asks for a new verification email.

-- +goose Up

ALTER TABLE email_verifications ADD COLUMN email_hash VARCHAR(64) NULL;

UPDATE email_verifications SET used_at = NOW() WHERE used_at IS NULL AND email_hash IS NULL;

-- +goose Down

ALTER TABLE email_verifications DROP COLUMN IF EXISTS email_hash;
