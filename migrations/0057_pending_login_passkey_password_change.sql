-- identuum-idp-oss — a passkey sign-in's verified proof kept through the
-- required password change (OSS-G8-PASSKEY-MFA-CARRYOVER, owner decision
-- 2026-10-16).
--
-- A passkey sign-in that meets a required password change (D-017) holds the
-- same one-time handle as a password sign-in. When the server verified the
-- assertion WITH user verification, the handle is the new kind
-- 'password_change_passkey_uv': the change step then finishes the sign-in at
-- the phishing-resistant rung instead of asking for TOTP. The proof is the
-- row itself — same user, same expiry, one use — and it is bound to the
-- client that made the assertion (OSS-G8-PASSKEY-MFA-R2): client_binding is
-- the SHA-256 of a secret only that client holds: exactly 32 bytes on the
-- new kind and NULL on every other kind (OSS-G8-BN2).
--
-- Additive: no existing row changes, and no row becomes the new kind. Down
-- removes the new kind's rows (short-lived handles; a member mid-change signs
-- in again), the column and its check, and restores the three-kind check.

-- +goose Up

ALTER TABLE mfa_pending_login_sessions
    DROP CONSTRAINT mfa_pending_login_sessions_kind_check;

ALTER TABLE mfa_pending_login_sessions
    ADD CONSTRAINT mfa_pending_login_sessions_kind_check
        CHECK (kind IN ('enroll', 'verify', 'password_change', 'password_change_passkey_uv'));

ALTER TABLE mfa_pending_login_sessions
    ADD COLUMN client_binding BYTEA;

ALTER TABLE mfa_pending_login_sessions
    ADD CONSTRAINT mfa_pending_login_sessions_client_binding_check
        CHECK (CASE WHEN kind = 'password_change_passkey_uv' THEN client_binding IS NOT NULL AND octet_length(client_binding) = 32 ELSE client_binding IS NULL END);

-- +goose Down

DELETE FROM mfa_pending_login_sessions WHERE kind = 'password_change_passkey_uv';

ALTER TABLE mfa_pending_login_sessions
    DROP CONSTRAINT mfa_pending_login_sessions_client_binding_check;

ALTER TABLE mfa_pending_login_sessions
    DROP COLUMN client_binding;

ALTER TABLE mfa_pending_login_sessions
    DROP CONSTRAINT mfa_pending_login_sessions_kind_check;

ALTER TABLE mfa_pending_login_sessions
    ADD CONSTRAINT mfa_pending_login_sessions_kind_check
        CHECK (kind IN ('enroll', 'verify', 'password_change'));
