-- identuum-idp-oss — a passkey sign-in's verified proof kept through the
-- required password change (OSS-G8-PASSKEY-MFA-CARRYOVER, owner decision
-- 2026-10-16).
--
-- A passkey sign-in that meets a required password change (D-017) holds the
-- same one-time handle as a password sign-in. When the server verified the
-- assertion WITH user verification, the handle is the new kind
-- 'password_change_passkey_uv': the change step then finishes the sign-in at
-- the phishing-resistant rung instead of asking for TOTP. The proof is the
-- row itself — same user, same expiry, one use; no other column changes.
--
-- Additive: no existing row changes, and no row becomes the new kind. Down
-- removes the new kind's rows (short-lived handles; a member mid-change signs
-- in again) and restores the three-kind check.

-- +goose Up

ALTER TABLE mfa_pending_login_sessions
    DROP CONSTRAINT mfa_pending_login_sessions_kind_check;

ALTER TABLE mfa_pending_login_sessions
    ADD CONSTRAINT mfa_pending_login_sessions_kind_check
        CHECK (kind IN ('enroll', 'verify', 'password_change', 'password_change_passkey_uv'));

-- +goose Down

DELETE FROM mfa_pending_login_sessions WHERE kind = 'password_change_passkey_uv';

ALTER TABLE mfa_pending_login_sessions
    DROP CONSTRAINT mfa_pending_login_sessions_kind_check;

ALTER TABLE mfa_pending_login_sessions
    ADD CONSTRAINT mfa_pending_login_sessions_kind_check
        CHECK (kind IN ('enroll', 'verify', 'password_change'));
