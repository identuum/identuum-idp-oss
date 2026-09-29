-- identuum-idp-oss — the password-change step of a sign-in (OSS-FIN-1, owner
-- ruling D-017, 2026-09-29).
--
-- A user created with an admin-set password must change it at first sign-in
-- (users.requires_password_change, present since 0001). The sign-in that
-- reaches that step — password, and MFA when the policy asks — holds a
-- one-time pending handle exactly like the MFA steps, and redeems it with the
-- new password; no session or token exists before. The handle is a row of
-- mfa_pending_login_sessions with kind 'password_change'.
--
-- Additive: no existing row changes. Down removes the new kind's rows (short-
-- lived handles; a user mid-change signs in again) and restores the check.

-- +goose Up

ALTER TABLE mfa_pending_login_sessions
    DROP CONSTRAINT mfa_pending_login_sessions_kind_check;

ALTER TABLE mfa_pending_login_sessions
    ADD CONSTRAINT mfa_pending_login_sessions_kind_check
        CHECK (kind IN ('enroll', 'verify', 'password_change'));

-- +goose Down

DELETE FROM mfa_pending_login_sessions WHERE kind = 'password_change';

ALTER TABLE mfa_pending_login_sessions
    DROP CONSTRAINT mfa_pending_login_sessions_kind_check;

ALTER TABLE mfa_pending_login_sessions
    ADD CONSTRAINT mfa_pending_login_sessions_kind_check
        CHECK (kind IN ('enroll', 'verify'));
