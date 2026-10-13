-- identuum-idp-oss — an administrator-set password expires (OSS-0913-B, owner
-- answers Q-G2 (a) and Q-G2b (a), 2026-10-13).
--
-- admin_password_set_at is when an administrator set the password that
-- requires_password_change asks the member to replace (create with a password,
-- PUT /api/v1/users/:id with a password). Password sign-in refuses that
-- password 24 hours later. A password the member chooses, and a password the
-- administrator sets with must_change_password false, store NULL. Rows written
-- before this migration keep NULL and never expire, so nobody is locked out by
-- the upgrade.

-- +goose Up

ALTER TABLE users ADD COLUMN admin_password_set_at TIMESTAMPTZ NULL;

-- +goose Down

ALTER TABLE users DROP COLUMN IF EXISTS admin_password_set_at;
