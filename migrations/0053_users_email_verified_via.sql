-- identuum-idp-oss — how the mailbox at a user's address was proven
-- (OSS-0912-C2, owner answers Q1 (a), Q2 (b), Q3 (a), 2026-10-12).
--
-- users.email_verified keeps its meaning: the account is activated. It does
-- not say the person controls the mailbox, because an administrator who
-- invites, activates or creates a user also holds the link or sets the
-- password. email_verified_via records HOW the address was verified:
--
--   email_link    the user opened a verification email      (proven)
--   upstream_idp  the sign-in provider confirmed the address (proven)
--   legacy        verified before this migration (owner Q2)  (proven)
--   admin_link    activated through an administrator's link (not proven)
--   admin_set     an administrator set it                    (not proven)
--   setup         the bootstrap or setup-wizard site_admin   (not proven)
--   NULL          never proven
--
-- The email_verified claim in tokens and userinfo is true only for the three
-- proven values. Rows already verified keep that answer ('legacy'); new rows
-- are strict. No constraint ties the column to email_verified: a pending
-- invitee can prove the mailbox before the invite activates the account.

-- +goose Up

ALTER TABLE users
    ADD COLUMN email_verified_via TEXT NULL
    CHECK (email_verified_via IN ('email_link', 'upstream_idp', 'admin_link', 'admin_set', 'setup', 'legacy'));

UPDATE users SET email_verified_via = 'legacy' WHERE email_verified = true;

-- +goose Down

ALTER TABLE users DROP COLUMN IF EXISTS email_verified_via;
