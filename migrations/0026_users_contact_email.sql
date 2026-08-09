-- identuum-idp-oss — the site_admin's CONTACT email (MODEL-CONTACT-EMAIL).
--
-- AdminPermissionsModel.md pins the site_admin's LOGIN identifier to
-- site_admin@system.local and, separately, gives it "a contact email field:
-- which will set by installing user for future communications by email".
-- Two different things: one is how you sign in, the other is where the product
-- writes to you. Measured before this landed, the site_admin payload carried
-- `email` and `email_verified` and nothing else email-shaped.
--
-- The column lands on every user rather than on the site_admin alone: a
-- single-row exception would need its own guard, and an ordinary user with a
-- null contact_email costs nothing.
--
-- Nullable by design — unset until an installer supplies it.
--
-- +goose Up
-- +goose StatementBegin
ALTER TABLE users ADD COLUMN IF NOT EXISTS contact_email VARCHAR(255);

COMMENT ON COLUMN users.contact_email IS
    'Operator-supplied address for product communications. SEPARATE from email, which is the login identifier. Nullable until an installer sets it.';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE users DROP COLUMN IF EXISTS contact_email;
-- +goose StatementEnd
