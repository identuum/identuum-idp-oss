-- identuum-idp-oss — OIDC address and phone claims (THE-ADDRESS-PHONE-CLAIMS).
--
-- OIDC Core §5.1 phone_number and the §5.1.1 structured address claim
-- (formatted, street_address, locality, region, postal_code, country), as
-- OPTIONAL columns beside the profile fields on user_profiles (0035). NULL =
-- unset = never emitted; the `address` object is emitted only when at least
-- one member is set and carries only set members. phone_number_verified is
-- NOT stored: identuum has no phone verification event, so it is always
-- false and derived at emission time, alongside phone_number only. Same
-- table, same cascade, same one-row-per-user shape.

-- +goose Up
-- +goose StatementBegin
ALTER TABLE user_profiles
    ADD COLUMN IF NOT EXISTS phone_number           TEXT NULL,
    ADD COLUMN IF NOT EXISTS address_formatted      TEXT NULL,
    ADD COLUMN IF NOT EXISTS address_street_address TEXT NULL,
    ADD COLUMN IF NOT EXISTS address_locality       TEXT NULL,
    ADD COLUMN IF NOT EXISTS address_region         TEXT NULL,
    ADD COLUMN IF NOT EXISTS address_postal_code    TEXT NULL,
    ADD COLUMN IF NOT EXISTS address_country        TEXT NULL;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE user_profiles
    DROP COLUMN IF EXISTS phone_number,
    DROP COLUMN IF EXISTS address_formatted,
    DROP COLUMN IF EXISTS address_street_address,
    DROP COLUMN IF EXISTS address_locality,
    DROP COLUMN IF EXISTS address_region,
    DROP COLUMN IF EXISTS address_postal_code,
    DROP COLUMN IF EXISTS address_country;
-- +goose StatementEnd
