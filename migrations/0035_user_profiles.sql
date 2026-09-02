-- identuum-idp-oss — OIDC standard profile claims (THE-PROFILE-CLAIMS).
--
-- Owner ruled the full profile: given_name, family_name, middle_name,
-- nickname, preferred_username, profile, picture, website, gender,
-- birthdate, zoneinfo, locale (OIDC Core §5.1). Every field is OPTIONAL and
-- an unset field is NEVER emitted — no placeholders, ever. `name` stays on
-- users.name; `updated_at` for the `profile` scope is the later of
-- users.updated_at and this row's updated_at.
--
-- A side table rather than 12 columns on users: the users table has three
-- scanners and ~17 explicit-column SELECT/RETURNING sites; profile data is
-- an OIDC concern read by userinfo/id_token/profile surfaces only. One row
-- per user, created on first write, removed with the user.
--
-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS user_profiles (
    user_id            UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    given_name         TEXT,
    family_name        TEXT,
    middle_name        TEXT,
    nickname           TEXT,
    preferred_username TEXT,
    profile            TEXT,
    picture            TEXT,
    website            TEXT,
    gender             TEXT,
    birthdate          TEXT,
    zoneinfo           TEXT,
    locale             TEXT,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS user_profiles;
-- +goose StatementEnd
