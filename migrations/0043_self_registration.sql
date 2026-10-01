-- identuum-idp-oss — self-registration (D-021, OSS-REGISTER-API).
--
-- Two switches, both OFF by default. The instance switch (site_admin) is the
-- ceiling; under it an organization's existing allow_public_registration
-- (org_admin) opens sign-up, require_registration_approval (existing) holds a
-- registrant for an org_admin, and the new registration_verify_email
-- requires the emailed link before the first sign-in. An organization may
-- restrict sign-up to email domains.
--
-- users.registration_state marks a self-registrant: 'pending_approval' or
-- 'active'. NULL for every other user, so every existing row keeps today's
-- sign-in gate exactly (owner ruling b).
--
-- Additive only: no existing column or row changes.

-- +goose Up

CREATE TABLE instance_settings (
    id                        UUID        PRIMARY KEY,
    self_registration_enabled BOOLEAN     NOT NULL DEFAULT false,
    updated_at                TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT instance_settings_singleton CHECK (id = '00000000-0000-7000-0000-000000000020'::uuid)
);

INSERT INTO instance_settings (id) VALUES ('00000000-0000-7000-0000-000000000020');

ALTER TABLE organizations
    ADD COLUMN registration_verify_email  BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN registration_email_domains TEXT[]  NOT NULL DEFAULT '{}';

ALTER TABLE users
    ADD COLUMN registration_state TEXT
        CONSTRAINT users_registration_state_valid CHECK (registration_state IN ('pending_approval', 'active'));

CREATE INDEX idx_users_registration_pending
    ON users (organization_id) WHERE registration_state = 'pending_approval';

-- +goose Down

DROP INDEX IF EXISTS idx_users_registration_pending;

ALTER TABLE users DROP COLUMN IF EXISTS registration_state;

ALTER TABLE organizations
    DROP COLUMN IF EXISTS registration_email_domains,
    DROP COLUMN IF EXISTS registration_verify_email;

DROP TABLE IF EXISTS instance_settings;
