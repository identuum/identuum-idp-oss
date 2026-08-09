-- identuum-idp-oss — AdminPermissionsModel.md enforced AT THE DATABASE.
--
-- The service layer already refuses each of these. The database did not, and
-- that gap is not theoretical: anything writing SQL directly — a migration, a
-- support script, a restore, a psql session — walked straight through. Measured
-- on a live database, with the service guards in place:
--
--     update organizations set name='HACKED' where id='…0000';   →  UPDATE 1
--     delete from organizations where id='…0000';                →  DELETE 1
--
-- and the delete CASCADED, taking the site_admin with it. One statement
-- destroyed the installation.
--
-- A guard in one layer is a guard one layer deep. These rules are described by
-- the model as "final and concrete", so they belong where nothing can route
-- around them.
--
-- +goose Up
-- +goose StatementBegin

-- ── R2: every user belongs to an organization ───────────────────────────────
-- "Each user MUST be a part of an organization." organization_id was nullable,
-- so an orphaned user was one INSERT away.
UPDATE users SET organization_id = '00000000-0000-7000-0000-000000000000'
WHERE organization_id IS NULL AND role = 'site_admin';

DO $$
DECLARE orphans bigint;
BEGIN
    SELECT count(*) INTO orphans FROM users WHERE organization_id IS NULL;
    IF orphans > 0 THEN
        RAISE EXCEPTION
            'cannot enforce users.organization_id NOT NULL: % user(s) belong to no organization. The model requires every user to be in one; assign them before upgrading rather than having this migration guess.',
            orphans;
    END IF;
END $$;

ALTER TABLE users ALTER COLUMN organization_id SET NOT NULL;

-- ── R9: the System organization can be neither renamed nor deleted ──────────
CREATE OR REPLACE FUNCTION model_protect_system_org() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'the System organization cannot be deleted (AdminPermissionsModel.md); deleting it destroys the site_admin''s own organization and bricks the installation';
    END IF;
    IF NEW.name IS DISTINCT FROM OLD.name THEN
        RAISE EXCEPTION 'the System organization cannot be renamed (AdminPermissionsModel.md): name is pinned to %', OLD.name;
    END IF;
    IF NEW.org_slug IS DISTINCT FROM OLD.org_slug THEN
        RAISE EXCEPTION 'the System organization slug is pinned to % (AdminPermissionsModel.md)', OLD.org_slug;
    END IF;
    IF NEW.id IS DISTINCT FROM OLD.id THEN
        RAISE EXCEPTION 'the System organization id is a reserved sentinel and cannot change';
    END IF;
    RETURN NEW;
END $$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_model_protect_system_org ON organizations;
CREATE TRIGGER trg_model_protect_system_org
    BEFORE UPDATE OR DELETE ON organizations
    FOR EACH ROW
    WHEN (OLD.id = '00000000-0000-7000-0000-000000000000'::uuid)
    EXECUTE FUNCTION model_protect_system_org();

-- ── R10: the site_admin cannot be deleted ───────────────────────────────────
CREATE OR REPLACE FUNCTION model_protect_site_admin() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'the site_admin cannot be deleted (AdminPermissionsModel.md): "site_admin CANNOT be deleted and there can only be site_admin user"';
END $$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_model_protect_site_admin ON users;
CREATE TRIGGER trg_model_protect_site_admin
    BEFORE DELETE ON users
    FOR EACH ROW
    WHEN (OLD.id = '00000000-0000-7000-0000-000000000001'::uuid)
    EXECUTE FUNCTION model_protect_site_admin();

-- ── R11: exactly ONE site_admin ─────────────────────────────────────────────
-- A partial unique index over a constant: at most one LIVE site_admin row can
-- exist. Soft-deleted rows are excluded so a historical row never blocks the
-- live one. This is the schema saying "only", not a service remembering to ask.
CREATE UNIQUE INDEX IF NOT EXISTS uq_model_single_site_admin
    ON users ((true))
    WHERE role = 'site_admin' AND deleted_at IS NULL;

-- ── R3: only the site_admin may be a member of the System organization ──────
ALTER TABLE users DROP CONSTRAINT IF EXISTS chk_model_system_org_members;
ALTER TABLE users ADD CONSTRAINT chk_model_system_org_members
    CHECK (
        organization_id <> '00000000-0000-7000-0000-000000000000'::uuid
        OR role = 'site_admin'
    );
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TRIGGER IF EXISTS trg_model_protect_system_org ON organizations;
DROP TRIGGER IF EXISTS trg_model_protect_site_admin ON users;
DROP FUNCTION IF EXISTS model_protect_system_org();
DROP FUNCTION IF EXISTS model_protect_site_admin();
DROP INDEX IF EXISTS uq_model_single_site_admin;
ALTER TABLE users DROP CONSTRAINT IF EXISTS chk_model_system_org_members;
ALTER TABLE users ALTER COLUMN organization_id DROP NOT NULL;
-- +goose StatementEnd
