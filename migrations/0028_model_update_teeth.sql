-- identuum-idp-oss — the UPDATE-shaped brick vectors 0027 left open (G1, G2).
--
-- 0027 put teeth on DELETE and on the System organization's name/slug/id. An
-- audit found the shape it did not cover, and both were REPRODUCED IN SQL at
-- HEAD a6840be before this migration was written:
--
--   G1  UPDATE organizations SET active=false     WHERE id='…0000';  → UPDATE 1
--       UPDATE organizations SET deleted_at=now() WHERE id='…0000';  → UPDATE 1
--
--   G2  UPDATE users SET banned=true              WHERE id='…0001';  → UPDATE 1
--       UPDATE users SET deleted_at=now()         WHERE id='…0001';  → UPDATE 1
--       UPDATE users SET role='org_user', organization_id='<tenant>'
--                                        WHERE id='…0001';           → UPDATE 1
--       …and after that last one: live site_admins = 0.
--
-- THAT LAST LINE IS THE WHOLE POINT. The installation was left with NO
-- site_admin at all, from one statement, past every Go guard and past 0027's
-- trigger. Suspending the System organization is the same class of fault: it
-- cascade-revokes every System-org session, the site_admin's included.
--
-- WHY THE EXISTING GUARDS MISSED IT. 0027's organization trigger compares
-- name, org_slug and id and returns NEW for anything else, so `active` and
-- `deleted_at` fell through a guard that was already running on the row. The
-- user trigger was BEFORE DELETE only, so every ban / demote / soft-delete went
-- around it. Both are UPDATE-shaped, and "cannot be deleted" was read as
-- "DELETE" when the model means the site_admin must not STOP EXISTING —
-- soft-deleting it is deleting it, and demoting it is worse, because the row
-- survives to look fine.
--
-- WHAT IS DELIBERATELY STILL ALLOWED: everything else about these rows. An
-- operator may change the site_admin's password, email, MFA state and contact
-- email; they may edit any other organization freely. Only the four columns
-- that decide whether infrastructure authority still EXISTS are pinned.
--
-- +goose Up
-- +goose StatementBegin

-- ── G1: the System organization may not be suspended or soft-deleted ────────
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
    -- NEW in 0028. Suspending the System organization revokes every session in
    -- it, and the site_admin lives there — so this is "cannot be deleted" by
    -- another spelling.
    IF NEW.active IS DISTINCT FROM OLD.active AND NEW.active IS NOT TRUE THEN
        RAISE EXCEPTION 'the System organization cannot be deactivated (AdminPermissionsModel.md): it holds the site_admin, and suspending it revokes that account''s sessions and locks the installation out of its own administration';
    END IF;
    IF NEW.deleted_at IS DISTINCT FROM OLD.deleted_at AND NEW.deleted_at IS NOT NULL THEN
        RAISE EXCEPTION 'the System organization cannot be soft-deleted (AdminPermissionsModel.md): a soft delete is a delete, and the model says this organization cannot be deleted';
    END IF;
    RETURN NEW;
END $$ LANGUAGE plpgsql;

-- ── G2: the sentinel site_admin may not be banned, demoted or soft-deleted ──
CREATE OR REPLACE FUNCTION model_protect_site_admin_update() RETURNS trigger AS $$
BEGIN
    -- REFUSE THE WRONG VALUE, NOT THE CHANGE. An earlier draft refused any role
    -- change at all, which made a row damaged through the old hole impossible to
    -- REPAIR: an installation whose site_admin had already been demoted was
    -- stuck there, with the new guard holding the damage in place. Found by
    -- teeth-proving this migration against a database that had been through the
    -- pre-fix vectors. Refusing incorrect values instead lets a repair through
    -- while still admitting no way to break a healthy row.
    IF NEW.role IS DISTINCT FROM 'site_admin' THEN
        RAISE EXCEPTION 'the site_admin cannot be demoted (AdminPermissionsModel.md): "site_admin CANNOT be deleted and there can only be site_admin user" — a demotion removes the only infrastructure authority in the installation just as surely as a delete would (attempted: % -> %)', OLD.role, NEW.role;
    END IF;
    IF NEW.deleted_at IS DISTINCT FROM OLD.deleted_at AND NEW.deleted_at IS NOT NULL THEN
        RAISE EXCEPTION 'the site_admin cannot be soft-deleted (AdminPermissionsModel.md): a soft delete is a delete';
    END IF;
    IF NEW.banned IS DISTINCT FROM OLD.banned AND NEW.banned IS TRUE THEN
        RAISE EXCEPTION 'the site_admin cannot be banned (AdminPermissionsModel.md): a banned site_admin cannot authenticate, which is a locked-out installation with extra steps';
    END IF;
    IF NEW.organization_id IS DISTINCT FROM '00000000-0000-7000-0000-000000000000'::uuid THEN
        RAISE EXCEPTION 'the site_admin cannot be moved out of the System organization (AdminPermissionsModel.md): only site_admin may be a member of it, and the site_admin belongs to it';
    END IF;
    RETURN NEW;
END $$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_model_protect_site_admin_update ON users;
CREATE TRIGGER trg_model_protect_site_admin_update
    BEFORE UPDATE ON users
    FOR EACH ROW
    WHEN (OLD.id = '00000000-0000-7000-0000-000000000001'::uuid)
    EXECUTE FUNCTION model_protect_site_admin_update();

-- Repair anything an operator already did through one of these holes, so an
-- upgrade lands on a model-conformant row rather than carrying the damage
-- forward silently. Each is a no-op on a healthy installation.
UPDATE organizations
   SET active = true, deleted_at = NULL
 WHERE id = '00000000-0000-7000-0000-000000000000'::uuid
   AND (active IS NOT TRUE OR deleted_at IS NOT NULL);

UPDATE users
   SET banned = false,
       deleted_at = NULL,
       role = 'site_admin',
       organization_id = '00000000-0000-7000-0000-000000000000'::uuid
 WHERE id = '00000000-0000-7000-0000-000000000001'::uuid
   AND (banned IS TRUE OR deleted_at IS NOT NULL
        OR role IS DISTINCT FROM 'site_admin'
        OR organization_id IS DISTINCT FROM '00000000-0000-7000-0000-000000000000'::uuid);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TRIGGER IF EXISTS trg_model_protect_site_admin_update ON users;
DROP FUNCTION IF EXISTS model_protect_site_admin_update();
-- The organization function is left as 0028 defines it: reverting it would
-- reopen a brick vector, and a Down that restores a defect is not a rollback.
-- +goose StatementEnd
