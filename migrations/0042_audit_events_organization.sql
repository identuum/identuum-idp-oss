-- identuum-idp-oss — the organization an audit row concerns (OSS-FIN-3).
--
-- audit_events.actor_organization_id took whatever organization the emitting
-- call site put on the event: the organization acted upon at some sites, the
-- actor's at others, none at most. An org_admin's view, clamped to that
-- column, therefore missed its own organization's user.* and org_role.*
-- rows, and every change a site_admin made to it.
--
-- organization_id is the organization ACTED UPON; actor_organization_id stays
-- the actor's own. The org_admin view reads organization_id (and, for rows
-- written before this migration, actor_organization_id as it always did).
--
-- Backfill: only where a row's metadata states the organization
-- unambiguously — a metadata "organization_id" naming an existing
-- organization, compared as text so a malformed value never fails a cast.
-- No other column of an existing row changes.

-- +goose Up

ALTER TABLE audit_events
    ADD COLUMN organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE;

CREATE INDEX idx_audit_events_organization_created_at
    ON audit_events (organization_id, created_at DESC);

UPDATE audit_events a
SET organization_id = o.id
FROM organizations o
WHERE a.organization_id IS NULL
  AND a.metadata ? 'organization_id'
  AND o.id::text = lower(a.metadata->>'organization_id');

-- +goose Down

DROP INDEX IF EXISTS idx_audit_events_organization_created_at;

ALTER TABLE audit_events DROP COLUMN IF EXISTS organization_id;
