-- identuum-idp-oss — a deleted organization releases its API resources'
-- audiences.
--
-- Migration 0045 made an API resource's audience unique across the whole
-- installation, and the organization soft delete left api_resources alone,
-- so a deleted organization's resource kept its audience for good: no
-- organization could register it again and no route could remove it (a
-- site_admin does not manage a tenant's resources, and a deleted
-- organization has no admin). The soft delete now stamps deleted_at on the
-- organization's resources (the same instant as on the organization, so a
-- restore brings back exactly those), and the audience index counts only the
-- resources that are not deleted. Rows of organizations already deleted are
-- stamped here with their organization's deleted_at.

-- +goose Up

ALTER TABLE api_resources ADD COLUMN deleted_at TIMESTAMPTZ;

UPDATE api_resources ar
SET deleted_at = o.deleted_at
FROM organizations o
WHERE o.id = ar.org_id AND o.deleted_at IS NOT NULL;

DROP INDEX IF EXISTS uq_api_resources_audience;
CREATE UNIQUE INDEX uq_api_resources_audience ON api_resources (audience) WHERE deleted_at IS NULL;

-- +goose Down

DROP INDEX IF EXISTS uq_api_resources_audience;
CREATE UNIQUE INDEX uq_api_resources_audience ON api_resources (audience);
ALTER TABLE api_resources DROP COLUMN IF EXISTS deleted_at;
