-- +goose Up
-- +goose StatementBegin

-- organization_protocol_settings is the org-scoped per-protocol
-- enable/disable configuration source consulted by the OSS DCR
-- and SCIM foundation handlers at request time.
--
-- Owner correction (2026-06-04): the protocol-availability source
-- of truth is per-organization DB state, NOT a global env
-- variable. The OSS scaffold's DCR + SCIM foundations remain in
-- OSS (per the open-core split decision); their availability is
-- gated per-organization here.
--
-- One row per organization. Both booleans default to FALSE so a
-- freshly created tenant has no protocol surface exposed until
-- the org_admin (or a site_admin) explicitly turns it on. An
-- organization with NO row at all is treated by the service
-- layer as "row absent → both effective false" — the column
-- defaults and the absent-row default are deliberately aligned
-- so the operator does not face a "table empty vs row missing"
-- distinction.
--
-- ON DELETE CASCADE removes the settings row when the underlying
-- organization is deleted, so no orphan settings can survive.
--
-- Columns are intentionally narrow. New protocol toggles
-- (LDAP, etc.) get their own columns here in future slices
-- rather than a generic key/value store, so each toggle's
-- semantics are inspectable in code and at the DB schema level.
CREATE TABLE organization_protocol_settings (
    organization_id UUID PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
    dcr_enabled     BOOLEAN NOT NULL DEFAULT FALSE,
    scim_enabled    BOOLEAN NOT NULL DEFAULT FALSE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS organization_protocol_settings;
-- +goose StatementEnd
