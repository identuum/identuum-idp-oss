-- Identuum IdP OSS — Organization Domains
-- Clean consolidated open-core migration. Authored from monolith 0019 (the
-- final-state organization_domains slice) with unchanged content; the
-- monolith trigger reuses the set_organizations_updated_at() function
-- defined in OSS 0001.
--
-- Introduces a per-organization domains table so future slices can support
-- multi-domain ownership and DNS-style proof-of-control verification. This
-- migration does NOT change any current behavior: organizations.domain
-- remains the legacy public discovery key. The backfill seeds one verified
-- primary row per existing organization so the table is consistent from
-- day one.

-- +goose Up

-- Case-insensitive matching on domain is required for both equality
-- lookups and global-uniqueness enforcement. citext is the minimal-
-- overhead Postgres extension that gives us that without sprinkling
-- LOWER() across every call site.
CREATE EXTENSION IF NOT EXISTS citext;

CREATE TABLE organization_domains (
    id                              UUID PRIMARY KEY DEFAULT uuidv7(),
    organization_id                 UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    domain                          CITEXT NOT NULL,
    is_primary                      BOOLEAN NOT NULL DEFAULT false,
    verified_at                     TIMESTAMPTZ,
    verification_token_hash         TEXT,
    verification_token_expires_at   TIMESTAMPTZ,
    verification_attempts           INTEGER NOT NULL DEFAULT 0,
    created_at                      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at                      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_org_domain_not_empty
        CHECK (length(trim(domain::text)) > 0),
    CONSTRAINT chk_org_domain_verification_attempts_nonneg
        CHECK (verification_attempts >= 0)
);

-- A given (organization, domain) pair can appear only once. Guards against
-- duplicate pending claims for the same string within a single org and is
-- enforced independent of verification state.
ALTER TABLE organization_domains
    ADD CONSTRAINT uq_org_domains_org_domain UNIQUE (organization_id, domain);

-- A verified domain is unique across the entire deployment. Two orgs may
-- both have an unverified pending claim for the same string (only one of
-- them can ever verify it), but at most one org may hold the verified
-- record at any time. Implemented as a partial unique index so unverified
-- rows are unaffected.
CREATE UNIQUE INDEX uq_org_domains_verified_domain
    ON organization_domains (domain)
    WHERE verified_at IS NOT NULL;

-- Each organization can mark at most one row as the primary domain.
CREATE UNIQUE INDEX uq_org_domains_one_primary_per_org
    ON organization_domains (organization_id)
    WHERE is_primary = true;

CREATE INDEX idx_org_domains_organization_id
    ON organization_domains (organization_id);

CREATE INDEX idx_org_domains_domain
    ON organization_domains (domain);

-- Supports a future cleanup job that expires stale verification tokens.
CREATE INDEX idx_org_domains_verification_expires
    ON organization_domains (verification_token_expires_at)
    WHERE verification_token_hash IS NOT NULL;

CREATE TRIGGER trg_organization_domains_updated_at
    BEFORE UPDATE ON organization_domains
    FOR EACH ROW EXECUTE FUNCTION set_organizations_updated_at();

-- Backfill: seed one verified primary row per existing organization from
-- the legacy organizations.domain value. The System Organization
-- (system.local) is intentionally included so the table is the single
-- source of truth from day one.
INSERT INTO organization_domains (
    organization_id,
    domain,
    is_primary,
    verified_at,
    created_at,
    updated_at
)
SELECT
    o.id,
    o.domain,
    true,
    NOW(),
    o.created_at,
    o.updated_at
FROM organizations o
WHERE o.domain IS NOT NULL
  AND length(trim(o.domain)) > 0;

-- +goose Down
DROP TRIGGER IF EXISTS trg_organization_domains_updated_at ON organization_domains;
DROP INDEX IF EXISTS idx_org_domains_verification_expires;
DROP INDEX IF EXISTS idx_org_domains_domain;
DROP INDEX IF EXISTS idx_org_domains_organization_id;
DROP INDEX IF EXISTS uq_org_domains_one_primary_per_org;
DROP INDEX IF EXISTS uq_org_domains_verified_domain;
DROP TABLE IF EXISTS organization_domains;
