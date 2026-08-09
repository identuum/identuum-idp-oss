-- Identuum IdP OSS — Signing Keys & Async Job Queue
-- Clean consolidated open-core migration. Authored fresh from the core
-- portion of monolith 0004. Deliberately omits all commercial subsystems
-- that were folded into monolith 0004:
--   audit_events + audit_chain_tail + audit RULE/trigger/function (CE audit)
--   system_backups + organization_backups + organization_backup_restore_jobs (CE backup)
--   compliance_attestations (CE compliance)
--   webhook_endpoints + webhook_outbox (CE webhook)
--
-- Targets: signing_keys, jobs.

-- +goose Up

-- ============================================================================
-- SIGNING_KEYS
-- ============================================================================
-- Backs the OSS KeyRepository. Stores key material for OIDC token signing,
-- audit chain head signing, and other crypto-primitive uses. Lifecycle:
-- active → rotating → deprecated.
CREATE TABLE signing_keys (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    kid VARCHAR(255) NOT NULL,
    algorithm VARCHAR(50) NOT NULL,
    private_key TEXT NOT NULL,
    public_key TEXT NOT NULL,
    state VARCHAR(50) NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    activated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    rotated_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    created_by VARCHAR(255),

    CONSTRAINT chk_signing_key_state CHECK (state IN ('active', 'rotating', 'deprecated'))
);

-- ============================================================================
-- JOBS  (background async job queue)
-- ============================================================================
-- Backs the OSS JobRepository (§2.13 job queue). status lifecycle:
-- queued → running → completed | failed. Partial index on (status='queued',
-- created_at) is the critical dispatch hot-path.
CREATE TABLE jobs (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    type VARCHAR(64) NOT NULL,
    status VARCHAR(16) NOT NULL CHECK (status IN ('queued','running','completed','failed')),
    payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    result JSONB,
    created_by_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    deleted_at TIMESTAMPTZ
);

CREATE INDEX idx_jobs_queued_created ON jobs(created_at) WHERE status = 'queued' AND deleted_at IS NULL;
CREATE INDEX idx_jobs_org_created ON jobs(organization_id, created_at DESC) WHERE deleted_at IS NULL;

-- +goose Down
DROP TABLE IF EXISTS jobs CASCADE;
DROP TABLE IF EXISTS signing_keys CASCADE;
