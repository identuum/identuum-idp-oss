-- Identuum IdP OSS — plain persistent audit log (queue L-2)
--
-- OSS gets a SIMPLE persistent audit log: events are written to this table
-- and pruned by a retention sweep. That is the whole feature.
--
-- What OSS DELIBERATELY does NOT get, because it is the commercial line:
--   - the per-org tamper-evident hash chain (prev_hash / entry_hash / chain
--     tail / head signing / KID) — computed at insert time by the CE service;
--   - DB-LEVEL append-only enforcement. There is intentionally NO RULE and NO
--     trigger on this table. Retention MUST be able to DELETE old rows, and
--     "you cannot delete or rewrite an audit row" is part of what CE sells
--     (its audit_events carries an append-only guard; audit_chain_tail and
--     audit_anomalies remain commercial-only tables). Making OSS rows
--     immutable here would give away that differentiator.
--
-- So this table is an ordinary, mutable, retention-pruned log. The event
-- shape mirrors internal/domain.AuditEvent; nullable columns take NULL when
-- the emitting audit.Event left the corresponding field zero (uuid.Nil / "").
-- metadata is an opaque JSON blob the caller controls — the audit pipeline
-- does not redact it, and callers must never put secret material in it.

-- outcome is the success/denied/error discriminator the emitter attaches
-- to an audit.Event (e.g. a DENIED MFA step-up vs a SUCCESSFUL one carry
-- the same event_type and differ only here). Nullable: NULL means the
-- emitter supplied no outcome.

-- +goose Up

CREATE TABLE audit_events (
    id                      UUID PRIMARY KEY,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    event_type              TEXT NOT NULL,
    outcome                 TEXT,
    actor_id                UUID,
    actor_type              TEXT NOT NULL,
    actor_email             TEXT,
    actor_role              TEXT,
    actor_organization_id   UUID REFERENCES organizations(id) ON DELETE CASCADE,
    subject_id              UUID,
    subject_type            TEXT,
    subject_email           TEXT,
    ip_address              INET,
    user_agent              TEXT,
    request_id              TEXT,
    correlation_id          TEXT,
    priority                TEXT NOT NULL DEFAULT 'normal',
    metadata                JSONB NOT NULL DEFAULT '{}'::jsonb
);

-- Newest-first scan (the natural read order for any future admin view) and
-- the retention sweep's created_at < cutoff prune.
CREATE INDEX idx_audit_events_created_at ON audit_events (created_at DESC);

-- Per-tenant, newest-first.
CREATE INDEX idx_audit_events_org_created_at
    ON audit_events (actor_organization_id, created_at DESC);

-- Per-event-type, newest-first.
CREATE INDEX idx_audit_events_type_created_at
    ON audit_events (event_type, created_at DESC);

-- +goose Down

DROP INDEX IF EXISTS idx_audit_events_type_created_at;
DROP INDEX IF EXISTS idx_audit_events_org_created_at;
DROP INDEX IF EXISTS idx_audit_events_created_at;
DROP TABLE IF EXISTS audit_events;
