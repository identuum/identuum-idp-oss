-- Identuum IdP OSS — Single-Replica Instance Lease (A-2a)
--
-- OSS is single-replica BY DESIGN. Horizontal scaling / HA is a
-- Professional+ commercial capability. The OSS process holds
-- per-process security state that is CORRECT for one replica but
-- SILENTLY BROKEN across replicas:
--
--   * rate limiting is an in-process token-bucket map
--     (internal/mw/rate_limit.go `buckets map[string]*tokenBucket`),
--     so N replicas grant N× every mounted limit;
--   * WebAuthn ceremony state is an in-process map
--     (repository.InMemoryWebAuthnSessionRepository), so a ceremony
--     begun on replica A cannot finish on replica B;
--   * the browser CSRF secret is a fresh 32-byte random value
--     generated PER PROCESS at startup (runtime.go), so replicas
--     cannot validate each other's tokens.
--
-- This table is the enforcement point: a singleton lease row that
-- exactly one live instance may hold. On startup an instance ACQUIRES
-- the lease atomically (see PgxInstanceLeaseRepository.TryAcquire) and
-- HEARTBEATS it periodically; an instance that cannot acquire a live
-- lease REFUSES TO SERVE (P-018 NOT-SERVING-JUST-ALERTING) rather than
-- serving with broken per-process security. The heartbeat TTL enables
-- rolling deploys: the outgoing pod stops heartbeating (or releases the
-- row on graceful shutdown), its lease lapses, and the incoming pod
-- takes over.
--
-- Singleton discipline mirrors system_setup_state (migration 0019):
-- the CHECK on id pins every installation to exactly one addressable
-- row (the reserved UUIDv7-zero sentinel
-- 00000000-0000-7000-0000-000000000020 = domain.InstanceLeaseSingletonID).
-- Unlike system_setup_state the row is NOT pre-seeded: the first
-- acquirer INSERTs it via INSERT ... ON CONFLICT so the acquire path is
-- a single atomic statement with no read-modify-write window.
--
-- instance_id is TEXT (not UUID) so it can carry an operator-friendly
-- "<hostname>/<uuid>" identity that names the incumbent in the loser's
-- ERROR log. It is NOT a secret.

-- +goose Up
-- +goose StatementBegin
CREATE TABLE instance_lease (
    id            UUID        PRIMARY KEY,
    instance_id   TEXT        NOT NULL,
    acquired_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    heartbeat_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT instance_lease_singleton CHECK (id = '00000000-0000-7000-0000-000000000020'::uuid)
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS instance_lease;
-- +goose StatementEnd
