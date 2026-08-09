-- +goose Up
-- +goose StatementBegin
--
-- Drop the dead `oauth_par_requests` table (+ its index). The OSS PAR
-- (RFC 9126 Pushed Authorization Requests) code was removed in 78dffcc;
-- this table + index were the only remaining residue — no OSS repository,
-- service, or handler reads or writes it.
--
-- CE SAFETY: this cannot affect the CE overlay. CE's PAR uses its OWN
-- independently-migrated table `pushed_authorization_requests` (different
-- name, no FK to any OSS table), and CE runs on a SEPARATE goose ledger
-- (goose_db_version_ce) that layers on top and never re-runs OSS
-- migrations. CE references `oauth_par_requests` nowhere.
--
-- SCOPE: only `oauth_par_requests` is dropped. `oidc_states` (created in
-- the same 0002 migration) is LIVE — it backs the shipped upstream-OIDC
-- login seam — and is explicitly KEPT.
--
DROP TABLE IF EXISTS oauth_par_requests CASCADE;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
--
-- Reversible per the repo convention (every migration has an inverse Down;
-- there is no irreversible-drop precedent). Recreate the table + index
-- verbatim from the original 0002_oauth_oidc.sql definition. The FK to
-- oauth_clients(client_id) is valid on rollback: oauth_clients (0001) is
-- untouched by this migration.
--
CREATE TABLE oauth_par_requests (
    request_uri VARCHAR(255) PRIMARY KEY,
    client_id VARCHAR(255) NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
    request_object JSONB NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_oauth_par_expires_at ON oauth_par_requests(expires_at);
-- +goose StatementEnd
