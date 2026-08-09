-- +goose Up
-- +goose StatementBegin
--
-- `system_setup_state` — single-row record of first-run setup progress.
--
-- The IDP binary is the authority for first-run setup per the appliance
-- install UX decisions (D-IDP-INSTALL-09). On a fresh database the row
-- carries status='setup_required' with a NULL token hash; the binary
-- generates the setup token at first boot, writes the plaintext to
-- $DATA_DIR/setup-token.txt (mode 0600) for the wizard, and stores
-- only the SHA-256 hash here. On wizard completion the row flips to
-- status='setup_complete', the token hash is cleared, and the
-- /api/setup/* endpoints (except status) start refusing as 410 Gone.
--
-- The CHECK on id enforces a true singleton: every installation has
-- exactly one row, addressable by the reserved UUIDv7-zero sentinel
-- 00000000-0000-7000-0000-000000000010 (= domain.SetupStateSingletonID).
-- The pre-seed INSERT is idempotent (ON CONFLICT DO NOTHING) so a
-- re-run of this migration on a pre-seeded database is a no-op.
--
CREATE TABLE system_setup_state (
    id                     UUID        PRIMARY KEY,
    status                 VARCHAR(32) NOT NULL,
    setup_token_hash       VARCHAR(64),
    setup_token_created_at TIMESTAMPTZ,
    completed_at           TIMESTAMPTZ,
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT system_setup_state_singleton CHECK (id = '00000000-0000-7000-0000-000000000010'::uuid),
    CONSTRAINT system_setup_state_status_valid CHECK (status IN ('setup_required', 'setup_complete'))
);

INSERT INTO system_setup_state (id, status)
VALUES ('00000000-0000-7000-0000-000000000010', 'setup_required')
ON CONFLICT (id) DO NOTHING;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS system_setup_state;
-- +goose StatementEnd
