-- +goose Up
-- +goose StatementBegin

-- backchannel_logout_deliveries records every back-channel
-- logout-token POST attempt. The table NEVER stores the raw
-- logout_token bytes — only its JTI (which is safe to log per
-- RFC 7519 — JWT IDs are random and carry no claim payload).
-- The audit row + this table together let operators answer
-- "did this RP receive a logout for this user?" without
-- replaying the signed token.
CREATE TABLE backchannel_logout_deliveries (
    id              UUID PRIMARY KEY,
    client_id       TEXT NOT NULL,
    session_id      UUID,
    user_id         UUID,
    logout_jti      TEXT NOT NULL,
    status          TEXT NOT NULL,
    http_status     INTEGER,
    attempt_count   INTEGER NOT NULL DEFAULT 0,
    last_error      TEXT NOT NULL DEFAULT '',
    next_attempt_at TIMESTAMPTZ,
    delivered_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_backchannel_logout_deliveries_status
    ON backchannel_logout_deliveries(status);
CREATE INDEX idx_backchannel_logout_deliveries_next_attempt_at
    ON backchannel_logout_deliveries(next_attempt_at)
    WHERE next_attempt_at IS NOT NULL;
CREATE INDEX idx_backchannel_logout_deliveries_client_id
    ON backchannel_logout_deliveries(client_id);
CREATE INDEX idx_backchannel_logout_deliveries_created_at
    ON backchannel_logout_deliveries(created_at);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS backchannel_logout_deliveries;
-- +goose StatementEnd
