-- identuum-idp-oss — per-client id_token_signed_response_alg
-- (THE-PKCE-DECISION, ruling 2).
--
-- Owner ruling, verbatim: "Add RS256 into the list BUT DO NOT USE except
-- testing and put this into documentation CLEARLY."
--
-- RS256 becomes a REAL id_token signing capability so the discovery
-- document's id_token_signing_alg_values_supported list is honest — but it
-- fires ONLY when a client explicitly registers RS256 here. The issuer
-- default is, and stays, EdDSA: this column defaults to 'EdDSA', the
-- key-selection default path never picks an RSA key, and
-- AutoGenerateInitialKey never generates one. RS256 exists for
-- conformance/interop TESTING, not operation (docs/TESTING-OPERATORS.md).
--
-- The CHECK set must stay in sync with domain.IDTokenSigningAlgorithms and
-- the discovery list in internal/api/router.go.
--
-- +goose Up
-- +goose StatementBegin
ALTER TABLE oauth_clients
    ADD COLUMN IF NOT EXISTS id_token_signed_response_alg TEXT NOT NULL DEFAULT 'EdDSA'
    CONSTRAINT chk_oauth_clients_id_token_alg
    CHECK (id_token_signed_response_alg IN ('EdDSA', 'ES256', 'RS256'));
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE oauth_clients
    DROP COLUMN IF EXISTS id_token_signed_response_alg;
-- +goose StatementEnd
