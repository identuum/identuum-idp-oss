-- identuum-idp-oss — an API resource's audience is unique across the whole
-- installation (H7).
--
-- Until now only (org_id, audience) was unique, while token issuance and the
-- audience lookup resolve an audience globally, so two organizations holding the
-- same audience made the answer depend on row order. The index below makes the
-- lookup single-valued.
--
-- If two resources already share an audience, this migration stops and names
-- them. It does not choose a survivor and does not rename anything: a resource
-- server validates the audience it is given, so the operator decides which
-- organization keeps it. Rename or delete all but one, then migrate again.

-- +goose Up

-- +goose StatementBegin
DO $$
DECLARE
    dup text;
BEGIN
    SELECT string_agg(audience, ', ') INTO dup
      FROM (SELECT audience FROM api_resources GROUP BY audience HAVING count(*) > 1 ORDER BY audience LIMIT 10) d;
    IF dup IS NOT NULL THEN
        RAISE EXCEPTION 'api_resources: audience held by more than one resource: %. Rename or delete all but one, then migrate again.', dup;
    END IF;
END
$$;
-- +goose StatementEnd

CREATE UNIQUE INDEX uq_api_resources_audience ON api_resources (audience);

-- +goose Down

DROP INDEX IF EXISTS uq_api_resources_audience;
