-- identuum-idp-oss — AgentCommunicationAuthorization foundation (AYGHU-1).
--
-- An owner authorizes exactly two of their own agent identities (service
-- accounts installed as private_key_jwt OAuth clients) to communicate
-- through a relay for one bounded session. The IdP allocates the
-- authorization id, the session id and one opaque Agent Communication
-- Identifier (ACI) per participant; every identifier is a UUIDv7. An ACI is
-- an address, never a credential — nothing secret is stored here.
--
-- The structural invariants of internal/domain/agent_communication_authorization.go
-- are reinforced below so a direct write cannot produce an invalid row:
-- closed role set, closed capability vocabulary, positive limits, future
-- expiry, unique session id, globally unique ACI, distinct roles / service
-- accounts per authorization, revocation shape, and — via a deferred
-- constraint trigger checked at COMMIT — exactly two participants per
-- authorization. Participants are immutable; on the authorization only the
-- three revocation columns may change, and only once (revocation is terminal).

-- +goose Up

CREATE TABLE agent_communication_authorizations (
    id                      UUID PRIMARY KEY,
    organization_id         UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    owner_user_id           UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    session_id              UUID NOT NULL,
    relay_audience          TEXT NOT NULL,
    max_messages            INTEGER NOT NULL,
    max_message_size_bytes  BIGINT NOT NULL,
    expires_at              TIMESTAMPTZ NOT NULL,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at              TIMESTAMPTZ NULL,
    revoked_by              UUID NULL REFERENCES users(id) ON DELETE SET NULL,
    revocation_reason       TEXT NULL,
    policy_version          TEXT NOT NULL,
    policy_digest           TEXT NOT NULL,
    CONSTRAINT uq_aca_session_id UNIQUE (session_id),
    CONSTRAINT aca_relay_audience_check CHECK (length(relay_audience) BETWEEN 1 AND 512),
    CONSTRAINT aca_max_messages_check CHECK (max_messages > 0),
    CONSTRAINT aca_max_message_size_bytes_check CHECK (max_message_size_bytes > 0),
    CONSTRAINT aca_expires_after_created_check CHECK (expires_at > created_at),
    CONSTRAINT aca_policy_version_check CHECK (policy_version = 'v1'),
    CONSTRAINT aca_policy_digest_check CHECK (policy_digest ~ '^[0-9a-f]{64}$'),
    CONSTRAINT aca_revocation_reason_check CHECK (revocation_reason IS NULL OR length(revocation_reason) BETWEEN 1 AND 256),
    CONSTRAINT aca_revocation_shape_check CHECK (
        (revoked_at IS NULL AND revoked_by IS NULL AND revocation_reason IS NULL)
        OR revoked_at IS NOT NULL
    )
);

CREATE INDEX idx_aca_organization_created ON agent_communication_authorizations (organization_id, created_at DESC);
CREATE INDEX idx_aca_owner_user_id ON agent_communication_authorizations (owner_user_id);
CREATE INDEX idx_aca_expires_at ON agent_communication_authorizations (expires_at) WHERE revoked_at IS NULL;

CREATE TABLE agent_communication_participants (
    id                      UUID PRIMARY KEY,
    authorization_id        UUID NOT NULL REFERENCES agent_communication_authorizations(id) ON DELETE CASCADE,
    aci                     UUID NOT NULL,
    service_account_id      UUID NOT NULL REFERENCES service_accounts(id) ON DELETE RESTRICT,
    oauth_client_id         UUID NOT NULL REFERENCES oauth_clients(id) ON DELETE RESTRICT,
    role                    TEXT NOT NULL,
    proof_key_thumbprint    TEXT NOT NULL,
    capabilities            TEXT[] NOT NULL DEFAULT '{}',
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_acp_aci UNIQUE (aci),
    CONSTRAINT uq_acp_authorization_role UNIQUE (authorization_id, role),
    CONSTRAINT uq_acp_authorization_service_account UNIQUE (authorization_id, service_account_id),
    CONSTRAINT uq_acp_authorization_client UNIQUE (authorization_id, oauth_client_id),
    CONSTRAINT acp_role_check CHECK (role IN ('initiator', 'responder')),
    CONSTRAINT acp_proof_key_thumbprint_check CHECK (length(proof_key_thumbprint) BETWEEN 1 AND 128),
    CONSTRAINT acp_capabilities_vocabulary_check CHECK (
        capabilities <@ ARRAY[
            'command.execute',
            'communication.discuss',
            'network.access',
            'report.final.required',
            'repository.read',
            'repository.write',
            'test.execute'
        ]::TEXT[]
    )
);

CREATE INDEX idx_acp_service_account_id ON agent_communication_participants (service_account_id);
CREATE INDEX idx_acp_oauth_client_id ON agent_communication_participants (oauth_client_id);

-- Exactly two participants per authorization, checked once at COMMIT for
-- every authorization touched in the transaction (insert of the
-- authorization, insert/delete/re-parenting of a participant). An
-- authorization that no longer exists (cascade delete) has nothing to count.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION agent_communication_enforce_two_participants()
RETURNS TRIGGER AS $$
DECLARE
    target UUID;
    n INTEGER;
BEGIN
    IF TG_TABLE_NAME = 'agent_communication_authorizations' THEN
        target := NEW.id;
    ELSIF TG_OP = 'DELETE' THEN
        target := OLD.authorization_id;
    ELSE
        target := NEW.authorization_id;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM agent_communication_authorizations WHERE id = target) THEN
        RETURN NULL;
    END IF;
    SELECT COUNT(*) INTO n FROM agent_communication_participants WHERE authorization_id = target;
    IF n <> 2 THEN
        RAISE EXCEPTION 'agent communication authorization % must have exactly two participants (has %)', target, n
            USING ERRCODE = 'check_violation', CONSTRAINT = 'aca_two_participants';
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

CREATE CONSTRAINT TRIGGER trg_aca_two_participants
    AFTER INSERT ON agent_communication_authorizations
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION agent_communication_enforce_two_participants();

CREATE CONSTRAINT TRIGGER trg_acp_two_participants
    AFTER INSERT OR DELETE OR UPDATE OF authorization_id ON agent_communication_participants
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION agent_communication_enforce_two_participants();

-- Participants are immutable after creation (no widening, no editing).
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION agent_communication_participants_immutable()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'agent communication participant % is immutable', OLD.id
        USING ERRCODE = 'check_violation', CONSTRAINT = 'acp_immutable';
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

CREATE TRIGGER trg_acp_immutable
    BEFORE UPDATE ON agent_communication_participants
    FOR EACH ROW EXECUTE FUNCTION agent_communication_participants_immutable();

-- The authorization may change ONLY through its revocation columns, and a
-- revoked row never changes again (revocation is terminal).
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION agent_communication_authorizations_revocation_only()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.id IS DISTINCT FROM OLD.id
        OR NEW.organization_id IS DISTINCT FROM OLD.organization_id
        OR NEW.owner_user_id IS DISTINCT FROM OLD.owner_user_id
        OR NEW.session_id IS DISTINCT FROM OLD.session_id
        OR NEW.relay_audience IS DISTINCT FROM OLD.relay_audience
        OR NEW.max_messages IS DISTINCT FROM OLD.max_messages
        OR NEW.max_message_size_bytes IS DISTINCT FROM OLD.max_message_size_bytes
        OR NEW.expires_at IS DISTINCT FROM OLD.expires_at
        OR NEW.created_at IS DISTINCT FROM OLD.created_at
        OR NEW.policy_version IS DISTINCT FROM OLD.policy_version
        OR NEW.policy_digest IS DISTINCT FROM OLD.policy_digest THEN
        RAISE EXCEPTION 'agent communication authorization % may only be revoked', OLD.id
            USING ERRCODE = 'check_violation', CONSTRAINT = 'aca_revocation_only';
    END IF;
    IF OLD.revoked_at IS NOT NULL AND (
        NEW.revoked_at IS DISTINCT FROM OLD.revoked_at
        OR NEW.revoked_by IS DISTINCT FROM OLD.revoked_by
        OR NEW.revocation_reason IS DISTINCT FROM OLD.revocation_reason) THEN
        RAISE EXCEPTION 'agent communication authorization % revocation is terminal', OLD.id
            USING ERRCODE = 'check_violation', CONSTRAINT = 'aca_revocation_terminal';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

CREATE TRIGGER trg_aca_revocation_only
    BEFORE UPDATE ON agent_communication_authorizations
    FOR EACH ROW EXECUTE FUNCTION agent_communication_authorizations_revocation_only();

-- +goose Down

DROP TRIGGER IF EXISTS trg_aca_revocation_only ON agent_communication_authorizations;
DROP FUNCTION IF EXISTS agent_communication_authorizations_revocation_only();
DROP TRIGGER IF EXISTS trg_acp_immutable ON agent_communication_participants;
DROP FUNCTION IF EXISTS agent_communication_participants_immutable();
DROP TRIGGER IF EXISTS trg_acp_two_participants ON agent_communication_participants;
DROP TRIGGER IF EXISTS trg_aca_two_participants ON agent_communication_authorizations;
DROP FUNCTION IF EXISTS agent_communication_enforce_two_participants();
DROP TABLE IF EXISTS agent_communication_participants;
DROP TABLE IF EXISTS agent_communication_authorizations;
