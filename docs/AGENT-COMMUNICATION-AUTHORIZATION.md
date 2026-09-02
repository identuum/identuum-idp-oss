# AgentCommunicationAuthorization (AYGHU)

Authoritative specification: the owner-held AYGHU document (outside this
repository). This page records what each slice made real in
`identuum-idp-oss` and names the slices that are NOT built yet.

## Vocabulary

- **Owner** — the human user of an organization who authorizes two of
  their own agent identities to communicate.
- **Agent identity** — a service account. An OAuth client bound to that
  service account is an *installation* of the identity.
- **ACI** (Agent Communication Identifier) — an opaque UUIDv7 the IdP
  allocates per participant. It is an ADDRESS the relay and the later
  tokens refer to; it is never a credential, a key or a JWT.
- **Authorization** — one owner, one organization, exactly two
  participants (one `initiator`, one `responder`), one relay audience,
  one session id, session limits, an expiry, a capability policy and its
  canonical digest. States: `active`, `revoked` (terminal), `expired`
  (derived from `expires_at` at use time, never stored).

## AYGHU-1 FOUNDATION — built (this slice)

| Layer | Where | What |
|---|---|---|
| Domain | `internal/domain/agent_communication_authorization.go` | Aggregate + participant, closed role set, closed capability vocabulary (`communication.discuss`, `repository.read`, `repository.write`, `command.execute`, `test.execute`, `network.access`, `report.final.required`; no implication between members; unknown fails closed; empty = communication only), typed errors, `Validate`, relay-audience normalization, `CheckAgentCommunicationSameOwner`, `CheckAgentCommunicationParticipantClient`, canonical policy digest. |
| Service | `internal/service/agent_communication_authorization_service.go` | `Create` / `Get` / `List` / `Revoke`. Refuses: not exactly two participants; invalid or duplicate role; unknown capability; duplicate service account or client; ownerless participant; participant owned by anyone but the creating owner (cross-owner is deferred, not built); inactive/expired participant; client not bound to the participant, not in the organization, public, or not `private_key_jwt` with registered keys. Allocates every id (UUIDv7) via `uuidgen`. Store errors surface as `domain.AuthStoreUnavailable` (AUTH-503), never as a verdict. |
| Store | `internal/repository/agent_communication_authorization.go`, `internal/postgres/agent_communication_authorization_repository_pgx.go`, `migrations/0037_agent_communication_authorizations.sql` | Atomic create (one transaction, both participant rows). DB reinforcement: unique `session_id`, globally unique `aci`, distinct role / service account / client per authorization, CHECKs for roles, vocabulary, positive limits, future expiry, digest shape; deferred constraint trigger enforcing exactly two participants at COMMIT; participants immutable; only the three revocation columns may change, once. |
| Wiring | `internal/postgres/postgres.go` (`Repositories.AgentCommunicationAuthorization`), `internal/runtime` (`buildDeps`), `api.OSSRouterDeps.AgentCommunicationAuthorizationService` | Constructed at boot; registers NO routes. |

### Canonical policy digest

`domain.AgentCommunicationPolicy` is the typed canonical form:
`policy_version`, `max_messages`, `max_message_size_bytes`, then
`participants` sorted by role, each with its capability set byte-sorted
and deduplicated. It is JSON-encoded without whitespace in that field
order and hashed with SHA-256; the digest is lowercase hex. Timestamps,
ACIs, thumbprints, the audience and row order are NOT inputs: the digest
binds WHAT was authorized. Example canonical bytes:

```
{"policy_version":"v1","max_messages":10,"max_message_size_bytes":1024,"participants":[{"role":"initiator","capabilities":["repository.read"]},{"role":"responder","capabilities":[]}]}
```

### Rules armed by this slice

| Rule | Sentence |
|---|---|
| `AYGHU-SAME-OWNER-1` | Both participant service accounts are owned by the creating owner; an ownerless participant is refused; a participant owned by anyone else is refused. |
| `AYGHU-TWO-PARTICIPANTS-1` | An authorization has exactly two participants, one initiator and one responder, distinct service accounts and distinct ACIs; any other count is refused before persistence. |
| `AYGHU-POLICY-DIGEST-1` | The policy digest is the SHA-256 of the canonical typed policy (version, limits, per-role sorted capability sets) and is independent of input order, timestamps and identifiers. |

## Not built yet — later slices

- **AYGHU-2 ADMIN API** — `POST /api/v1/organizations/:id/agent-communication-authorizations`,
  `GET` (list), `GET /:auth_id`, `POST /:auth_id/revoke`; org_admin /
  owner authorization; audit events for create and revoke.
- **AYGHU-3 ISSUANCE + DPoP** — client-credentials issuance carrying
  `authorization_details` of type `agent_communication` bound to one
  participant ACI, DPoP (RFC 9449) proof binding to
  `proof_key_thumbprint`, relay audience as the token audience, session
  limits as claims.
- **AYGHU-4 INTROSPECTION / REVOCATION / AUDIT** — introspection answers
  for agent-communication tokens, revocation propagation (authorization
  revoked ⇒ tokens inactive), the remaining rulefloor rules of the
  specification. When the revocation/status store is unavailable the
  answer is 503 with a correlation id (AUTH-503), never a verdict.

Cross-owner authorization (participants of two different owners) is
deferred by the specification and refused by AYGHU-1; it is not scheduled.
