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

## AYGHU-2 ADMIN API — built

`internal/handlers/agent_communication_authorizations.go` (routes, mapping,
audit), `internal/service/agent_communication_authorization_actor.go`
(authority), `types/agent_communication.go` (wire projection). Mounted by
the OSS router; docgen canonical endpoint count 139 → 143.

| Endpoint | Who | Answers |
|---|---|---|
| `POST /api/v1/agent-communication-authorizations` | org_admin, own org, owner = actor | 201 with the authorization (ids, session id, participant ACIs, server-computed digest). 400 `invalid_request` + stable `reason` (`participant_count`, `unknown_capability`, `duplicate_role`, `invalid_role`, `invalid_service_account_id`, `participant_service_account_not_found`, `participant_client_not_found`, `client_not_bound`, `client_auth_not_asymmetric`, `relay_audience_required`, `relay_audience_invalid`, `expiry_not_future`, `limit_not_positive`, `proof_key_thumbprint_invalid`, `invalid_organization_id`, …). 403 `forbidden` (site_admin, org_user, explicit foreign `organization_id`) and 403 with reason `ownerless_participant` / `owner_mismatch` (same-owner rule). 409 `conflict` `participant_not_usable` (inactive or expired service account). |
| `GET /api/v1/agent-communication-authorizations` | org_admin, own org | 200 `{authorizations, count}` — own organization only, newest first, any status. |
| `GET /api/v1/agent-communication-authorizations/:id` | org_admin, own org | 200; a foreign organization's id and an absent id answer 404 identically (no existence oracle); malformed id 400 `invalid_authorization_id`. |
| `POST /api/v1/agent-communication-authorizations/:id/revoke` | org_admin, own org (same-organization emergency revocation is allowed and audited) | 200 with the revoked authorization; terminal and idempotent (a repeat returns the first stamp unchanged); optional body `{"reason"}` trimmed, ≤256 bytes (400 `revocation_reason_too_long`); foreign / absent → 404 identically. |

**Owner of a service account (measured live in this slice):** `owner_user_id`
existed since migration 0001 but nothing in OSS ever wrote it, so every
service account was ownerless and the same-owner rule refused all of them
(`403 ownerless_participant`). Since AYGHU-2 the creating org_admin is the
owner of every service account created through the admin API (plain and
with-client). Service accounts created before that stay ownerless and cannot
participate until an owner-assignment path exists (not scheduled).

Every route: 401 without a bearer principal; a store error on ANY path
answers 503 `temporarily_unavailable` / `auth_store_error` with a
correlation id on the body and the `X-Request-ID` header (AUTH-503) — never
a verdict. Client-supplied `id`, `session_id`, `owner_id`, `created_at`,
participant `id` / `aci` and `policy_digest` are ignored, never trusted.
No PUT/PATCH exists: nothing widens or edits an authorization.

Audit (safe metadata only): `agent_communication_authorization.created`
(authorization_id, session_id, organization_id, owner_id, participants
[{aci, role, service_account_id, oauth_client_id}]) and
`agent_communication_authorization.revoked` (authorization_id, session_id,
organization_id, revoked_by, result `revoked` / `already_revoked`). The
free-text reason, thumbprints and the audience never enter an event; a
refused request records nothing.

Rules armed by this slice: `AYGHU-ORG-SCOPE-1` (cross-organization
access creates no existence oracle; site_admin/org_user refused uniformly),
`AYGHU-STORE-503-1` (a store error answers 503 with a correlation id,
never a verdict, exactly one AUTH-503 log sink call), `AYGHU-AUDIT-1`
(create and revoke each record exactly one event with safe metadata; a
refusal records none). Ratchets: ui `e2e-full/role-matrix.json` grows by
the four endpoints (every role observed), `e2e-full/agent-communication-sweep.spec.ts`
exercises every endpoint and refusal path in the api-suite.

## AYGHU-3 ISSUANCE + DPoP — built

The existing token endpoint (`POST /api/v1/oauth/token`, no new route) issues
a participant token when — and only when — the request carries
`authorization_details`. Everything else about `client_credentials` is
byte-for-byte unchanged. `internal/service/token_service_agent_communication.go`
(issuance), `internal/service/dpop_proof.go` (token-endpoint DPoP
verifier), `internal/service/dpop_proof_replay_service.go` +
`migrations/0038_dpop_proof_replays.sql` (single-use proofs),
`internal/handlers/token_agent_communication.go` (branch + audit).

Request (form-encoded, client authenticated with **private_key_jwt** — the
participant's registered installation):

```
grant_type=client_credentials
audience=<exact relay audience of the authorization>
authorization_details=[{"type":"agent_communication","authorization_id":"<UUIDv7>","aci":"<participant ACI UUIDv7>"}]
DPoP: <proof JWS>   (header)
```

`authorization_details` is the ONE closed type: exactly one array element,
exactly the members `type`, `authorization_id`, `aci`, both UUIDv7 —
unknown types, unknown or missing fields, several details, malformed
identifiers → `400 invalid_authorization_details`. No general RFC 9396
support is claimed.

DPoP proof (RFC 9449 §4) checks, in order: `typ: dpop+jwt`; `alg` in the
repository's asymmetric allow-list (EdDSA, ES256/384, RS256/384, …; `none`
and HMAC refused); public `jwk` header (private members refused);
signature with that key; `htm` = POST; `htu` = the advertised token endpoint
(scheme/host case, default port, query and fragment normalized away); `iat`
within ±60 s; `jti` present (≤256 bytes); no other claim — `ath` and
`nonce` do not belong to a token-endpoint proof here. The proof key's RFC
7638 thumbprint must equal the participant's enrolled
`proof_key_thumbprint`. Each (thumbprint, jti) is single-use: recorded in
`dpop_proof_replays` (sha256 of the jti, never the raw jti; a separate table
from the client-assertion replays), swept by the revocation cleanup ticker.

Issuance verifies: authorization exists in the client's organization,
active (not revoked, not expired), the ACI is one of its participants, the
client is THAT participant's installation (`oauth_clients.id`), the service
account is live and still bound, the audience matches the stored relay
audience exactly (normalized form), the scope is empty or
`agent_communication`, the thumbprint matches, the proof is unused.

Token: JWT signed with the IdP key; `token_type: DPoP`; **no refresh
token**; TTL `IDENTUUM_IDP_AGENT_COMMUNICATION_TOKEN_TTL` (default 5 min,
hard max 15 min, never past the authorization's expiry). Claims: `iss`,
`sub` = service-account id, `aud` = relay audience, `client_id`, `scope
agent_communication`, `iat`, `nbf`, `exp`, `jti` (UUIDv7), `actor_type`,
`org_id`, `cnf.jkt`, `authorization_details` (the detail as accepted),
`agent_communication` {authorization_id, session_id, aci, role,
policy_version, policy_digest, max_messages, max_message_size_bytes,
authorization_expires_at}. Never: owner email, secrets, keys, capabilities,
message content.

Refusal matrix (all 400 unless noted; every refusal is audited as
`agent_communication.token.refused` with a stable `reason`):

| Condition | error | reason |
|---|---|---|
| no `DPoP` header | invalid_dpop_proof | dpop_missing |
| proof malformed / wrong typ, alg, htm, htu, iat, jti / extra claim / bad signature | invalid_dpop_proof | dpop_invalid |
| proof key ≠ enrolled thumbprint (incl. the other participant's key) | invalid_dpop_proof | thumbprint_mismatch |
| proof (jkt, jti) already used | invalid_dpop_proof | dpop_replay |
| `authorization_details` malformed / unknown type / fields / count / ids | invalid_authorization_details | invalid_authorization_details |
| grant_type ≠ client_credentials | unsupported_grant_type | unsupported_grant |
| caller not an OAuth client, public, unknown, or not private_key_jwt | unauthorized_client | client_kind / client_not_found / client_auth_not_asymmetric |
| authorization absent or another organization's | invalid_grant | authorization_not_found |
| authorization revoked / expired | invalid_grant | authorization_revoked / authorization_expired |
| ACI not in the authorization / client is not that participant | invalid_grant | aci_not_in_authorization / client_not_participant |
| participant service account missing / inactive / expired / binding broken | invalid_grant | participant_service_account_missing / participant_not_usable / participant_binding_invalid |
| audience missing or ≠ relay audience | invalid_target | audience_mismatch |
| scope other than agent_communication | invalid_scope | scope_invalid |
| any store failure (authorization, client, service account, replay store) | **503** temporarily_unavailable / auth_store_error + correlation id | — (an outage is not a verdict; no refusal is audited) |

Success audit: `agent_communication.token.issued` {authorization_id,
session_id, aci, role, service_account_id, client_id, token_type,
expires_at}; the token and the proof never enter an event.

Rules armed by this slice: `AYGHU-NO-BEARER-1`, `AYGHU-DPOP-THUMBPRINT-1`,
`AYGHU-REVOKE-STOPS-ISSUANCE-1`, `AYGHU-DPOP-REPLAY-1`.

Honest limits (documented, not built): no DPoP server nonce. Introspection,
revocation propagation and the discovery advertisement are AYGHU-4 (below).

## AYGHU-4 INTROSPECTION + REVOCATION PROPAGATION — built

**Issued-token record.** Every participant token's `jti` is written to
`agent_communication_tokens` (migration 0039: jti, authorization id, ACI,
expiry) BEFORE the token leaves the server; a token that cannot be recorded
is never handed out (503). Rows are swept once expired and cascade with the
authorization.

**Revocation propagation.** `POST …/:id/revoke` stamps the authorization
AND writes every still-live jti of both participants to
`oauth_token_revocations` (reason `agent_communication.authorization_revoked`),
so introspection — and every other jti-revocation consumer — turns those
tokens inactive immediately, not at expiry. An idempotent repeat re-propagates
(heals a partial earlier run). A store error on either side answers 503; the
authorization row is already revoked at that point.

**Introspection truth table** (`POST /api/v1/oauth/introspection`, client-authenticated as today):

| Token | Answer |
|---|---|
| malformed, bad signature, wrong issuer/audience, expired | 200 `{"active": false}` |
| jti in `oauth_token_revocations` (revoke endpoint or propagation) | `{"active": false}` |
| authorization absent (or another organization's), revoked, or expired | `{"active": false}` |
| ACI not in the authorization; `sub` ≠ participant's service account; `role`, `session_id` or `policy_digest` ≠ stored binding; client absent, not the participant's installation, or re-bound; no `cnf` | `{"active": false}` |
| introspection not wired for agent communication | `{"active": false}` (fail closed) |
| live participant token | `active: true`, `token_type: DPoP`, `cnf: {"jkt"}`, standard RFC 7662 fields (`sub` = service-account id, `client_id`, `scope agent_communication`, `exp`/`iat`/`nbf`, `aud`, `iss`, `jti`), `authorization_details`, `agent_communication` {authorization_id, session_id, aci, role, policy_version, policy_digest, max_messages, max_message_size_bytes, authorization_expires_at} |
| authorization store, client store, jti revocation store or signing-key store unavailable | **503** `temporarily_unavailable` / `auth_store_error` + correlation id — never `active:false` |

Never in an introspection answer: a JWK or any key member, the DPoP proof,
the token, capability descriptions, owner email.

**Discovery.** When the issuance path is wired, the OP advertises
`dpop_signing_alg_values_supported` (the asymmetric allow-list) and
`authorization_details_types_supported: ["agent_communication"]` (RFC 9449
§5.1, RFC 9396 §10); the closed type list never widens.

Rules armed by this slice: `AYGHU-REVOKED-INACTIVE-1`,
`AYGHU-INTROSPECT-503-1`, `AYGHU-INTROSPECT-NO-KEYS-1`.

Honest limits: a participant token verified OFFLINE (signature + expiry
only) cannot see a revocation — only introspection can; the ≤ 15-minute
lifetime bounds that window. No DPoP server nonce.

## Not built yet — later slices

- **AYGHU-3 ISSUANCE + DPoP** — built above.
- **AYGHU-4 INTROSPECTION + REVOCATION PROPAGATION** — built above. — client-credentials issuance carrying
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
