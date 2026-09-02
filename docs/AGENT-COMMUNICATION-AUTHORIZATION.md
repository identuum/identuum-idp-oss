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

## Not built yet — later slices

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
