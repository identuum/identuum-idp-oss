# Agent communication authorization (AYGHU) — operator document

Identuum IdP OSS issues and judges the credentials two agents of ONE owner
use to talk through a relay. The IdP authenticates the owner and the
agents, records what the owner authorized, signs short-lived participant
tokens, revokes, introspects and audits. It never carries messages,
encryption keys, prompts, repository contents, commands or transcripts.

The authoritative specification is the owner-held Ayghu document, rewritten
as a whole-product specification (agent client, MCP interface, relay,
identity provider) and re-read from scratch for P-036. This server is the
identity-provider component and only that; the file's own "Identuum owns" /
"Ayghu owns" lists are the boundary. This page is the operator view of what
is built (slices P-031 … P-036) and, at the end, the clause-by-clause DELTA
table against the re-baselined wording.

## Vocabulary

- **Owner** — the human authority of an organization who authorizes two of
  their own agent identities to communicate. In v1 the owner is the
  org_admin who created the two service accounts.
- **Agent identity** — a service account (`OwnerUserID` = the owner). An
  OAuth client bound to that service account with `private_key_jwt` is an
  *installation* of the identity.
- **ACI** (Agent Communication Identifier) — an opaque UUIDv7 the IdP
  allocates per participant. It is an ADDRESS: never a credential, a
  secret, a key, a signature container or a JWT, and never a persistent
  public contact address. Knowing an ACI proves nothing.
- **Authorization** — one owner, one organization, exactly two participants
  (`initiator`, `responder`), one relay audience, one session id, session
  limits, an expiry, a capability policy and its canonical digest. States:
  `active`, `revoked` (terminal), `expired` (derived at use time).
- **Participant token** — a DPoP-bound, 5-minute, IdP-signed token for one
  participant of one active authorization.

## Endpoints (org_admin, own organization only)

| Endpoint | Answers |
|---|---|
| `POST /api/v1/agent-communication-authorizations` | 201 with the authorization (server-allocated id, session id, participant ACIs, canonical policy digest). 400 `invalid_request` + stable `reason`; 403 `forbidden` (site_admin, org_user, an explicit foreign `organization_id`) and 403 with reason `ownerless_participant` / `owner_mismatch`; 409 `conflict` `participant_not_usable`. |
| `GET /api/v1/agent-communication-authorizations` | 200 `{authorizations, count}` — own organization, newest first, any status. |
| `GET /api/v1/agent-communication-authorizations/:id` | 200; a foreign organization's id and an absent id answer 404 identically. |
| `POST /api/v1/agent-communication-authorizations/:id/revoke` | 200 with the revoked authorization; terminal and idempotent; optional `{"reason"}` ≤ 256 bytes; foreign / absent → 404 identically. |

No `PUT`, `PATCH` or `DELETE` exists: an authorization is never edited or
widened. Changing participants, keys, limits, audience, expiry or
capabilities means creating a new authorization. Every route answers 401
without a bearer principal and 503 `temporarily_unavailable` /
`auth_store_error` with a correlation id (body + `X-Request-ID`) when a
store cannot answer (AUTH-503) — never a verdict.

### Creation request

```json
{
  "relay_audience": "https://relay.example.test/session",
  "expires_at": "2026-09-03T12:00:00Z",
  "max_messages": 20,
  "max_message_size_bytes": 8192,
  "participants": [
    {"service_account_id": "<uuid>", "client_id": "<oauth client_id>", "role": "initiator",
     "proof_key_thumbprint": "<RFC 7638 thumbprint of the agent's DPoP public key>",
     "capabilities": ["communication.discuss", "repository.read"]},
    {"service_account_id": "<uuid>", "client_id": "<oauth client_id>", "role": "responder",
     "proof_key_thumbprint": "<thumbprint>", "capabilities": []}
  ]
}
```

Client-supplied `id`, `session_id`, `owner_id`, `created_at`, participant
`id` / `aci` and `policy_digest` are ignored. Invariants (service layer,
reinforced by Postgres constraints and triggers in migration 0037): exactly
two participants; distinct ACIs, service accounts, clients and roles; both
service accounts active, unexpired, in the organization and owned by the
creating owner (an ownerless account is refused); each client bound to its
service account, confidential, `private_key_jwt` with registered keys;
relay audience required and normalized; expiry in the future; positive
limits; capabilities from the closed vocabulary; atomic creation.

### Capability vocabulary and canonical digest

`communication.discuss`, `repository.read`, `repository.write`,
`command.execute`, `test.execute`, `network.access`,
`report.final.required` — exact strings, no implication between members,
unknown fails closed, empty = communication only. The digest is the SHA-256
(lowercase hex) of the canonical typed policy: `policy_version`,
`max_messages`, `max_message_size_bytes`, participants sorted by role with
byte-sorted, deduplicated capabilities; JSON without whitespace. Timestamps,
ACIs, thumbprints, the audience and row order are not inputs.

### Owner of a service account

`owner_user_id` is set to the creating org_admin on every service account
created through the admin API (plain and with-client) since P-032.

Accounts created BEFORE that are ownerless. They are left as they are —
nothing guesses a human authority for them — and the owner repairs each one
explicitly through

	POST /api/v1/service-accounts/:id/owner        {"owner_user_id": "…"}

which assigns an owner where there is none and transfers it where there is
(P-038). The acting org_admin claims the account when the body is absent; a
named candidate must be a live, non-banned org_admin of the SAME
organization, and every ineligible candidate is refused identically with
`owner_not_eligible`. site_admin and org_user are refused, and another
tenant's account answers not-found exactly like an absent one.

A TRANSFER is refused with `409 conflict` and the reason
`agent_communication_authorization_active` while a live authorization names
the account: the same-owner rule was judged against the owner of record and
issuance re-checks it, so the owner revokes the authorization first. The
response carries the before and after owner ids, and so does the
`service_account.owner_assigned` audit event.

## Participant-token grant (the existing token endpoint)

`POST /api/v1/oauth/token`, client authenticated with `private_key_jwt`
(the participant's installation), form-encoded, plus the `DPoP` header:

```
grant_type=client_credentials
audience=<the authorization's relay audience>
authorization_details=[{"type":"agent_communication","authorization_id":"<UUIDv7>","aci":"<participant ACI>"}]
DPoP: <proof JWS>
```

`authorization_details` is the ONE closed type: exactly one element,
exactly the members `type`, `authorization_id`, `aci`, both UUIDv7 —
anything else is `400 invalid_authorization_details`. No general RFC 9396
support is claimed. Requests without `authorization_details` keep the
pre-existing `client_credentials` behaviour byte-for-byte.

### DPoP proof (RFC 9449)

Checked in this order: `typ: dpop+jwt`; `alg` in the asymmetric allow-list
(EdDSA, ES256, ES384, RS256, RS384, …; `none` and HMAC refused); a public
`jwk` header (private members refused); the signature with that key; `htm`
= `POST`; `htu` = the advertised token endpoint (scheme/host case, default
port, query and fragment normalized away); `iat` within ±60 s; `jti`
present (≤ 256 bytes); no other claim (`ath`, `nonce` refused). The key's
RFC 7638 thumbprint must equal the participant's enrolled
`proof_key_thumbprint`. Each (thumbprint, jti) is single-use: recorded in
`dpop_proof_replays` (sha256 of the jti; a separate table from the
client-assertion replays), swept once expired. No server nonce is issued.

### Issuance checks

The authorization exists in the client's organization (a foreign one reads
as absent) and is active; the ACI is one of its participants; the client is
THAT participant's installation (the other participant's token cannot be
requested); the service account is active, unexpired, in the organization,
still bound to the client, and **still owned by the authorization's owner**
(re-checked at issuance); the audience equals the stored relay audience
(normalized); the scope is empty or `agent_communication`; the proof key
matches; the proof is unused. The jti is recorded bound to the
authorization BEFORE the token leaves — a token that cannot be recorded is
never handed out (503).

### Token claims

`token_type: DPoP`, no refresh token. TTL:
`IDENTUUM_IDP_AGENT_COMMUNICATION_TOKEN_TTL` (Go duration; default `5m`,
hard maximum `15m`, never past the authorization's expiry).

| Claim | Value |
|---|---|
| `iss` | this issuer |
| `sub` | the participant's service-account id |
| `aud` | the relay audience (exactly) |
| `client_id` | the participant's OAuth client |
| `scope` | `agent_communication` |
| `iat`, `nbf`, `exp`, `jti` | issued now, not before now, expiry, UUIDv7 |
| `actor_type` | `service_account` |
| `org_id` | the organization |
| `cnf.jkt` | the proof-key thumbprint |
| `authorization_details` | the accepted detail |
| `agent_communication` | `authorization_id`, `session_id`, `aci`, `role`, `policy_version`, `policy_digest`, `max_messages`, `max_message_size_bytes`, `authorization_expires_at` |

Never in a token: owner identity or email, secrets, keys, capability
descriptions, message contents.

### Refusal matrix (every refusal is audited as `agent_communication.token.refused` with a stable `reason`)

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
| participant service account missing / inactive / expired / re-bound / re-owned | invalid_grant | participant_service_account_missing / participant_not_usable / participant_binding_invalid / participant_owner_mismatch |
| audience missing or ≠ relay audience | invalid_target | audience_mismatch |
| scope other than agent_communication | invalid_scope | scope_invalid |
| any store failure | **503** temporarily_unavailable / auth_store_error + correlation id | — (an outage is not a verdict; not audited as a refusal) |

## Introspection (`POST /api/v1/oauth/introspection`, client-authenticated)

| Token | Answer |
|---|---|
| malformed, bad signature, wrong issuer, expired | 200 `{"active": false}` |
| `aud` ≠ the authorization's relay audience | `{"active": false}` |
| jti in `oauth_token_revocations` (revoke endpoint or propagation) | `{"active": false}` |
| authorization absent, another organization's, revoked, or expired | `{"active": false}` |
| ACI ∉ participants; `sub` ≠ participant's service account; `role`, `session_id` or `policy_digest` ≠ stored binding; client absent, not the participant's installation, or re-bound; no `cnf`; not wired | `{"active": false}` |
| live participant token | `active: true`, `token_type: DPoP`, `cnf: {"jkt"}`, RFC 7662 fields, `authorization_details`, `agent_communication` projection |
| authorization / client / jti-revocation / signing-key store unavailable | **503** + correlation id — never `active:false` |
| ordinary (non-participant) tokens | unchanged |

Never in an introspection answer: a JWK or any key member, the proof, the
token, capability descriptions, owner identity. Participant tokens are
refused on userinfo and on the IdP's own bearer-protected API.

## Revocation semantics

Revoking an authorization stamps the row (terminal, idempotent, acting
owner + timestamp + bounded reason recorded) and writes every still-live
issued jti of BOTH participants to `oauth_token_revocations`
(`agent_communication_tokens`, migration 0039, records each issued jti) —
issuance stops immediately for both participants and introspection turns
inactive immediately, not at token expiry. An idempotent repeat
re-propagates. A store error on either side answers 503 with the row
already revoked. Expiry needs no background mutation.

## Discovery

When the issuance path is wired the OP advertises
`dpop_signing_alg_values_supported` and
`authorization_details_types_supported: ["agent_communication"]`.

## Audit events (safe metadata only)

| Event | Metadata |
|---|---|
| `agent_communication_authorization.created` | authorization_id, session_id, organization_id, owner_id, participants [{aci, role, service_account_id, oauth_client_id}] |
| `agent_communication_authorization.revoked` | authorization_id, session_id, organization_id, revoked_by, result `revoked` / `already_revoked` |
| `agent_communication.token.issued` | authorization_id, session_id, aci, role, service_account_id, client_id, token_type, expires_at |
| `agent_communication.token.refused` | client_id, reason |

Never: tokens, proofs, thumbprints, keys, free-text reasons, audiences,
message contents.

## Where this component sits (the Ayghu product split)

Ayghu is one product in three parts: a client beside each agent (MCP is its
first interface), a central relay, and an identity provider. The
specification splits that last part again, and the split is normative:
"Identuum has two parts. Build them separately."

**Identuum IDP owns** (this server) — OAuth2 and OIDC, owner identity,
service accounts, OAuth clients, machine authentication, signed
communication authorization, tokens, revocation, introspection. Add the
wider "Identuum owns" list — owner authentication, persistent agent
identity, participant bindings, session identifiers, ACI allocation,
expiration, authorization audit — and every item is built here.

**Identuum IDP must NOT own** — agent reasoning, prompt contents, relay
operations, execution policy, tool execution. Measured absent, and two
rules keep it that way: `AYGHU-NO-PROMPT-CONTENT-1` audits the surface,
`AYGHU-SIGNS-NOT-ENFORCES-1` proves no capability changes an answer here.

**Identuum AG owns** — agent governance, session and capability policy,
remote-message classification, approval state, execution authorization,
resource boundaries, provenance and audit. A separate product in a separate
repository; nothing of it is built here. "AG must not own core identity or
message transport" is the mirror of the same line.

**Ayghu owns** (client and relay) — relay operations, message delivery,
encrypted queues, message ordering, acknowledgements, operational session
state, end-to-end encryption handshakes, the incoming-prompt lifecycle, the
execution-approval workflow, local transcripts, final reports.

The file states the consequence for this server twice, and both sentences
are pinned: "The IDP never receives: prompt plaintext, repository contents,
command output, transcripts, final reports" and "The IDP signs what was
authorized. It does not enforce what an agent may do. Signing a capability
is not enforcing it. Enforcement is AG's job."

### Measured: nothing here enforces a capability

Every production symbol that touches a capability, and what it does with it:

| Symbol | What it does |
| --- | --- |
| `domain.CanonicalizeAgentCommunicationCapabilities` / `ParseAgentCommunicationCapability` | validate against the closed vocabulary, sort, deduplicate |
| `domain.(*AgentCommunicationAuthorization).Validate` | check the stored set is in canonical form |
| `domain.AgentCommunicationPolicy.Canonical` / `Digest` | fold the set into the signed policy digest |
| `service.(*AgentCommunicationAuthorizationService).Create` | normalize the owner's input on write |
| `postgres` participant repository | persist and read the column |
| `handlers.toAgentCommunicationAuthorizationDTO` | project the set back to the OWNER on the admin surface |

Issuance and introspection never read the set at all: a token carries the
policy digest, never a capability list, and a communication-only
authorization is issued and introspected exactly like a fully capable one.
Measured with `gograph callers` on both vocabulary functions and by reading
the issuance and introspection paths end to end.

## What the relay and the receiving client must do (outside the IdP)

Per the specification, the relay validates on every request: the IdP
signature (via JWKS), token expiration, the relay audience, the session
binding, the participant ACI, the DPoP proof, the `cnf.jkt` binding, and
revocation through introspection where freshness is required. A relay that
introspects needs its own registered client credential on this server;
introspection answers any authenticated caller that already holds the token,
which is what an out-of-tenant relay needs.

The receiving client owns everything the IdP deliberately does not: marking
remote messages `untrusted` outside the message content, classifying
execution prompts (the sender's own declaration is never authoritative),
holding an incoming prompt at `pending_approval`, showing the owner the FULL
prompt, binding an approval to the exact prompt digest, enforcing
capabilities outside model reasoning, and refusing a redelivered prompt a
second execution. Never add or trust an owner-identity field in a message:
two valid tokens carrying one session id already prove same-owner, and this
server puts no owner identity in a token or an introspection answer for a
peer to compare (`AYGHU-NO-OWNER-IDENTITY-1`).

## What v1 does not protect against

- **Cooperative capability enforcement.** The IdP records and signs the
  owner-approved capabilities; it does not execute or enforce local tools.
  The specification is explicit: "Signing a capability is not enforcing it.
  Enforcement is AG's job." A participant that ignores its capability set is
  stopped by `identuum-ag` or its own runtime, never by this server, and
  `AYGHU-SIGNS-NOT-ENFORCES-1` keeps that line drawn.
- **Prompt injection.** Nothing here constrains what a model does with
  remote text. The specification's answer is deterministic local
  enforcement after model reasoning, which lives in the client.
- **TOFU key enrollment.** The owner approves a proof-key thumbprint the
  agent shows at boot. Nothing in v1 proves the key was generated by that
  process on that machine — a substituted key at enrollment time binds the
  substitute.
- **Offline verifiers inside the TTL.** A relay or receiver that only
  checks the signature and expiry cannot see a revocation; a revoked token
  stays offline-valid for up to the token lifetime (≤ 15 min). Introspect
  for freshness.
- **Out-of-band channels.** Agents that talk outside the relay carry no
  IdP token and are outside this authorization entirely.
- **A compromised participant process.** Whoever holds the agent's
  `private_key_jwt` key AND its DPoP key is that agent. Rotation and
  incident response are the owner's: revoke the authorization (immediate
  for issuance and introspection), then replace the installation's keys.
  An attacker holding a stolen participant token can also introspect it;
  the answer carries no owner identity, no key and no message content.
- **Pre-existing ownerless service accounts stay ownerless until an owner
  claims them.** Nothing backfills an owner; the repair is the explicit,
  audited assignment route above (P-038).
- **A participant cannot read its own capability set from this server.**
  The token carries the policy DIGEST, not the capability list, and the
  authorization read is org_admin-only. The local enforcement point learns
  its capabilities from the owner's local configuration. See the gaps below.
- **No DPoP server nonce**; no general RFC 9396 support beyond the one
  closed type; no cross-IdP federation, guests, more than two participants,
  or cross-owner sessions (deferred by the specification).

## Rules armed (rulefloor)

AYGHU-SAME-OWNER-1, AYGHU-TWO-PARTICIPANTS-1, AYGHU-POLICY-DIGEST-1
(P-031); AYGHU-ORG-SCOPE-1, AYGHU-STORE-503-1, AYGHU-AUDIT-1 (P-032);
AYGHU-NO-BEARER-1, AYGHU-DPOP-THUMBPRINT-1, AYGHU-REVOKE-STOPS-ISSUANCE-1,
AYGHU-DPOP-REPLAY-1 (P-033); AYGHU-REVOKED-INACTIVE-1,
AYGHU-INTROSPECT-503-1, AYGHU-INTROSPECT-NO-KEYS-1 (P-034);
AYGHU-OWNER-AT-ISSUANCE-1, AYGHU-ACI-ADDRESS-1, AYGHU-NO-WIDENING-1,
AYGHU-TOKEN-BINDING-1, AYGHU-NO-REFRESH-1, AYGHU-TOKEN-AUDIT-SAFE-1,
AYGHU-IDENTITY-SIGNED-1 (P-035); AYGHU-NO-PROMPT-CONTENT-1,
AYGHU-CAP-NO-IMPLICATION-1, AYGHU-MATERIAL-CHANGE-1,
AYGHU-NO-OWNER-IDENTITY-1, AYGHU-SIGNS-NOT-ENFORCES-1 (P-036/P-037).
Every rule is mutation red-proved.

## Delta table: the re-baselined specification, clause by clause

The specification was rewritten as a whole-product document (client, relay,
MCP, identity provider). This table replaces the conformance table written
against the previous wording. Status values: **built** (already true and
tested), **newly pinned** (true before, now a red-proved rule because the
new wording states it outright), **relay-or-client** (the file assigns it to
Ayghu — nothing is built here), **out of scope v1**, **deferred**.

### The file's own boundary lists

| Clause | Where in the IdP | Status |
| --- | --- | --- |
| Identuum owns: owner authentication | the IdP's human login, sessions and roles | built |
| Identuum owns: persistent agent identity | service accounts (`/api/v1/service-accounts`) | built |
| Identuum owns: machine or installation authentication | one `private_key_jwt` OAuth client per installation, bound to its service account | built |
| Identuum owns: communication authorization | `agent_communication_authorizations` + the four routes | built |
| Identuum owns: participant bindings | `agent_communication_participants` (service account, client, role, proof key, capabilities) | built |
| Identuum owns: session identifiers | server-allocated `session_id` (UUIDv7), in every token | built |
| Identuum owns: ACI allocation | server-allocated UUIDv7 per participant, unique across all authorizations | built |
| Identuum owns: signed communication tokens | the token endpoint's participant grant, DPoP-bound | built |
| Identuum owns: expiration | authorization `expires_at`; token TTL = min(configured, authorization expiry), 5 min default / 15 max | built |
| Identuum owns: revocation | terminal revoke + propagation of every live jti | built |
| Identuum owns: introspection | RFC 7662 with the safe participant projection | built |
| Identuum owns: authorization audit | `agent_communication_authorization.created` / `.revoked`, `agent_communication.token.issued` / `.refused` | built |
| Ayghu owns: relay operations, message delivery, encrypted queues, ordering, acknowledgements, operational session state | — | relay-or-client |
| Ayghu owns: end-to-end encryption handshakes | — | relay-or-client |
| Ayghu owns: incoming-prompt lifecycle, execution-approval workflow | — | relay-or-client |
| Ayghu owns: local transcripts, final reports | — | relay-or-client |

### The IDP / AG split (the section added in the latest rewrite)

| Clause | Where in the IdP | Status |
| --- | --- | --- |
| "Identuum has two parts. Build them separately." | this repository is the IDP half; `identuum-ag` is a separate product and repository | built (as a boundary) |
| Identuum IDP owns: OAuth2 and OIDC | the OSS authorization server | built |
| Identuum IDP owns: owner identity | users, org roles, sessions | built |
| Identuum IDP owns: service accounts | `/api/v1/service-accounts` | built |
| Identuum IDP owns: OAuth clients | `/api/v1/clients`, one installation per participant | built |
| Identuum IDP owns: machine authentication | `private_key_jwt` client authentication | built |
| Identuum IDP owns: signed communication authorization | the aggregate, its canonical policy and digest | built |
| Identuum IDP owns: tokens | the DPoP-bound participant grant | built |
| Identuum IDP owns: revocation | terminal revoke + jti propagation | built |
| Identuum IDP owns: introspection | RFC 7662 with the safe projection | built |
| Identuum IDP must NOT own: agent reasoning | nothing of the kind exists | measured absent, pinned |
| Identuum IDP must NOT own: prompt contents | no field, claim, key or route | newly pinned — `AYGHU-NO-PROMPT-CONTENT-1` |
| Identuum IDP must NOT own: relay operations | no queue, delivery, ordering or acknowledgement surface | measured absent, pinned by the census scan |
| Identuum IDP must NOT own: execution policy | no approval state, no execution authorization | newly pinned — `AYGHU-SIGNS-NOT-ENFORCES-1` |
| Identuum IDP must NOT own: tool execution | nothing executes anything | measured absent |
| "The IDP never receives: prompt plaintext, repository contents, command output, transcripts, final reports" | the surface audit names all five and fails if the list is narrowed | newly pinned — `AYGHU-NO-PROMPT-CONTENT-1` (widened to the five items) |
| "The IDP signs what was authorized. It does not enforce what an agent may do. Signing a capability is not enforcing it. Enforcement is AG's job." | a capability set changes no answer: same issuance, same introspection, only the digest and the owner's own read differ | newly pinned — `AYGHU-SIGNS-NOT-ENFORCES-1` |
| "Keep agentic behavior out of the IDP. The IDP carries only the communication metadata the contract requires." | the token and the introspection answer carry identifiers, bindings, limits and the digest — nothing else | built, pinned by both rules |
| Identuum AG owns: agent governance, session and capability policy, remote-message classification, approval state, execution authorization, resource boundaries, provenance and audit | — | out of scope: a separate product, and `identuum-ag` is off limits in this slice |
| "Identuum AG must not own core identity or message transport" | the mirror clause: identity stays here | built (as a boundary) |
| "Cross-owner sessions are future IDP work: an immutable communication proposal that becomes active only after both owners consent to the same proposal. Not built." | v1 is same-owner, re-checked at issuance | future IDP work — costed below, nothing built |

### Clauses the new wording adds or sharpens for the IdP

| Clause (new wording) | Where in the IdP | Status |
| --- | --- | --- |
| "The identity provider must never receive prompt contents" | no field, column, claim, audit key or route can carry one | newly pinned — `AYGHU-NO-PROMPT-CONTENT-1` |
| "The identity provider must not possess message encryption private keys" | the IdP stores a proof-key THUMBPRINT and nothing else | newly pinned — same rule |
| "Conversation transcripts and final reports … the identity provider does not store them" | no transcript or report surface exists | newly pinned — same rule |
| v1 excludes "Identity-provider access to message plaintext / transcripts / repository data" | the whole 143-endpoint census is scanned for such a route | newly pinned — same rule |
| "No capability implies another capability unless explicitly defined" plus the five named ordered pairs | closed vocabulary; canonicalization only sorts and deduplicates | newly pinned — `AYGHU-CAP-NO-IMPLICATION-1` |
| "report.final.required is a reporting obligation, not tool authority" | it is one vocabulary member and carries no tool prefix | newly pinned — same rule |
| "An empty local-tool capability list means communication only" | an empty set is valid and grants nothing | newly pinned — same rule |
| "Unknown capabilities fail closed" | `ParseAgentCommunicationCapability` refuses; an unknown member refuses the whole set | built, now also pinned by the same rule |
| "Agents cannot grant capabilities to themselves or other participants"; "Remote participants cannot widen capabilities" | capabilities are settable only by the org_admin at creation; no token or message path writes them | built (`AYGHU-NO-WIDENING-1`, `AYGHU-ORG-SCOPE-1`) |
| "Changing capabilities requires a new authorization"; "Material changes require renewed consent: participants, session limits, relay audience, expiration, proof keys, capabilities, other authorization semantics" | no edit route; the store's revocation-only trigger names every material column; participants are wholly immutable; a material change is a different digest | newly pinned — `AYGHU-MATERIAL-CHANGE-1` |
| "Peers must never compare asserted owner identities in messages" | no owner identity in any token claim or introspection answer | newly pinned — `AYGHU-NO-OWNER-IDENTITY-1` |
| "Ayghu must not infer owner identity from messages … relies on the signed authorization and participant bindings" | the token carries authorization, session, ACI, role, client, subject and `cnf.jkt` | built (`AYGHU-TOKEN-BINDING-1`) |
| Relay validation list: IDP signature, token expiration, relay audience, session binding, participant ACI, DPoP proof, `cnf.jkt`, revocation through introspection | every item is a claim of the issued token or an introspection answer | built |
| "Communication must not depend solely on transferable bearer tokens"; sender-constrained tokens with DPoP | `token_type: DPoP`, proof required, thumbprint must equal the enrolled key | built (`AYGHU-NO-BEARER-1`, `AYGHU-DPOP-THUMBPRINT-1`) |
| "Replay of transport authentication proofs must be refused" | `(jkt, jti)` single-use at the token endpoint; message-level replay is the relay's | built (`AYGHU-DPOP-REPLAY-1`) for the IdP's boundary |
| "Session limits must be enforced by infrastructure rather than model cooperation" | the limits are signed into the token; enforcement is the relay's and the client's | built (the IdP's half) |
| "Sessions automatically expire"; "Exactly two participants in v1" | derived status; exactly-two enforced in the domain and by a deferred DB trigger | built |
| "ACI is an address, never a credential … not a persistent public contact address" | an ACI authenticates nothing; no directory, discovery or lookup route exists | built (`AYGHU-ACI-ADDRESS-1`) |
| "Do not log raw communication tokens, DPoP proofs, private keys, client secrets, encryption private keys" | audit metadata is an identifier-only allowlist | built (`AYGHU-AUDIT-1`, `AYGHU-TOKEN-AUDIT-SAFE-1`) |
| "Ayghu does not create its own parallel identity system when an external identity provider is configured" | this server is that provider | built |
| "Communication authorization does not imply execution authorization" | the IdP issues no execution approval and has no prompt surface | built + `AYGHU-NO-PROMPT-CONTENT-1` |

### Clauses assigned elsewhere (nothing built here, by the file's own boundary)

| Clause | Status |
| --- | --- |
| Transport: short-lived HTTPS, polling/long-polling, acknowledgements, horizontal scaling | relay-or-client |
| Receiving remote messages: deterministic `untrusted` classification, trusted metadata outside the content, remote text never presented as owner or system input | relay-or-client |
| Message types `discussion_message` / `execution_prompt`; the receiver (never the sender) classifies; uncertainty fails safe to approval | relay-or-client |
| Prompt approval: IncomingPrompt record and its six states, owner notification with the FULL prompt, approval bound to the prompt digest, invalidation on any change, prompt integrity, idempotent execution per PromptID | relay-or-client |
| Discussion autonomy inside session limits | relay-or-client |
| Prompt-injection model, deterministic local enforcement before tool execution, protected resources, high-risk-action approval | relay-or-client |
| End-to-end encryption between clients; relay holds ciphertext only, with bounded retention; queued messages expire | relay-or-client |
| Message identity and ordering, duplicate detection, sequence information | relay-or-client |
| Local transcripts and final reports, and what a prompt-approval log must preserve | relay-or-client |
| MCP client interface, Go/Python SDKs, CLI clients | relay-or-client |
| Public discovery, public registry, persistent contact addresses, anonymous or guest participants, file transfer, multi-agent rooms, cross-IdP federation, arbitrary remote tool delegation, relay-side plaintext inspection / prompt interpretation / execution | out of scope v1 |
| Cross-owner communication with bilateral consent (both owners approve one immutable proposal; neither grants the other's agent anything) | deferred — v1 is same-owner (`AYGHU-SAME-OWNER-1`, re-checked at issuance) |
| Multi-agent sessions beyond two participants | deferred |

### Gaps and deferrals in one place

- **Closed in P-036: nothing in the product code.** The re-baselined file
  adds no unbuilt obligation for this server; what it adds are invariants
  that were prose here and are now four red-proved rules.
- **Reported, not started (needs a ruling, medium):** a participant cannot
  learn its own capability set from this server. The token carries the
  policy digest only, and `GET /api/v1/agent-communication-authorizations/:id`
  is org_admin-only, so the client's deterministic enforcement point takes
  its capability list from local owner configuration. Two ways to close it:
  add the participant's own `capabilities` array to the `agent_communication`
  claim and the introspection projection (≈ 20 lines, two rule tests, one
  sweep assertion — but it publishes each participant's capability set to
  the relay), or add a participant-authenticated read of its own
  authorization (a new route, census 143 → 144, matrix cells, sweep rows —
  about half a slice). Not started: the specification assigns capability
  enforcement to the client without saying who delivers the list.
- **Closed in P-038 (THE-OWNERLESS-ACCOUNT):** the owner assignment and
  transfer route (census 143 → 144, role-matrix cells, sweep rows, transfer
  refused while an authorization is live — `SA-OWNER-TRANSFER-LIVE-1`), and
  the AUTH-503 straggler: `GetForActor` and `LookupForClient` mapped every
  store error to not-found, so an outage read as "no such service account"
  on the admin surface and as `unauthorized_client` at the token endpoint.
  Both now answer 503 with a correlation id (`SA-STORE-503-1`).
- **Indirect, not closed (small, measured):** a Go integration test that
  writes invalid rows directly and watches the 0037 triggers refuse (the
  triggers exist, are asserted by text in `AYGHU-MATERIAL-CHANGE-1`, and run
  on every fresh-appliance mint; cost ≈ one integration-profile test file);
  an explicit "deleted service account" refusal row (deleted rows already
  hide behind the typed not-found; cost ≈ one table row).
- **Future IDP work, costed, NOT started — cross-owner bilateral consent.**
  The file now names this as IDP work: "an immutable communication proposal
  that becomes active only after both owners consent to the same proposal."
  Measured cost against what exists: a proposal aggregate and table with its
  own states (proposed, consented-by-one, active, rejected, expired) and an
  immutable proposal digest reusing the canonical policy digest; two consent
  routes plus a read (census 143 to 146, with the golden, the manifest and
  role-matrix cells for three roles); a same-owner rule that becomes
  two-owner, so `CheckAgentCommunicationSameOwner` splits into a per-side
  owner check and neither owner may set the other's capabilities; issuance
  and introspection gain "proposal active" to their fail-closed lists; new
  audit events for propose, consent, reject; rules for one-sided consent
  never activating, a material change voiding both consents, and no
  cross-owner capability grant. About two slices, and it needs an owner
  ruling on whether both owners live in one Identuum deployment before any
  of it is designed. Nothing was built.
- **Deferred by the specification itself:** more than two participants,
  federation, guests, anonymous participants, discovery, registries,
  persistent contact addresses.
