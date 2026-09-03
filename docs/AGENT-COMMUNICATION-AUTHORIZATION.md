# Agent communication authorization (AYGHU) — operator document

Identuum IdP OSS issues and judges the credentials two agents of ONE owner
use to talk through a relay. The IdP authenticates the owner and the
agents, records what the owner authorized, signs short-lived participant
tokens, revokes, introspects and audits. It never carries messages,
encryption keys, prompts, repository contents, commands or transcripts.

The authoritative specification is the owner-held AYGHU document. This page
is the operator view of what is built (slices P-031 … P-035) and, at the
end, the clause-by-clause conformance table.

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
created through the admin API (plain and with-client) since P-032. Service
accounts created before that are ownerless and cannot participate; no
owner-assignment path exists yet (see the deferred list).

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

## What the relay and the receiver must do (outside the IdP)

Verify the IdP signature via JWKS; require the SAME `session_id` in both
participants' tokens; require the exact relay audience; require `cnf.jkt`
to match the sender's DPoP key on every message; introspect for revocation
freshness (offline signature checks cannot see a revocation). Never add or
trust an owner-identity field in a message: two valid tokens with one
session id already prove same-owner.

## What v1 does not protect against

- **Cooperative capability enforcement.** The IdP records and signs the
  owner-approved capabilities; it does not execute or enforce local tools.
  A participant that ignores its capability set is stopped only by its own
  runtime (or `identuum-ag`), not by the IdP.
- **TOFU key enrollment.** The owner approves a proof-key thumbprint the
  agent shows at boot. Nothing in v1 proves the key was generated by that
  process on that machine — a substituted key at enrollment time binds the
  substitute.
- **Offline verifiers inside the TTL.** A relay or receiver that only
  checks the signature and expiry cannot see a revocation; a revoked
  token stays offline-valid for up to the token lifetime (≤ 15 min).
  Introspect for freshness.
- **Out-of-band channels.** Agents that talk outside the relay carry no
  IdP token and are outside this authorization entirely.
- **A compromised participant process.** Whoever holds the agent's
  `private_key_jwt` key AND its DPoP key is that agent. Rotation and
  incident response are the owner's: revoke the authorization (immediate
  for issuance and introspection), then replace the installation's keys.
- **Owner assignment for pre-existing service accounts** is not built:
  such accounts cannot participate until an assignment path exists.
- **No DPoP server nonce**; no general RFC 9396 support beyond the one
  closed type; no cross-IdP federation, guests, more than two
  participants, or cross-owner sessions (deferred by the specification).

## Rules armed (rulefloor)

AYGHU-SAME-OWNER-1, AYGHU-TWO-PARTICIPANTS-1, AYGHU-POLICY-DIGEST-1
(P-031); AYGHU-ORG-SCOPE-1, AYGHU-STORE-503-1, AYGHU-AUDIT-1 (P-032);
AYGHU-NO-BEARER-1, AYGHU-DPOP-THUMBPRINT-1, AYGHU-REVOKE-STOPS-ISSUANCE-1,
AYGHU-DPOP-REPLAY-1 (P-033); AYGHU-REVOKED-INACTIVE-1,
AYGHU-INTROSPECT-503-1, AYGHU-INTROSPECT-NO-KEYS-1 (P-034);
AYGHU-OWNER-AT-ISSUANCE-1, AYGHU-ACI-ADDRESS-1, AYGHU-NO-WIDENING-1,
AYGHU-TOKEN-BINDING-1, AYGHU-NO-REFRESH-1, AYGHU-TOKEN-AUDIT-SAFE-1,
AYGHU-IDENTITY-SIGNED-1 (P-035). Every rule is mutation red-proved.

## Conformance table (specification clause → where built → proof → verdict)

Verdicts: **met**, **gap** (closed in P-035 unless stated), **deferred**
(with the ruling that deferred it), **n/a** (outside the IdP by the
specification's own boundary).

| Clause | Where built | Proof | Verdict |
|---|---|---|---|
| Terminology: "owner" in new prose, API, docs, comments, audit, errors; no new human-facing "user" | domain/service/handlers/docs wording; audit keys owner_id / revoked_by | terminology sweep (P-035: two "human user" phrases corrected) | met |
| Initial inspection (remote main, instructions, tree, review list, gograph plan/review, rulefloor red proofs) | every slice's pre-flight and close ritual | wiki pins P-031…P-035; GATE-RUN witnesses | met |
| No new general Agent principal; service accounts = identities; OAuth clients = installations | domain.AgentCommunicationParticipant references ServiceAccountID + OAuthClientID | TestAgentCommAPI_Create_HappyPath | met |
| ACI = opaque UUIDv7 address, not a credential/secret/key/JWT/contact address | uuidgen.NewV7 allocation; no lookup accepts an ACI as auth | AYGHU-ACI-ADDRESS-1; TestAgentCommunicationAuthorization_Validate (aci not v7) | met |
| IdP allocates authorization id, session id, both ACIs; all new identifiers UUIDv7 | service.Create + domain.Validate requireV7 | TestAgentCommAPI_Create_IgnoresClientSuppliedServerFields; validate table | met |
| IdP never possesses plaintext, keys, prompts, contents | no such fields anywhere; audit/response safe sets | AYGHU-AUDIT-1, AYGHU-TOKEN-AUDIT-SAFE-1, AYGHU-INTROSPECT-NO-KEYS-1 | met |
| IdP records/signs capabilities, does not enforce | policy digest in the token; no enforcement code | token claim tests | met (see "not protected against") |
| Issuer key signs tokens; no owner key/signature in the ACI | jwtAccessTokenMinter; ACI = bare UUID | AYGHU-IDENTITY-SIGNED-1 | met |
| v1: two participants, same trust domain; active/non-deleted/unexpired SAs; same org; distinct SAs; client bound; asymmetric method; registered keys; distinct ACIs; approved thumbprint; same owner; ownerless refused | domain.CheckAgentCommunicationSameOwner, CheckAgentCommunicationParticipantClient; service.Create | TestAgentCommAPI_Create_RefusalStatuses (20 rows), AYGHU-SAME-OWNER-1, AYGHU-TWO-PARTICIPANTS-1 | met |
| Deferred: federation, external issuers, guests, anonymous, discovery, registries, contact addresses, >2 participants, cross-owner | not built | — | deferred by the specification ("Defer") |
| Same-owner at creation | service.Create → CheckAgentCommunicationSameOwner | AYGHU-SAME-OWNER-1 | met |
| Same-owner re-checked at issuance | IssueAgentCommunication participant_owner_mismatch | AYGHU-OWNER-AT-ISSUANCE-1 | **gap found by the audit, closed in P-035** |
| Owner comparison lives in the IdP only | no owner claim in tokens; relay/peers get none | AYGHU-TOKEN-BINDING-1 (no owner identity) | met |
| Boot carries client key + DPoP key; owner identity never a config/env/message field | token endpoint contract | AYGHU-TOKEN-BINDING-1 | met (enrollment ceremony is the agent's; see TOFU limit) |
| Enrollment: owner approves the thumbprint at creation | proof_key_thumbprint on the participant | create tests, AYGHU-DPOP-THUMBPRINT-1 | met |
| Session invocation: client credentials + DPoP + authorization_details {authorization_id, aci} | HandleToken branch → IssueAgentCommunication | TestTokenAgentComm_HappyPath_ContractOnTheWire | met |
| Messages carry the token, never an owner field; receiver/relay verify signature, same session id, audience, cnf.jkt; relay introspects | documented relay duties; session_id in every token | lifecycle e2e (same session_id in both tokens) | n/a for the IdP beyond the claims (relay-side) |
| First-class aggregate with the suggested fields; closed roles | domain.AgentCommunicationAuthorization / Participant | domain tests | met |
| Domain invariants (all 23 bullets) | domain.Validate + service + migration 0037 constraints/triggers | validate table, AYGHU-TWO-PARTICIPANTS-1, AYGHU-POLICY-DIGEST-1, migration_0037 guard; DB triggers exercised by the fresh-appliance mint | met (direct-write refusal proven by constraints, not by a unit test — see gaps) |
| State model active/revoked/expired; no other states; revocation permanent | domain.Status; DB trigger aca_revocation_terminal | TestAgentCommunicationAuthorization_Status; revoke tests | met |
| Capability vocabulary and rules; empty = communication only; no self-grant | domain vocabulary; capabilities only settable by the owner at creation | TestAgentCommunicationCapabilities_ClosedVocabulary; AYGHU-NO-WIDENING-1 | met |
| Canonical policy digest requirements | AgentCommunicationPolicy.Canonical/Digest | AYGHU-POLICY-DIGEST-1, TestAgentCommunicationPolicy_CanonicalForm | met |
| Admin API: the four routes, no PUT/PATCH | RegisterAgentCommunicationAuthorizationRoutes | api-docgen golden (143), AYGHU-NO-WIDENING-1 | met |
| Creation request/response contents; never secrets/keys/tokens/proofs/hashes | request/response types | TestAgentCommAPI_Create_HappyPath (forbidden keys) | met |
| Owner authority: same-org owner; cross-org create refused; cross-org read/revoke no oracle; platform admin ≠ tenant owner; audited emergency revocation; no widening | agentCommunicationActor; RevokeForActor; audit | AYGHU-ORG-SCOPE-1, AYGHU-AUDIT-1, AYGHU-NO-WIDENING-1 | met |
| List/read: scoped; pagination conventions; no key material; thumbprints not keys; effective state | ListForActor; DTO | list tests; AYGHU-INTROSPECT-NO-KEYS-1 (thumbprint only) | met (the family's existing convention is an unpaginated list, as service accounts) |
| Revocation: terminal, actor/timestamp/bounded reason, sanitized, idempotent, stops issuance, introspection inactive | Revoke + propagation | TestAgentCommAPI_GetListRevoke, AYGHU-REVOKE-STOPS-ISSUANCE-1, AYGHU-REVOKED-INACTIVE-1 | met |
| OAuth issuance: extend the token path; request shape; closed detail type; unknown/missing/multiple/malformed fail closed; only activated with details; existing grants unchanged; no general RFC 9396 claim | token_service_agent_communication.go; HandleToken switch | TestIssueAgentCommunication_Refusals, TestTokenAgentComm_LegacyClientCredentialsUntouched, discovery test | met |
| Issuance verification list (13 bullets) | IssueAgentCommunication | refusal tests, AYGHU-TOKEN-BINDING-1, AYGHU-OWNER-AT-ISSUANCE-1 | met |
| Token claims required set; binding set; excluded set | Extra claims | TestIssueAgentCommunication_HappyPath_DPoPBoundNoRefresh | met |
| TTL config: 5 min default, 15 max, min(TTL, authorization expiry); no refresh | resolveAgentCommunicationTokenTTL; issuance | TestResolveAgentCommunicationTokenTTL, TTL cap test, AYGHU-NO-REFRESH-1 | met |
| Proof of possession (RFC 9449 list) | VerifyDPoPTokenEndpointProof + replay store | TestVerifyDPoPTokenEndpointProof_*, AYGHU-NO-BEARER-1, AYGHU-DPOP-THUMBPRINT-1, AYGHU-DPOP-REPLAY-1 | met (no server nonce: not required by the clause) |
| Never log raw proofs or tokens | audit/log sinks receive identifiers only | AYGHU-TOKEN-AUDIT-SAFE-1 | met |
| Reuse replay/clock seams; do not conflate assertion and proof identifiers | dpop_proof_replays separate table | migration_0038 guard | met |
| Introspection: RFC 7662 + safe fields; inactive conditions; fail closed; 503 on store failure | IntrospectionService.WithAgentCommunication | truth-table tests, AYGHU-INTROSPECT-503-1, AYGHU-INTROSPECT-NO-KEYS-1 | met |
| Revocation semantics: both participants, introspection inactive, permanent, audited | propagation + triggers + audit | AYGHU-REVOKED-INACTIVE-1, propagation tests | met |
| Document offline-verification limits honestly | this page | — | met |
| Audit events: created, issued, revoked, refusals; safe metadata; never-list | handlers | AYGHU-AUDIT-1, AYGHU-TOKEN-AUDIT-SAFE-1, refusal tests | met |
| Security/product boundaries (no relay, storage, crypto custody, …) | nothing of the kind exists | review of the surface | met |
| OSS/CE boundary | all in OSS; no CE change | — | met |
| Testing requirements (identity/tenancy, identifiers, policy, issuance, PoP, introspection, confidentiality) | the suites named above | all bullets covered except "deleted service accounts are refused" (a deleted account is unreadable through the typed not-found store answer — covered indirectly) and "database constraints reject invalid direct writes" (constraints exist; no Go integration test writes rows directly) | met / 2 indirect (see gaps) |
| Rulefloor requirements: the eleven named rules, genuine red proofs | 20 rules | RULE-FLOOR.md | met |
| Verification steps (format, tests, migration tests, integration, go test ./..., lint, vuln, rulefloor, gograph rebuild+review, gate, diff check) | each slice's make verify + close ritual | GATE-RUN witnesses | met |
| Final report contents | each slice's report | — | met |
| "Do not claim completion if PoP, tenant isolation, revocation or binding remains advisory" | all four are refusals with red-proved rules | this table | met |

### Gaps and deferrals in one place

- Closed in P-035: owner binding re-checked at issuance; the seven
  spec-named rules that lacked their own ledger row; terminology.
- Indirect, not closed (small, measured): a Go integration test that
  writes invalid rows directly and watches the 0037 triggers refuse
  (constraints exist and run on every fresh-appliance mint; cost ≈ one
  integration-profile test file); an explicit "deleted service account"
  refusal test (the store hides deleted rows behind the typed not-found;
  cost ≈ one table row in the refusal test).
- Reported, not started (large): an owner-assignment/transfer path for
  pre-existing service accounts (new route, census 143 → 144, matrix
  cells, transfer rules while an authorization is active); the
  `LookupForClient` AUTH-503 collapse on the legacy client-credentials
  path (outside the AYGHU surface).
- Deferred by the specification: federation, external assertion issuers,
  guests, anonymous participants, discovery, registries, persistent
  contact addresses, more than two participants, cross-owner sessions.
