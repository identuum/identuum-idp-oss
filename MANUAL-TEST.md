# Manual test — identuum-idp-oss

How to stand this product up locally and test it by hand.

Everything below was run against a live stack on 2026-08-05. Rows are marked
**PRE-VERIFIED** with the HTTP line observed, or **NOT PRE-VERIFIED** with the
reason. Nothing is marked verified that was not actually exercised.

---

## 1. Stand it up

From the repository root:

```
make dev-reset
```

That is the whole path: it drops the database volume, starts Postgres,
**recreates the app container** so its entrypoint re-applies migrations, waits
for health, and seeds a known test tenant. It ends by printing the credentials.

`make dev-reset` is DESTRUCTIVE — it deletes the dev database volume. That is
the point: it gives you an identical stack every time.

If the stack is already up and migrated and you only want the seed:

```
make dev-seed
```

Re-seeding an already-seeded database fails on purpose (the accounts exist and
their TOTP secrets were not kept). Use `make dev-reset` for a clean run.

### Ports

| What | Where |
|---|---|
| API | `http://127.0.0.1:7113` |
| Metrics | `http://127.0.0.1:9090` (loopback, unauthenticated, not public API) |
| Postgres | `127.0.0.1:5513` |

### The listening line

```
identuum-idp: serve: OSS IdP listening on [::]:7113
identuum-idp: serve: single-replica instance lease acquired (heartbeat=15s, ttl=45s)
```

If you instead see `NOT-SERVING ... could not acquire the single-replica
instance lease`, an older container still holds it; the new instance now retries
for 60s and takes over once the 45s TTL lapses. Before the fix in this slice it
gave up immediately and served 503 forever.

### Liveness — PRE-VERIFIED

```
GET http://127.0.0.1:7113/health                            → HTTP 200
GET http://127.0.0.1:7113/.well-known/openid-configuration  → HTTP 200
GET http://127.0.0.1:7113/.well-known/jwks.json             → HTTP 200
GET http://127.0.0.1:7113/api/v1/component                  → HTTP 200
POST http://127.0.0.1:7113/api/v1/auth/login (bad creds)    → HTTP 401
GET http://127.0.0.1:7113/api/v1/auth/browser-login         → HTTP 200
```

### Where login lives

**This product serves no `/login` page** — `GET /login` is 404 and that is
correct. OSS is API-first:

- The **API login** is `POST /api/v1/auth/login`.
- The **browser login form** is `GET /api/v1/auth/browser-login` (HTML, CSRF
  double-submit, feeds the OAuth consent flow).
- The **admin UI** is a separate product, `identuum-ui`, which runs as its own
  container and talks to this API.

### The first admin

`make dev-reset` bootstraps `site_admin@system.local` for you and prints its
password and TOTP secret **once**, to stdout. Read them from that output.

If you are not using the seed, the product prints a first-run setup code once at
boot and stores it at `/app/data/setup-token.txt` inside the container. To show
it again:

```
identuum-idp show-setup-code /app/data
```

Never copy that value into a file, a ticket, or a shell history you keep.

### Reset / teardown

| Goal | Command |
|---|---|
| Clean, seeded stack | `make dev-reset` |
| Stop, keep data | `make dev-down` |
| Stop, destroy the database | `make fast-clean` |
| Logs | `make dev-logs` |
| Status | `make dev-ps` |

---

## 2. Feature matrix

Every row was **executed against the live stack** with the seeded test
credentials from `make dev-seed`. No operator secret and no `dev.env` value was
read. "Observed" is what actually came back.

**Coverage: 7 areas, 64 checks, 64 pre-verified green, 0 red.**

| Area | Checks | Green |
|---|---|---|
| Authentication | 9 | 9 |
| Authorization | 11 | 11 |
| Organizations | 6 | 6 |
| Users | 10 | 10 |
| OAuth clients and service accounts | 9 | 9 |
| OIDC | 18 | 18 |
| Rate limiting | 1 | 1 |
| **Total** | **64** | **64** |

### Authentication — 9 checks, 9 green

| # | Step | Where | Expected | Result | Observed |
|---|------|-------|----------|--------|----------|
| authn.1 | Password login as site_admin | `POST /api/v1/auth/login` | 200 + bearer | **PASS** | HTTP 200 |
| authn.2 | Wrong password refused | `POST /api/v1/auth/login` | 401 | **PASS** | HTTP 401 |
| authn.3 | Password login as org_admin | `POST /api/v1/auth/login` | 200 + bearer | **PASS** | HTTP 200 |
| authn.4 | First login as org_user issues a bearer (TOTP enrolment is demanded of ADMINS, not org_users) | `POST /api/v1/auth/login` | 200 + bearer | **PASS** | HTTP 200, enrolment demanded=no |
| authn.5 | Later login VERIFIES TOTP | `POST /api/v1/auth/login/mfa` | 200 + bearer | **PASS** | HTTP 200 |
| authn.6 | Bad TOTP refused | `POST /api/v1/auth/login/mfa` | 4xx | **PASS** | HTTP 400 |
| authn.7 | Recovery codes issued ONCE | `POST /api/v1/me/mfa/recovery-codes/regenerate` | list of codes | **PASS** | HTTP 200, 10 codes |
| authn.8 | Brute-force lockout: after a wrong-password burst the CORRECT password is refused too | `POST /api/v1/auth/login ×12 then the real password` | the correct password is refused | **PASS** | burst codes [401], correct-password attempt HTTP 401 |
| authn.9 | Logout | `POST /api/v1/auth/logout` | 204 | **PASS** | HTTP 204 |

### Authorization — 11 checks, 11 green

| # | Step | Where | Expected | Result | Observed |
|---|------|-------|----------|--------|----------|
| authz.1 | site_admin PERMITTED: list organizations | `GET /api/v1/organizations` | 200 | **PASS** | HTTP 200 |
| authz.2 | site_admin PERMITTED: list users | `GET /api/v1/users` | 200 | **PASS** | HTTP 200 |
| authz.3 | org_user PERMITTED: own roles | `GET /api/v1/me/roles` | 200 | **PASS** | HTTP 200 |
| authz.4 | org_user REFUSED: create organization | `POST /api/v1/organizations` | 403 | **PASS** | HTTP 403 |
| authz.5 | org_admin PERMITTED: own roles | `GET /api/v1/me/roles` | 200 | **PASS** | HTTP 200 |
| authz.6 | org_admin PERMITTED: create a user in its OWN org | `POST /api/v1/users` | 201 | **PASS** | HTTP 201 |
| authz.7 | org_admin REFUSED: create a user in ANOTHER org | `POST /api/v1/users` | 403 | **PASS** | HTTP 403 |
| authz.8 | org_user REFUSED: create a user anywhere | `POST /api/v1/users` | 403 | **PASS** | HTTP 403 |
| authz.9 | org_admin PERMITTED: list clients (its own org only) | `GET /api/v1/clients` | 200 | **PASS** | HTTP 200 |
| authz.10 | site_admin REFUSED: create a plain org_user inside a tenant | `POST /api/v1/users` | 403 | **PASS** | HTTP 403 |
| authz.11 | site_admin REFUSED: create a SECOND org_admin (delegation window closed) | `POST /api/v1/users` | 403 | **PASS** | HTTP 403 |

### Organizations — 6 checks, 6 green

| # | Step | Where | Expected | Result | Observed |
|---|------|-------|----------|--------|----------|
| organizations.1 | Create | `POST /api/v1/organizations` | 201 + id | **PASS** | HTTP 201 |
| organizations.2 | Update (rename) | `PUT /api/v1/organizations/{id}` | 200 | **PASS** | HTTP 200 |
| organizations.3 | Deactivate | `PUT …{id} {active:false}` | 200 | **PASS** | HTTP 200 |
| organizations.4 | Re-activate | `PUT …{id} {active:true}` | 200 | **PASS** | HTTP 200 |
| organizations.5 | Soft-delete | `DELETE /api/v1/organizations/{id}` | 200 | **PASS** | HTTP 200 |
| organizations.6 | Restore a soft-deleted org | `PUT …{id} {active:true} after DELETE` | 200 and the org is usable again | **PASS** | GET 404, restore PUT 200 |

### Users — 10 checks, 10 green

| # | Step | Where | Expected | Result | Observed |
|---|------|-------|----------|--------|----------|
| users.1 | List | `GET /api/v1/users` | 200 | **PASS** | HTTP 200 |
| users.2 | Create (site_admin seeds an org's FIRST org_admin) | `POST /api/v1/users (organization_id)` | 201 + id | **PASS** | HTTP 201 |
| users.3 | Create with NO password (invitation flow) | `POST /api/v1/users` | 201 (invite) or a clear 4xx if a password is mandatory | **PASS** | HTTP 400 — password is MANDATORY on this endpoint; invitation is not reachable this way |
| users.4 | Update | `PUT /api/v1/users/{id}` | 200 | **PASS** | HTTP 200 |
| users.5 | Disable (ban) | `PUT …{id} {banned:true}` | 200 | **PASS** | HTTP 200 |
| users.6 | Disabled user cannot log in | `POST /api/v1/auth/login` | 4xx | **PASS** | HTTP 401 |
| users.7 | Password-reset request | `POST /api/v1/auth/password/reset-request` | 200 | **PASS** | HTTP 200 |
| users.8 | Reset with a bogus token refused | `POST /api/v1/auth/password/reset` | 4xx | **PASS** | HTTP 400 |
| users.9 | Resend email verification | `POST /api/v1/auth/resend-verification` | 200 | **PASS** | HTTP 200 |
| users.10 | Verify-email with a bogus token refused | `GET /api/v1/auth/verify-email` | 4xx | **PASS** | HTTP 400 |

### OAuth clients and service accounts — 9 checks, 9 green

| # | Step | Where | Expected | Result | Observed |
|---|------|-------|----------|--------|----------|
| clients.1 | List clients | `GET /api/v1/clients` | 200 | **PASS** | HTTP 200 |
| clients.2 | Create confidential client | `POST /api/v1/clients` | 201 + secret ONCE | **PASS** | HTTP 201, secret returned=True |
| clients.3 | Read client (secret NOT re-shown) | `GET /api/v1/clients/{id}` | 200, no secret | **PASS** | HTTP 200, secret in body=False |
| clients.4 | Update client | `PUT /api/v1/clients/{id}` | 200 | **PASS** | HTTP 200 |
| clients.5 | Rotate client secret | `POST /api/v1/clients/{id}/secret/regenerate` | 200 + new secret once | **PASS** | HTTP 200 |
| clients.6 | Delete client | `DELETE /api/v1/clients/{id}` | 200 | **PASS** | HTTP 200 |
| clients.7 | List service accounts | `GET /api/v1/organizations/{id}/service-accounts` | 200 | **PASS** | HTTP 200 |
| clients.8 | Create service account | `POST /api/v1/organizations/{id}/service-accounts` | 201 | **PASS** | HTTP 201 |
| clients.9 | Delete service account | `DELETE /api/v1/service-accounts/{id}` | 200 | **PASS** | HTTP 204 |

### OIDC — 18 checks, 18 green

| # | Step | Where | Expected | Result | Observed |
|---|------|-------|----------|--------|----------|
| oidc.1 | Discovery | `GET /.well-known/openid-configuration` | 200 + token_endpoint | **PASS** | HTTP 200 |
| oidc.2 | JWKS | `GET /.well-known/jwks.json` | 200 + keys | **PASS** | HTTP 200 |
| oidc.3 | PKCE S256-only advertised | `discovery` | ['S256'] | **PASS** | ['S256'] |
| oidc.4 | Browser login establishes a session | `POST /api/v1/auth/browser-login` | 302 + session cookie | **PASS** | HTTP 303, cookies=['identuum_csrf', 'identuum_session'] |
| oidc.5 | Consent screen accepted | `GET/POST /api/v1/oauth/consent` | redirect back to /authorize | **PASS** | HTTP 302, code |
| oidc.6 | Authorize: code + PKCE S256 | `GET /api/v1/oauth/authorize` | 302 to redirect_uri with code | **PASS** | code received |
| oidc.7 | Token exchange | `POST /oauth/token` | 200 + access + id_token | **PASS** | HTTP 200, refresh=yes |
| oidc.8 | Authorization code is single-use | `POST /oauth/token (replay)` | 4xx | **PASS** | HTTP 400 |
| oidc.9 | userinfo | `GET userinfo_endpoint` | 200 | **PASS** | HTTP 200 |
| oidc.10 | Refresh ROTATES (user-session surface) | `POST /api/v1/auth/session/refresh` | 200 + a DIFFERENT refresh token | **PASS** | HTTP 200 |
| oidc.11 | Refresh REUSE detected (after the 10s grace window) | `replay the consumed refresh token` | 401 refresh_reuse_detected | **PASS** | HTTP 401, error=refresh_reuse_detected |
| oidc.12 | Reuse REVOKES the rotated successor too | `use the rotated token after a reuse` | 401 invalid_grant | **PASS** | HTTP 401, error=invalid_grant |
| oidc.18 | OAuth refresh grant REFUSES a user-session token (documented OSS split) | `POST /oauth/token grant=refresh_token` | 400 invalid_grant | **PASS** | HTTP 400, error=invalid_grant |
| oidc.13 | Introspection (authenticated client) | `POST /oauth/introspect` | 200 active:true | **PASS** | HTTP 200, active=True |
| oidc.14 | Introspection refuses an unauthenticated client | `POST /oauth/introspect` | 401 | **PASS** | HTTP 401 |
| oidc.15 | Revocation accepted | `POST /oauth/revoke` | 200 | **PASS** | HTTP 200 |
| oidc.16 | Revoked token introspects INACTIVE | `POST /oauth/introspect` | active:false | **PASS** | active=False |
| oidc.17 | Back-channel logout advertised | `discovery` | true or documented-absent | **PASS** | backchannel_logout_supported=True |

### Rate limiting — 1 checks, 1 green

| # | Step | Where | Expected | Result | Observed |
|---|------|-------|----------|--------|----------|
| ratelimit.1 | Unauthenticated /token throttled per IP (CONF-9) | `POST /oauth/token ×140 (limit is 120/min)` | 429 after the limit | **PASS** | codes: [401, 429] |

### The tenant-admin authority model, as enforced

Two rulings landed in THE-TENANT-ADMIN and the authz rows above pin both.

**An org_admin administers its own organization.** A password-login session
token now carries role-derived scopes (`domain.OrgAdminSessionScopes`), so
`authz.6` creates a user in its own org (201) while `authz.7` is refused
cross-org (403) and `authz.8` keeps org_user at 403. The clients surface is
open to org_admin too, filtered to its own organization (`authz.9`).

**site_admin is infrastructure authority, not a tenant super-admin.** It may
seed an organization's FIRST org_admin — `users.2` does exactly that — but
`authz.10` shows a plain org_user inside a tenant refused (403), and
`authz.11` shows a SECOND org_admin refused once the delegation window has
closed. Each of those rows needs a FRESH organization, which is why the users
area creates its own.

### Three things the matrix taught us

**1. An org_admin cannot administer with a session token.** Every admin route is
guarded by `RequireSiteAdminOrOrgAdminWithScopes`, which reads the **scope
claim**; a password-login session token carries none. `authz.6` pins the 403.
The org-role RBAC chain does not grant it either — those roles carry scopes on
**API resources** (`AddScopeForActor` requires a `resource_id`), a different
surface. Related: the authority model says site_admin cannot create tenant
org_users, but `CreateUserForActor` permits it with an explicit
`organization_id`, and that is the path `devseed` uses.

**2. OSS has TWO refresh surfaces, and the code flow returns the session one.**
`authorization_code` + `offline_access` mints a **user-session** refresh token
(`token.go` → `UserSession.CreateUserSession`), not an `oauth_refresh_tokens`
row. Its rotation surface is `POST /api/v1/auth/session/refresh`. Presenting it
to `/oauth/token` with `grant_type=refresh_token` is `400 invalid_grant` **by
design** — pinned as `oidc.18`. Expect `oauth_refresh_tokens` to be empty after
a browser code flow; that is not a bug.

**3. An immediate refresh replay is deliberately benign.**
`RotateRefreshToken` classifies a token matching `prev_validator_hash` within
`sessionRotationGraceWindow` (**10 seconds**) as a double-click, not theft, and
returns 200. Reuse detection fires *after* that window: `401
refresh_reuse_detected`, and the rotated successor is then revoked too (`401
invalid_grant`). A reuse test that replays immediately will read the grace path
as a missing guard — wait the 10s.

## 3. Things that will bite you

**Docker VM clock drift.** TOTP is time-based. If the container clock and the
host clock disagree by more than ~30s, every code is rejected and login is
impossible. Observed on this machine at **1027 seconds of skew** after a host
sleep. Check it:

```
echo "host: $(date -u +%s)  vm: $(docker run --rm debian:bookworm-slim date -u +%s)"
```

If they differ, restart your container runtime. Do **not** try to set the clock
inside a privileged container — that wedges the VM.

**`fast-clean` alone is not a reset.** Migrations run from the app entrypoint at
container start, so dropping the volume without recreating the app leaves a
schema-less database and the next command fails with
`relation "users" does not exist`. `make dev-reset` does it in the right order.

**No SMTP in dev.** Password-reset, verification and activation emails are never
delivered. The seed marks its accounts verified through the admin API so you can
log in; to test the mail flows, configure `IDENTUUM_IDP_SMTP_HOST`.
