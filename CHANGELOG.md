# Changelog — identuum-idp-oss

All notable changes to `identuum-idp-oss` are recorded here, starting from
the first public release. Format roughly follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning
follows [Semantic Versioning](https://semver.org/).

## `v0.9.0`

Organization claim links (D-022) and self-registration (D-021), both off
until an administrator uses them; identuum-ui `v0.6.0` embedded (`36a3827`,
tree digest
`4e2f073c04be1dbd43e31526b885220306b2f8d1e19331cea71c528a27f63db5`). Delta `v0.8.2..` (`git rev-list --count`, measured at
`172757e`, before the vendor and notes commits): 29 commits, 50 files,
+2579/−188. Migration `0043` (additive; applied on boot by the image, run
`identuum-idp migrate` for the bare binary); `go.mod`/`go.sum` unchanged.
The canonical endpoint count 148 → 157. No route, field or response shape
removed or renamed; the behaviour changes are listed in
`docs/releases/v0.9.0.md`, "Upgrading".

- **The embedded UI is identuum-ui `v0.6.0`** (next 16.3.8): Issue claim
  link on an organization's page, the self-registration switches and page,
  sign-ups waiting for approval, and an archived organization's page that
  offers only Restore.
- **Self-registration** (D-021), off by default behind two switches: the
  instance switch (`PUT /api/v1/settings/self-registration`, site admin) and
  each organization's policy (`PUT /api/v1/organizations/:id/registration`,
  its organization admin: open, approval, verify email, email domains).
  `GET`/`POST /api/v1/auth/register/:org_slug` answer a closed, unknown or
  `idp_only` organization, and a new or existing address, identically (202);
  a self-registrant is always `org_user`, verifies its email when the
  organization requires it (refused without SMTP), and with approval on
  waits for its organization admin (`GET .../registrations`,
  `POST /api/v1/users/:id/approve` / `reject`; `403 registration_pending`
  until then). Rate-limited per IP (/64) and per organization; audited.
  Accounts that were not self-registered keep their sign-in gate.
  Migration `0043` (additive). Endpoint count 149 → 157.
- **Approval reads the registration state.** `POST /api/v1/users/:id/approve`
  approves a self-registrant held for approval (organization admin, own
  organization); it no longer clears an `org_user`'s `banned` flag.

- **A site administrator issues organization claim links** (D-022). New
  `POST /api/v1/organizations/:id/claim` `{email?}` answers 201
  `{claim_url, expires_at, email_bound}` once, for an active organization
  with no active administrator (else 409 `organization_not_claimable`);
  without `IDENTUUM_IDP_UI_PUBLIC_BASE_URL` it issues nothing (409
  `claim_url_unavailable`). An email binds the link and it is also mailed
  when SMTP is configured. A re-issue retires every earlier link of the
  organization. Redeeming at `/claim` is unchanged on the wire; the new
  administrator enrols MFA at first sign-in. Issue and redemption are
  audited (`claim.generated` with the issuer and the retired count,
  `claim.consumed` with the new administrator); no row carries the token.
  Endpoint count 148 → 149.
- **Claim redemption checks the organization at redemption time.** A claim
  is redeemed only into an active organization that still has no active
  administrator; otherwise the link is retired and the answer is the same
  opaque `{"success":false}`. (Before, redemption required an inactive
  organization, so no link a site administrator could issue was redeemable.)

## `v0.8.2`

identuum-ui `v0.5.3` embedded (`0630183`, tree digest `f1fd1583…e0e79a`).
Delta `v0.8.1..` (`git rev-list --count`, measured at `8efe9cb`, before the
vendor and notes commits): 21 commits. No migration; no route, field or
response shape removed or renamed; one default changed (the bare binary's
listen is IPv4 only, see Upgrading in `docs/releases/v0.8.2.md`). Notes:
`docs/releases/v0.8.2.md`.

- **The embedded UI's next moves to 16.3.7**, the newest stable that clears
  pnpm's release age without an exclude list. The export's files are
  byte-identical to the previous build's (same tree digest).
- **The remaining expected-state answers honour the step-status opt-in.**
  With `X-Identuum-Login-Step-Status: 200`, `password_change_required` at
  `POST /api/v1/auth/login` and the MFA continuation of
  `POST /api/v1/auth/login/password-change` answer 200 with the same body
  (still no session, cookie or token); `GET /api/v1/validate` and the browser
  refresh answer a caller who presents no credential 200
  `{"authenticated":false}` (no session, no cookie). Without the header every
  answer is unchanged; a credential that does not verify is still a 401. The
  embedded console sends it, so a signed-out visit to `/` and a sign-in that
  must change its password no longer log a browser console error.
- **Console and application sign-ins are separate** (D-023), now written in
  the operator guide.
- **Development compose stack has its own names** (D-024):
  `deployment/docker-compose.dev.yml` defaults to the project
  `identuum-idp-oss-dev` (containers `identuum-idp-oss-dev`,
  `identuum-idp-oss-dev-postgres`, image `identuum-idp-oss-dev:local`), so it
  and the production compose file can run on one host. The production
  compose file is unchanged. For a developer: the dev database volume is
  project-scoped, so the first `make fast-up` after this change starts an
  empty dev database, and a still-running pre-change dev stack keeps port 5513
  until it is stopped; `IDENTUUM_IDP_COMPOSE_PROJECT=identuum-idp-oss` keeps
  the old stack.

- **IPv4 is the default everywhere; IPv6 is supported and opt-in.** The
  default listen `0.0.0.0:7113` (and an empty host, `:7113`) is now IPv4
  only. `[::]:7113` listens on IPv6 (dual-stack where the OS allows); an
  IPv6 literal listens on that address only. The same rule applies to the
  metrics listener (default unchanged, `127.0.0.1:9090`). The healthcheck
  probes `[::1]` for `[::]`. The compose file's `IDENTUUM_IDP_BIND_ADDRESS`
  takes an IPv6 address (`'[::]'`); its header shows how to publish both
  families. Rate limits and the sign-in lockout count an IPv6 client by its
  `/64` (IPv4 unchanged), so rotating inside a `/64` no longer reaches a
  fresh limit; `IDENTUUM_IDP_TRUSTED_PROXIES` takes IPv6 CIDRs.
  **Upgrading:** the bare binary's default listen was dual-stack in `v0.8.1`
  — `0.0.0.0:7113` accepted IPv6 connections too (measured: a `[::1]` dial
  answered). It is IPv4 only now; to keep IPv6, set
  `IDENTUUM_IDP_LISTEN='[::]:7113'` (or `--listen '[::]:7113'`). The compose
  install is unchanged: it already published IPv4 only.
- **Sign-in, the password step's MFA next step can answer 200** (opt-in).
  `POST /api/v1/auth/login` still answers a correct password whose next step
  is MFA with 401 `mfa_required` / `mfa_enrollment_required` by default. A
  request carrying `X-Identuum-Login-Step-Status: 200` receives the same body
  with status 200 — still no session, cookie or token. Every other answer
  (a wrong password, a locked account, rate limiting) is unchanged with or
  without the header, and so are the audit rows. The embedded console sends
  it, so an MFA sign-in no longer logs a browser console error.

## `v0.8.1`

A patch: identuum-ui `v0.5.2` embedded (`bbd6578`, tree digest
`fa82552b…659639`; identuum-ui `v0.5.1` was tagged and never published).
Delta `v0.8.0..` (`git rev-list --count`, measured at `fdb9357`, before
this notes commit): 14 commits. No migration; no route,
field or response shape changed. Notes: `docs/releases/v0.8.1.md`.

### Fixed

- Embedded console: an organization created without an admin email now
  offers **Invite the first administrator** on its Assign administrator
  page, instead of only a re-issue that answered "already active" (GitHub
  issue #1). The invitation uses the existing first-admin rule: a site
  admin may invite an organization's first administrator, and only while it
  has none.

### Security

- The embedded UI's next moves to 16.3.6 (GHSA-vcvr-r3jv-pc5j). The console
  is a static export — no Next server runs and `next/og` is not used — so
  the vulnerable path was not reachable; the export's files are unchanged.

## `v0.8.0`

A user created with a password chooses their own at first sign-in (D-017),
an organization admin can mark its own application first-party (D-018), and
the audit log says who did what to which organization; identuum-ui `v0.5.0`
embedded. Delta `v0.7.0..` (`git log`/`git diff --shortstat`, measured at
`5d8ffa3`, before this notes commit): 34 commits, 76 files, +2523/−186.
Migrations `0041` and `0042` (applied on boot by the image; run
`identuum-idp migrate` for the bare binary), no dependency moved
(`go.mod`/`go.sum` unchanged), Go 1.27.1. The canonical endpoint count
147 → 148. No route, field or response shape removed; the behaviour changes
are listed in docs/releases/v0.8.0.md, "Upgrading".

### Added

- **Admin-set passwords the Microsoft way** (OSS-FIN-1, owner ruling D-017):
  a user created with a password (`POST /api/v1/users`, `/users/bulk`) is
  active and verified at once — the admin vouches; `user.created` records
  `password_set_by_admin` and `must_change_password`. By default the user must
  choose their own password at first sign-in: `POST /api/v1/auth/login`
  answers `401 password_change_required` with a one-time `session_id`, and the
  new `POST /api/v1/auth/login/password-change {session_id, new_password}`
  sets it (organization policy; not the admin-set one; `400 weak_password`
  keeps the handle), then continues to MFA enrolment or verification when the
  policy asks, else the session. The OpenID Connect browser sign-in renders
  the same step. `must_change_password: false` lets the admin-set password
  stand. Migration `0041` admits the pending kind; canonical endpoint count
  147 → 148. Users created with a password before this release are unchanged
  (still unverified). docs/OPERATOR-GUIDE.md "Creating a user with a password
  instead".
- **`activation_pending` on the organization read surface** (OSS-FIN-1):
  org_admins exist and none has activated — the state `PUT active=true`
  refuses with `409 activation_pending`.
- **First-party clients** (OSS-FIN-2, owner ruling D-018(b)): `POST` and
  `PUT /api/v1/clients` accept `skip_consent` for the caller's own
  organization's client, and every client read returns it. `/authorize`
  then issues the code without the consent page (`prompt=consent` still
  shows it), and `oauth_authorize.code_issued` records `consent_skipped`.
  `client.updated` records `skip_consent_before` and `skip_consent_after`.
  A public client is refused `400 invalid_request` ("skip_consent requires
  a confidential client", RFC 8252 §8.6); dynamic client registration
  cannot set it.
- **Inviting a user created with a password before D-017** (OSS-FIN-2):
  `POST /api/v1/users/:id/invite` now also invites a local user who is
  unverified and holds no invite (created with a password in `v0.7.0` or
  earlier); redeeming sets a new password and verifies the account. A
  verified user is still `409 user_not_pending`.
- **TOTP enrolment at the OpenID Connect browser sign-in** (OSS-FIN-2):
  after the D-017 change step, a user whose organization requires MFA and
  who has none enrols an authenticator app on the same form (the key and
  its `otpauth://` link as text, the recovery codes once, then a code) and
  is signed in; a wrong code asks again. The console hand-off page remains
  only for an enrolment that cannot start.

- **The audit log says who did what to which organization** (OSS-FIN-3,
  audit F4): every row carries its actor, filled centrally from the signed-in
  principal (`user`, `service_account`, `client`; `setup_token` and `system`
  where set; `anonymous` only without one); a client's id is in
  `metadata.actor_client_id`. Migration `0042` adds `organization_id`, the
  organization acted upon (the event's, else its metadata's, else an
  organization-bound actor's), with an index; existing rows are backfilled
  only from a metadata `organization_id` naming an existing organization.
  `actor_organization_id` is now the actor's own organization. The read
  API returns `organization_id`. docs/OPERATOR-GUIDE.md "Reading the audit
  log".
- **`identuum-idp bootstrap` is audited like the setup wizard**
  (OSS-FIN-3): `setup.completed` and `user_created` for the `site_admin` it
  creates, actor `system`.
- **TOTP enrolment at the OpenID Connect browser sign-in without a password
  change first** (OSS-FIN-3): a user whose organization requires MFA and
  who has none enrols on the sign-in form, as after the D-017 change step.

### Changed

- **The embedded UI is identuum-ui `v0.5.0`** (`2e552be`, tree digest
  `bf41513457ab23b76e55159a8e0f7f05ec52804dd26e392ccda16e38f83f7000`):
  "Choose a new password" at first sign-in, "First-party (skip consent)" on
  applications, "Send invitation" for users created with a password before
  D-017, and the actor and Organization columns in the audit tables.
- **An organization admin's audit view shows its organization's rows,
  whoever acted** (OSS-FIN-3): `GET /api/v1/audit/events` for an org_admin
  returns every row whose `organization_id` is its own — a site admin's
  changes included — and none of another organization's; rows from before
  `0042` keep their `actor_organization_id` visibility. It used to clamp on
  `actor_organization_id` alone, which most call sites left empty.
- A user flagged `requires_password_change` used to be refused as
  `invalid_credentials` after a correct password; the flag now leads to the
  change step above.
- **RP-initiated logout without `post_logout_redirect_uri` shows a
  signed-out page** (OSS-FIN-2, owner ruling D-018(a)):
  `/api/v1/oidc/logout` answers `200` with a static "You are signed out"
  page (`no-store`, a CSP with no scripts, naming no user or client) after
  the same termination, instead of `204` with no body. The redirect case,
  its refusals and the `204` for an unresolved client with a redirect are
  unchanged.

## `v0.7.0`

An organization admin adds users without mail, a site admin re-issues a
lost activation link from the console, and each release ships Linux
binaries; identuum-ui `v0.4.0` embedded. Delta `v0.6.3..` (`git log`/`git
diff --shortstat`, measured at `929951f`, before this notes commit): 55
commits, 73 files, +3800/−208. No migration (`0001`–`0040`, as in
`v0.6.3`), no dependency moved (`go.mod`/`go.sum` unchanged), Go 1.27.1.
The canonical endpoint count 144 → 147. No route, field or response shape
removed; the new refusals are listed in docs/releases/v0.7.0.md,
"Upgrading".

### Added

- **Invite a user with a one-time link** (OSS-ONBOARD-A, owner ruling D-016):
  `POST /api/v1/users` without a password creates a pending user and answers
  `{user, invite_token, invite_url | invite_url_unavailable, expires_at}` once;
  `POST /api/v1/users/:id/invite` re-issues (the older link stops working;
  a user who is not pending is `409`); the public
  `GET /api/v1/auth/invite/:token` and `POST /api/v1/auth/invite` validate and
  redeem (password under the organization's policy, then verified and
  active; `invalid_token` for unknown, expired or spent; rate-limited like
  sign-in). With SMTP configured the link is also mailed. The token is 256-bit,
  stored hashed, single-use, 24 hours; audited as `user.invited`,
  `user.invite_reissued` and `user.invite_redeemed` without it. `GET
  /api/v1/component` declares `user_invite`; users carry
  `invitation_pending`. No migration: the invite uses the user row's
  activation columns. Canonical endpoint count 144 → 147. The creation with a
  password is unchanged. docs/OPERATOR-GUIDE.md "Invite a user".
- **Linux binaries per release** (OSS-BINARIES, owner ruling): the manual
  workflow `.github/workflows/publish-binaries.yml` builds
  `identuum-idp-oss_<version>_linux_amd64` and `…_linux_arm64`
  (`CGO_ENABLED=0`, `-trimpath`, version and commit stamped, the embedded UI
  checked against its manifest), writes `SHA256SUMS` over both and attests
  each binary's build provenance. `dry_run` (the default) keeps them as
  workflow artifacts; otherwise they are uploaded to the existing release of
  the verified tag, never replacing an asset. README "Running the bare
  binary"; deployment/README "Releasing: the binaries".

### Changed

- **Reactivating a never-activated organization is refused** (OSS-BINARIES):
  `PUT /api/v1/organizations/:id` with `{"active":true}` answers `409
  activation_pending` and changes nothing while the organization's
  administrators have never activated; the administrator's activation link
  activates it. It used to switch the organization on without its
  administrator, whose link then answered `organization_already_active`. A
  shell organization, or one whose administrator has activated, reactivates
  as before. The refusal's message names the console action, **Re-issue
  activation link** on the organization's page (OSS-FINAL).

- **The embedded UI is identuum-ui `v0.4.0`** (`55af159`, tree digest
  `20950ed95cf47bad23bf215665e4ca1bcee70738c23c4adf54673e18fb4eebf6`). From
  `05f0c96` (OSS-ONBOARD-B): Users →
  Invite user (`/org-admin/users/new`) shows the one-time link, its token and
  its expiry once; pending users read "Invitation pending" and their page
  re-issues. The public `/invite?token=` page validates the link, sets the
  password and sends the user to sign-in. Each of these appears only where
  `user_invite` is declared. From `cf2f5f7` (OSS-POLISH) a deleted
  organization's row in the site-admin list links only to Restore. From
  `9745185` (OSS-BINARIES) the new-organization form says the activation
  link is shown to hand over and mailed only when email delivery is
  configured, and Reactivate on a never-activated organization explains its
  `409` instead of "Try again". From `8d30b24` (OSS-FINAL) a pending
  organization's page offers **Re-issue activation link**: after a
  confirmation it shows the new link with Copy, its token and its expiry once,
  and the earlier link stops working (it was reachable only once the
  activation had expired); assign-admin, `/activate` and `/claim` say what
  D-016 says.
- **`identuum-idp healthcheck` (the image's Docker HEALTHCHECK) reports
  unhealthy when the database is unreachable** (OSS-POLISH). It now requires
  `/healthz` and the new unannotated `/readyz` (503
  `{"status":"store_unreachable"}` when the store does not answer a ping).
  `/health` and `/healthz` stay liveness. The canonical endpoint count is
  unchanged.
- **The setup token no longer lands in the working directory** (OSS-POLISH).
  With `IDENTUUM_IDP_DATA_DIR` unset, the data directory is the per-user
  config directory's `identuum-idp`. The image still uses `/app/data`.
- **An invite or activation that is not mailed because SMTP is not
  configured logs Info**, "not mailed: delivery not configured" (D-016's
  default mode), not WARN. Delivery failures, password reset and email
  verification still log WARN.
- **The published image names its commit** (OSS-POLISH):
  `publish-image.yml` passes the tagged commit as `COMMIT`, so
  `identuum-idp version` no longer reports "commit unknown".

### Fixed

- **Audit gaps** (OSS-POLISH, rehearsal F4 and F7):
  - Setup completion records `setup.completed` and `user_created` (the
    first admin).
  - Disable and enable record `user_deactivated` / `user_activated` with
    the actor, not a bare `user.updated`.
  - A code minted from the consent page records
    `oauth_authorize.code_issued`.
- **A restored organization's admin-recovery candidates answer 200**, not
  404, so the site-admin recovery panel shows its admins (ORG-RESTORE-1).
- **The activation link works without SMTP** (OSS-RC): `GET /api/v1/component`
  declares `activation_link`, and the embedded UI (identuum-ui `12eb4e1`)
  offers `/activate` on it; on a default no-SMTP install the page used to
  say it was not available. The setup wizard names the
  `show-setup-code` subcommand (it named a flag that does not exist).
- **A valid pending administrator no longer reads "Invitation expired"**
  (OSS-RC): `can_assign_admin` turns `true` only once the pending activation
  has expired.
- **Serving an unmigrated database says what to do** (OSS-RC): it stops at
  once with "run `identuum-idp migrate`" instead of a minute of lease
  retries blaming another instance.
- **README and the operator guide describe `v0.7.0`**: the binary-only path
  (migrate, then serve), first sign-in and MFA, organizations and invites,
  OpenID Connect clients, health, where data lives.

### Security

- **One-time tokens in a request path no longer reach the logs**
  (OSS-ONBOARD-B). Until now the access log, the database-not-ready,
  DenyM2MClients, panic, timeout, rate-limit and auth-refused lines, and the
  `feature.denied` and `scope.denied` audit rows, recorded the raw path of
  `GET /api/v1/auth/invite/:token` and
  `GET /api/v1/auth/organizations/activate/:token`, token included. They
  now record the route template (`…/:token`).

## `v0.6.3`

Security and correctness fixes since `v0.6.2`, with identuum-ui `v0.3.3`
embedded. Delta `v0.6.2..` (`git log`/`git diff --shortstat`, measured at
`32b9335`, before this notes commit): 21 commits, 24 files, +793/−109.
No migration (`0001`–`0040`, as in `v0.6.2`), no dependency moved
(`go.mod`/`go.sum` unchanged), Go 1.27.1. The canonical endpoint count
stays 144 (`go run ./tools/api-docgen --dry-run | grep -c '^  - id:'`) and
`openapi.yaml` is unchanged. No route, field or response shape is removed
or renamed. The new refusals below are security fixes;
`docs/releases/v0.6.3.md` lists them under Upgrading.

### Changed

- **The embedded UI is identuum-ui `v0.3.3`** (`96d0169`, `22962eb`,
  `bd3b002`, `562dc1d`, `32b9335`): `/` sends a signed-in visitor to their
  role's home instead of `/login`; `/reset-link` says it is not available
  on this installation (OSS declares `admin_reset_link: false`); the
  create-application form hides the public-client option only where an IdP
  declares `public_clients: false`, which OSS does not.

### Security

- **A deleted client's tokens stop at once.** Userinfo and introspection
  used to judge an access token by its signature, subject and revocation
  only, so a deleted client's unexpired token kept working.
  - Userinfo now answers 401 `invalid_token` and introspection
    `active:false` for a token whose client no longer exists. A failed
    client lookup fails closed (503).
  - `DELETE /api/v1/clients/:id` revokes the client's refresh tokens, and
    the access tokens linked to them, before it deletes the client. A
    failed revocation answers 503 `revocation_failed` and deletes nothing.

### Fixed

- **Client delete tells the truth.** `DELETE /api/v1/clients/:id` for
  another organization's client or an unknown id answered 200
  `{"deleted": id}` and recorded a `client.deleted` audit event while
  deleting nothing. It now answers 404 and records nothing.

- **A failed revocation leaves no change.** A role change or a disable
  through `PUT /api/v1/users/:id` whose credential revocation fails still
  answers 503 `revocation_failed`, but the user row is no longer written:
  the revocation now runs first, after every guard and validation and right
  before the write. A retry of the same request is still a change, so it
  revokes again. The user row and the credentials live in separate stores
  with no shared transaction, so revoke-first is the order used.

## `v0.6.2`

Security and correctness fixes since `v0.6.1`, with identuum-ui `v0.3.2`
embedded. Delta `v0.6.1..` (`git log`/`git diff --shortstat`, measured at
`c1367b4`, before this notes commit): 33 commits, 37 files, +1867/−165.
No migration (`0001`–`0040`, as in `v0.6.1`), no dependency moved
(`go.mod`/`go.sum` unchanged), Go 1.27.1. The canonical endpoint count
stays 144 (`go run ./tools/api-docgen --dry-run | grep -c '^  - id:'`). No
route, field or response shape is removed or renamed. The new refusals
below are security fixes; `docs/releases/v0.6.2.md` lists them under
Upgrading.

### Security

- **A role change takes effect at once.** A bearer's role and scopes come
  from its access token, so a demoted org_admin used to keep org_admin
  rights until its token expired (up to one hour).
  - Any role change through `PUT /api/v1/users/:id` now revokes the user's
    sessions, which kills every session-bound access token and refresh
    token on its next request, and its OAuth refresh tokens, with their
    linked access tokens denylisted.
  - A disable does the same. It was already refused on the next request.
  - Revocation is now fail-closed: a failure answers 503 `revocation_failed`
    and the change stays, so the caller retries.
- **An organization can no longer lock itself out.** Through the admin
  routes, an org_admin no longer:
  - changes its own active state or role (`PUT /api/v1/users/:id` → 403
    `cannot_change_self`; its own name and profile stay editable);
  - deletes itself (`DELETE /api/v1/users/:id` → 403 `cannot_change_self`);
  - assigns or removes its own roles (`/api/v1/users/:id/roles` → 403
    `cannot_change_own_roles`);
  - resets its own MFA (`POST /api/v1/users/:id/recovery/reset-mfa` → 403
    `cannot_reset_self`; its own factor is self-service).

  An organization's last active org_admin is never disabled, demoted or
  deleted (409 `last_org_admin`). The check and the write run in one
  transaction that locks the organization row, so two admins disabling each
  other at once leave one. The rules match identuum-idp-ce
  (contracts/AdminPermissionsModel.md line 3). The site_admin's recovery of
  an organization that lost its admins is unchanged.

### Added

- **`GET /api/v1/component` declares `user_approval: true`**: OSS holds
  pending registrations and serves `POST /api/v1/users/:id/approve`.
  identuum-idp-ce declares false.
- **`GET /api/v1/component` names two mail capabilities**:
  `mail_ceremonies` is true only when SMTP is configured
  (`IDENTUUM_IDP_SMTP_HOST` and a sender, `internal/runtime/smtp_config.go`),
  and `admin_reset_link` is false (an identuum-idp-ce surface). The UI hides
  "Forgot password?" and the reset, verification and activation-mail pages
  when mail cannot be delivered.

### Deployment

- **The compose file pins identuum-idp-oss `v0.6.1` by index digest**
  (`deployment/docker-compose.yml`, `sha256:39f968e2…`, publish run
  36200767001, built from `f1de6ee`), in place of `v0.6.0`.

### Documentation

- **The install line downloads the compose file from GitHub Releases**:
  `curl -fsSLO https://github.com/identuum/identuum-idp-oss/releases/latest/download/docker-compose.yml`
  (README.md, deployment/README.md, the compose and publish-image.yml
  header comments, docs/releases/v0.6.1.md), in place of
  `downloads.identuum.com`, which does not resolve. Every release carries
  its pinned `docker-compose.yml` and `docker-compose.yml.sha256` as
  assets; deployment/README.md, "Releasing: the compose asset", is the
  procedure and its check. publish-image.yml's header also named the UI on
  `:7104`; it names `:7113`.

### Fixed

- **Honest statuses on user PUT and DELETE**:
  - `DELETE /api/v1/users/:id` answered 404 for any failure, database faults
    included. Only a missing user is 404 now; a fault is 500
    `internal_error`.
  - Both routes answer an unidentified actor 401 `unauthorized`, as the
    reset-MFA route does, where PUT answered 500 and DELETE 404.

## `v0.6.1`

Fixes since `v0.6.0`, with identuum-ui `v0.3.1` embedded. Delta
`v0.6.0..` (`git log`/`git diff --shortstat`, measured at `b471d35`,
before this notes commit): 16 commits, 34 files, +1667/−158. No migration
(`0001`–`0040`, as in `v0.6.0`), no dependency moved (`go.mod`/`go.sum`
unchanged), Go 1.27.1; the canonical endpoint count stays 144
(`go run ./tools/api-docgen --dry-run | grep -c '^  - id:'`). Nothing
breaks for a `v0.6.0` install: see `docs/releases/v0.6.1.md`, "Upgrading".

### Changed

- **The embedded UI is identuum-ui `cf6575a`** (tree digest
  `b0eac627428a33c42df374573cf73b952c31f6aef874032b28ebd771a8b8e259`, the
  same tree identuum-ui `v0.3.1` publishes, whose later commits carry only
  release files), in place of `e400398`'s `cf25b025…` (with `48f8f33`, `86c29253…`, `a8d829f`,
  `29049d21…`, and `b33811b`, `b1241960…`, in between). Since `b33811b`:
  the profile tab shows the saved profile (it rendered empty, and saving it
  cleared every field), a site_admin's sessions tab says session management
  is not available for administrator accounts instead of "Could not load
  sessions", and session revoke asks `POST /api/v1/revoke` on every
  edition. Since `a8d829f`: every date is sent and kept
  as UTC and shown in the viewer's browser time zone with the zone named,
  the exact UTC time on hover; a page no longer fails to hydrate when the
  server's and the browser's calendar days differ. Since `e400398`, it
  also no longer offers the report export links, the organization webhooks list
  or passkey rename, which no edition serves, and session revoke asks only
  `POST /api/v1/revoke` on this edition, where it tried the CE route first
  and fell back on its 404. Since `48f8f33`: `/logout` is a sign-out page
  whose form posts the sign-out (loading it never signs out); the boot
  probe routes a CE upgrade-mode binary to `/upgrade`; a cookie-session
  sign-out confirmed in its body reads as signed out.

### Fixed

- **A claim link is no longer lost when creating its org_admin fails.** A
  user-create failure after the burn used to leave the claim link burned
  with no user. The consume of `POST /api/v1/auth/claim` now runs in one
  transaction with the claim row locked: the attempt count, the burn and the
  new org_admin commit together, and a failure rolls the burn back, so the
  link stays usable. The response bodies, the email binding, single use and
  the three-attempt budget are unchanged. Concurrent consumes of one link
  already created exactly one user (the burn reports its row count); a test
  now guards that too.
- **Verification mail can no longer be requested without bound, and it is
  audited.** `POST /api/v1/auth/resend-verification` and
  `GET /api/v1/auth/verify-email` carried no rate limit, and the runtime
  built the email verification service with no audit, so an inbox could be
  flooded and nothing was recorded.
  - Resend is now limited per client IP (10 per 15 minutes) and per target
    address (3 per hour, keyed by a SHA-256 of the address, never the
    address). Known and unknown addresses are counted and answered alike.
  - Verify is limited per client IP (30 per 15 minutes).
  - Past a window the answer is the other limiters' `429` with
    `Retry-After: 60`.
  - Overrides: `IDENTUUM_IDP_RATE_LIMIT_EMAIL_VERIFICATION_RESEND_*`,
    `_EMAIL_VERIFICATION_ADDRESS_*` and `_EMAIL_VERIFY_*` (`_REQUESTS`,
    `_WINDOW`). An override can only raise a limit.
  - Each sent mail is audited as `email_verification_resent` and each
    verification as `email_verified`, with neither the token nor the
    address.
- **A wrong method on a registered path answers `405 Method Not Allowed`
  with an `Allow` header naming the path's methods** and the body
  `{"error":"method_not_allowed"}`, where it answered a plain 404 (for
  example `GET /api/v1/auth/login`, `DELETE /api/v1/organizations`,
  `GET /api/v1/oauth/token`). Through the browser boundary the same request
  is answered 405 before the `X-Requested-With`/Origin check and is never
  forwarded, and `GET /bff/session/refresh` and `/bff/session/logout` answer
  405 with `Allow: POST` where they answered 404 `bff_destination_refused`.
  HEAD on a GET route, CORS preflight, UI pages and assets, and unregistered
  paths answer as before. `pkg/uiserve` gains `Options.AllowedMethods`;
  left nil, every answer is unchanged.
- **`migrate` says what it did**: `identuum-idp: migrate: applied N
  migration(s) of M embedded; database at version V`, where M is every
  migration the binary carries and V the database's version afterwards.
  It printed the number applied as the embedded count, so a database
  already up to date read "applied 0 migration(s) of 0 embedded" (the
  container entrypoint on every restart, `migrate` run twice). Nothing was
  missing: the published v0.6.0 image embeds all 40 migrations. The
  factory-reset's re-migration line reports the same way.

### Deployment

- **The compose file pins identuum-idp-oss `v0.6.0` by index digest**
  (`deployment/docker-compose.yml`, `sha256:dd4db90f…`, publish run
  36061444727, built from `db77482`), in place of `v0.5.1`: one container
  serves the UI and the API on `:7113`.

## `v0.6.0`

One binary serves the UI and the API. The identuum-ui static export
(identuum-ui `v0.3.0`, `e400398`, tree digest `cf25b025…`) is embedded in
the binary and served on the issuer's own origin, `:7113`, behind a narrow
`/bff` browser boundary; the separate identuum-ui container and its `:7104`
port are gone from the compose file. Delta `v0.5.1..` (`git log`/`git diff
--shortstat`, measured at `6e8c608`, before this notes commit): 28 commits,
65 files, +5048/−243. No migration (`0001`–`0040`, as in `v0.5.1`), no dependency
moved (`go.mod`/`go.sum` unchanged), Go 1.27.1; the canonical endpoint count
stays 144 (`go run ./tools/api-docgen --dry-run | grep -c '^  - id:'`).
Upgrading from `v0.5.x` changes the URL, and a browser on another host name signs in again: see
`docs/releases/v0.6.0.md`, "Upgrading".

### Added

- **The binary serves the identuum-ui export** (`c5c968f`, `b0bbd5a`,
  `4b8ce6f`, `6e14fe5`). The export is embedded from `internal/uiexport`
  with its manifest and checked against its tree digest; `IDENTUUM_IDP_UI_DIR`
  overrides it with a directory (developer use). Routes the engine carries
  are never answered with the app shell (`a0bacf9`). The serving and the
  boundary are the public, standard-library-only package `pkg/uiserve`
  (`d2eb9c5`), mounted by the OSS engine through gin.
- **The `/bff` browser boundary.** It lifts the HttpOnly access cookie into
  a Bearer for `/api/v1/` only, never forwards the Cookie header, and
  requires `X-Requested-With: identuum-ui` and a same-origin (or
  allowlisted) `Origin` on every request, safe methods included (`1f73198`,
  owner decision D1). `/bff/session/refresh` rotates the refresh cookie into
  new HttpOnly cookies with no token body; `/bff/session/logout` revokes and
  reports `local_only` when revocation was not confirmed.
- **`GET /api/status`, `GET /api/runtime-config` and `/healthz`** answer
  from the binary when the UI is mounted (`97a8cbe`, `c42b1e2`); `/healthz`
  answers as `/health`.
- **`identuum-idp healthcheck [base-url]`** (`32ef161`): exits 0 only when
  the server's own `/healthz` answers 200, following the appliance's listen
  address (`IDENTUUM_IDP_LISTEN`, then `IDENTUUM_IDP_OSS_LISTEN`, then
  `0.0.0.0:7113`, a wildcard host probed on loopback). The distroless image
  has no shell, so the compose healthcheck calls it.

### Changed

- **The `refresh_token` cookie is scoped to `Path=/bff/session/`** (`bf48190`,
  owner decision D3): the browser sends it only to the boundary's refresh
  and logout, never with every page or API request. Clearing it expires it
  at `/bff/session/` and at the `/` of earlier releases. `access_token` stays
  at `/`.
- **`POST /api/v1/auth/session/refresh` answers a session-store outage with
  `503 {"error":"refresh_unavailable"}`** (`0711265`, owner decision D2),
  not the generic `500 internal_error`, and rotates nothing — the same answer
  the browser refresh gives. A client should retry later, not discard its
  refresh token. Reuse, invalid and expired refresh tokens keep their
  existing `401` answers. (Listed under `v0.5.1` before this release in
  error; `0711265` is not in `v0.5.1`.)
- **`GET /api/v1/organizations/:id/identity-provider` answers `200
  {"success":true,"identity_provider":null}` when the organization has no
  provider configured**, not `404` (owner ruling for `v0.6.0`): no provider
  is a state of the organization, and the org-admin settings page now reads
  it without a failed browser request. Authorization, tenant scoping and
  every other answer are unchanged; `PUT` and `DELETE` of an absent
  provider still answer `404`. A client that treated the `404` as "none
  configured" should read `identity_provider: null` instead.
- **Refresh and logout refuse honestly when the session store cannot
  confirm** (`16aded8`): a refresh whose account or organization lookup
  fails rotates nothing; reuse whose family revocation did not land answers
  `503 refresh_unavailable`; logout reports `503 revocation_unconfirmed`
  when it could not confirm, refuses a cookie-carrying request without
  `X-Requested-With`, prefers an explicit Bearer over cookies, and ends the
  session from the refresh cookie when the access cookie has expired.

### Deployment

- **One container serves the UI and the API on `:7113`** (`55db566`).
  `deployment/docker-compose.yml` drops the `identuum-ui` service, its
  `ui-runtime` config and `IDENTUUM_UI_BIND_ADDRESS`; the issuer, the UI's
  public URL and the allowed origin are one origin, `http://localhost:7113`.
  A Docker healthcheck runs `/app/identuum-idp healthcheck`.
  `deployment/docker-compose.build.yml` builds the one image.
- **The compose file pinned identuum-idp-oss `v0.5.1` by index digest**
  (`bcbca2e`, `sha256:82a4dfa7…`, publish run 35984270749, built from
  `1b6f09b`), in place of `v0.5.0`, until this release's pin.

## `v0.5.1`

First-run setup completes when the organization domain is left empty.
Delta `v0.5.0..v0.5.1` (`git log`/`git diff --shortstat`, measured before
this release commit): 5 commits, 10 files, +226/−22 — the fix below, the
compose re-pins and the dev-compose image name listed under Deployment,
and the `v0.5.0` release-notes commit; plus this release commit. No
migration, no dependency moved, no endpoint added or removed (canonical
count 144).

### Fixed

- **An empty organization domain defaults to `slug(name) + ".local"`**
  (`6e0412a`). `POST /api/setup/complete` with `organization_domain` empty
  used the raw organization name as the domain, so a name with a space
  ("Acme Corp") failed organization validation and the request answered
  `400 setup_complete_failed`: first-run setup through the ui wizard failed
  whenever its optional domain field was left empty. The domain is now the
  name's slug under `.local` ("acme-corp.local"), as the wizard documents.
  An explicit domain is unchanged, and a resumed setup still reuses the
  organization a partial run left. A name with no letter or digit ("!!!")
  has no default and is refused as `400 organization_domain_required`
  (previously the generic `setup_complete_failed`).

### Deployment

- **The compose file pins identuum-idp-oss `v0.5.0` and identuum-ui
  `v0.2.3` by index digest** (`deployment/docker-compose.yml`; `v0.5.0`
  cannot carry its own digest, so the pin follows the tag). Its header now
  says that the UI refuses state changes from any origin other than
  `ui_origin`, so it is opened at exactly `http://localhost:7104`, and that
  the developer stack shares this file's project and container names, so
  the two cannot run on one host at the same time; and the comments above
  the two image lines name the pinned releases and their publish runs.
- **The compose file pins identuum-ui `v0.2.4` by index digest**
  (`deployment/docker-compose.yml`, `sha256:06c7d2ed…`, publish run
  35933342230), in place of `v0.2.3`. Site administrators can now restore a
  deleted organization from the UI; before, the restore page read the
  organization by id, which this server answers with 404 for a deleted
  organization (ORG-RESTORE-1), and always showed "not found".

## `v0.5.0`

A second factor that behaves like one. A TOTP code is accepted once; the
account password no longer disarms MFA; recovery codes cannot buy more
recovery codes; the recovery-code route is rate-limited; and the routes that
set the browser's auth cookies refuse a cross-site form. One migration
(`0040`), one new public symbol, no endpoint added or removed (canonical
count `go run ./tools/api-docgen --dry-run | grep -c '^  - id:'` = 144 at
this release), no dependency moved, Go 1.27.1 unchanged.

Measured delta `v0.4.0..v0.5.0` (`git rev-list --count v0.4.0..HEAD` and
`git diff --shortstat v0.4.0..HEAD` at `e9e06d1`, before this notes commit):
126 commits, 108 files changed, +6767/−1430. By subject line — 27 witness
records (`Witness: `), 27 manifest re-bases (subject contains "rebase"), 4
CI records (`ci: record run `), 68 others; of the others, 11 change what an
operator or integrator meets and are listed one by one below, the other 57
are verification machinery, tests and documentation (the notes commits
`acd65be`, `5be0e45` and `e9e06d1` among them), grouped at the end.

### Security

- **Login CSRF closed on the four routes that set the browser's auth
  cookies** (`d8d4459`) — `POST /api/v1/auth/login`, the MFA verify and
  enroll-complete steps of that login, and the passkey login finish. The
  CORS middleware withholds only its Allow-* headers from a disallowed
  origin, so a cross-site SIMPLE request still reached these handlers, and
  a `text/plain` body carrying JSON was decoded: a cross-site form could
  log the victim's browser into the attacker's account (measured: 200 with
  `Set-Cookie`). A request that carries `Origin` must now carry
  `Content-Type: application/json`, or it is refused `403
  {"error":"csrf_failed"}` before its body is read. Non-browser clients,
  which send no `Origin` (curl, server-to-server callers, the UI's
  server-side proxy), are unchanged.
- **A TOTP code is accepted once** (`0429ce0`, migration `0040`). A code
  used to be matched inside its ±1-step window and nothing else, so a
  captured code was accepted again while the window lasted. Every TOTP
  proof — password+TOTP login, the pending-login MFA step, step-up,
  enrolment completion, recovery-code regenerate, self-disable — now claims
  its `(user, step)` in `totp_used_steps`; a second claim is refused exactly
  like a wrong code (same status, body and audit row). A store that cannot
  be consulted refuses rather than accepting.
- **The password no longer disarms MFA** (`52b5d0e`). `POST
  /api/v1/me/mfa/disable` accepted the current password as a proof; it now
  accepts a current TOTP code or a recovery code only. The `password` key
  is still read off the wire and ignored; a password-only request gets the
  route's existing `401 invalid_code`.
- **Regenerating recovery codes requires a TOTP code** (`22e1c06`). `POST
  /api/v1/me/mfa/recovery-codes/regenerate` took the session as its only
  proof. It now requires `{"code": "<current TOTP>"}`; a recovery code is
  not accepted. A wrong code or a recovery code answers `401
  invalid_code`, a malformed body `400 invalid_request`.
- **An absent code on that route is `400 code_required`** (`f44d551`),
  answered before the service is consulted — the shape the disable route
  and identuum-idp-ce already use. A present wrong code is still `401
  invalid_code`.
- **The recovery-code regenerate route is rate-limited per authenticated
  subject** (`3bd83c0`): default 5 requests per 15 minutes, keyed on the
  user, configurable through
  `IDENTUUM_IDP_RATE_LIMIT_MFA_RECOVERY_CODES_REGENERATE_REQUESTS` and
  `…_WINDOW`; past the limit the router answers `429`.

### Fixed

- **A disabled user can be read and enabled again** (`1ea42c1`). The
  admin-management reads (`GET`/`PUT /api/v1/users/:id`, approve, reset MFA,
  delete, role assignment) went through a lookup that hides banned users, so
  a user disabled with `PUT {"active": false}` answered `404` and could never
  be re-enabled, and a pending self-registration could never be approved.
  They now see a disabled user; a deleted user stays not found, and login,
  refresh, session validation and every other authentication path still
  refuse a disabled user exactly as before.

### Added

- **`pkg/webauthn.ErrCredentialNotYours`** (`954b89f`) — a new public
  symbol: the refusal `Service.DeleteCredential` returns for an unknown or
  another user's credential id (deliberately indistinguishable). It aliases
  the internal not-found sentinel, so behaviour is unchanged; a caller that
  imports only the seam can now `errors.Is` the refusal instead of seeing a
  500.
- **Every 401 verdict is logged with its reason** (`048ace0`): one WARN line
  on the security logger (`event_type auth_refused`, reason, method, path,
  client IP, request id when set). No header or credential is logged;
  status and body are unchanged.
- **`GET /health` says when brute-force protection is off** (`3fdce76`): the
  response carries `X-Identuum-Brute-Force-Protection: disabled` while the
  test-only `IDENTUUM_IDP_INSECURE_DEV_MODE` hatch is active, and the probe
  answers `Cache-Control: no-store`.

### Database

- **Migration `0040_totp_used_steps`** (`0429ce0`) — creates
  `totp_used_steps (user_id, step, expires_at, created_at)`, primary key
  `(user_id, step)`, a `step >= 0` check and an index on `expires_at`. Only
  the step number is stored, never a code or a seed; rows are swept once the
  step can no longer be accepted. Applied on start like every migration;
  `Down` drops the index and the table.

### Deployment

- **The appliance's host listening address is configurable**
  (`deployment/docker-compose.yml`): `IDENTUUM_IDP_BIND_ADDRESS` (port
  7113) and `IDENTUUM_UI_BIND_ADDRESS` (port 7104), each defaulting to
  `0.0.0.0`. Set both to `127.0.0.1` for a loopback-only install. Only the
  host side of the mapping changes; the listeners inside the containers
  stay on `0.0.0.0`. Measured with the default: `docker port` shows
  `0.0.0.0:7113` and `0.0.0.0:7104` only, and `curl -6
  http://localhost:7113/health` no longer connects — the bare `7113:7113`
  mapping of earlier releases also published `[::]`; the explicit `0.0.0.0`
  publishes IPv4 only.
- **Warning — fixed container and volume names.** The compose file pins
  `container_name:` and volume `name:` values, so every install of it on
  one host shares them, and `docker compose down -v` under ANY project name
  deletes the install's database and data volumes.

### Verification machinery (repository-visible, not in the binary)

- **CI runs three jobs** — Verify (`ci-verify` + integration lint),
  Govulncheck and Integration Tests. The separate race job was dropped
  (`74cb995`): `ci-verify`'s recorded `go-test-race` already runs the same
  packages under `-race`. Compiling jobs cache GOCACHE, GOMODCACHE and
  staticcheck's cache (`d9d5a6c`).
- **The gate judges are the installed, pinned lictor**: `grype-scan`
  (`63ee215`, `tools/grype-gate` retired), `repo-green` (`e642f92`),
  `clock-fuse-gate` (`39b2122`), and `ci-verify` / `verify-integration`
  driven through `lictor witness run` (`7fa3941`, `a3cbe8c`, `cd79b68`).
- **Tool pins follow the installed tools** (`24b9d7d`):
  `GOVULNCHECK_VERSION` v1.7.0 → v1.8.0 and `LICTOR_VERSION` v0.4.1 →
  v0.4.2 with `LICTOR_SHA256` the linux_amd64 line of v0.4.2's published
  checksums. `toolchain-parity`'s synthetic fixture follows the pins and
  `CI-LOCAL-PARITY-1` is rehashed and declared. Earlier moves in this
  range: grype v0.119.0 (`903f294`), lictor v0.4.0 and v0.4.1 (`39b2122`,
  `dc74ede`).
- Witness, mint and CI-record machinery: records refused on a dirty tree
  (`99ac0ca`), mint debt refused until paid (`6da6a07`), CI gate identity
  declared and required (`e437b0c`, `bfd0c84`), the CI integration job's own
  record (`341fc31`), a non-minting `verify-check` (`20261ef`), declared
  no-reach sets for the mint (`8f50063`, `6a92d3f`, `3187862`), and a
  suppression past its re-check date is a red finding (`fa40090`).
- Removed an unreachable MFA disarm wrapper and password helper
  (`d8e1c49`); tests share one HOTP helper (`0cc4d10`).

### Documentation

- **OIDC config certification posture decided** (`3835d71`, P-062 (b)):
  discovery keeps `id_token_signing_alg_values_supported` `[EdDSA, ES256]`;
  RS256 stays registrable per client and mintable on explicit operator
  request, never advertised. The conformance condition requiring RS256 in
  discovery is a recorded expected failure: conformant against the
  committed floor, not certifiable on that condition. `a450cdc` corrected
  the earlier "passes clean" claim at its site.

## `v0.4.0`

The public API is frozen: `pkg/` holds exactly the six packages the
commercial edition imports — `features`, `licenseprovider`, `oidc`, `pkce`,
`totp`, `webauthn` — and a gate keeps it so. The three `pkg/` directories
nobody outside this repository imported (`migrations`, `runtime`, `server`)
moved under `internal/pkg/` (decision P-061). That is a change to the
module's import surface, hence `0.4.0` and not `0.3.8`. Measured delta
`v0.3.7..v0.4.0`: 12 commits (4 witness records, 4 manifest re-bases, 1 CI
record, 3 others), 19 files changed, +258/−93. No migration added, no
dependency moved, Go
1.27.1 unchanged; no endpoint changed.

### Changed

- **`pkg/migrations`, `pkg/runtime`, `pkg/server` → `internal/pkg/…`**
  (`d1b9830`). Measured first at `d461bd7`: inside this repository each was
  imported only by its own test, `pkg/runtime` also by
  `cmd/identuum-idp/main.go`; identuum-idp-ce's dependency closure named
  none of them; identuum-ui and the AG repositories import no OSS package.
  Package names, identifiers and behaviour are unchanged — only the import
  path moved. The destination is `internal/pkg/<name>` rather than
  `internal/<name>` because `internal/runtime` and `internal/server` already
  exist as the authorities the two shims alias. An importer of the old
  paths (there was none) would fail to compile; that is the SemVer minor.
  The `boundaries.json` rules follow the packages.

### Verification machinery (repository-visible, not in the binary)

- **`api-surface`** (`958a7d7`) — a Makefile gate in both `verify` and
  `ci-verify`: red unless the directories directly under `pkg/` are
  exactly the six above, each extra or missing directory named; red-proved
  with an untracked `pkg/decoy/` and with `pkg/totp` moved aside. `verify`
  runs 32 targets (was 31), `ci-verify` 25. The CI matrix comment and two
  workflow comments that still said `pkg/runtime` were corrected.
- CI run 34149894245 at `eb54e7f` (the gate commit's witness) green on all
  four jobs; its `ci-verify` record — 25 targets, `api-surface` among them —
  is committed as `CI-WITNESS.txt` (`fe82a71`).

## `v0.3.7`

Intermediate release on the v0.3 train, cut so identuum-idp-ce can pin a tag
instead of a pseudo-version (a pseudo-version's base-tag validation
unshallows the module-cache clone, and GitHub's runners on git 2.55.0 die
there with `fatal: shallow file has changed since we read it`). Measured
delta `v0.3.6..v0.3.7`: 305 commits (81 witness records, 11 manifest
re-bases, 4 CI records, 209 others), 445 files changed, +45336/−2588.
Eight migrations added (`0032`–`0039`); Go 1.27.1; eleven dependency bumps.
The Go source is identical to `f8a1e6a`, which identuum-idp-ce compiled and
vetted against clean and which CI run 34115127258 proved green.

### Added

- **Forced re-authentication** — `prompt=login` and `max_age` at the
  authorize endpoint; the login page is marked when re-authentication is
  forced (`a45c186`, `41add7b`).
- **The `claims` request parameter** — honored, consent-gated and
  role-intersected (`afffe86`); the **full OIDC profile** modelled (unset is
  never emitted; consent echoes `max_age`) (`0cabdc3`); **`address` and
  `phone` claims** as real profile fields with scope/claims release
  (`1a5fda9`); locale validated as RFC 5646 syntax (`d43044c`).
  Migrations `0034_claims_parameter`, `0035_user_profiles`,
  `0036_address_phone`.
- **Request objects by value** — verified against registered keys or
  unsigned; `request_uri` refused (`8dbcb01`).
- **Per-client PKCE, testing-only RS256** and the conformance findings they
  exposed (`ae6f837`); RS256 is a per-client registration again and discovery
  advertises what the issuer signs with (`d9ab771`). Migration
  `0032_client_id_token_alg`.
- **Scope stamping and replay revocation** — consented ∩ role-permitted scope
  is stamped on authorization-code access tokens (`37f3af7`); a replayed
  authorization code revokes what it minted (`58cc5a8`). Migration
  `0033_authcode_issued_tokens`.
- **Agent communication (AYGHU)** — the AgentCommunicationAuthorization
  aggregate with invariants and a canonical policy digest (`3d7dbc3`); the
  org_admin own-org admin API create/list/get/revoke with no existence oracle
  (`82bf8d6`); DPoP-bound participant tokens by client credentials
  (`32717fd`); observable revocation of issued participant `jti`s
  (`d4ab9cf`); introspection judged against the authorization (`ec2d785`);
  the creating org_admin owns the service account (`ea5e283`), owners can be
  set later (`c3cda23`). Migrations `0037_agent_communication_authorizations`,
  `0038_dpop_proof_replays`, `0039_agent_communication_tokens`.
- **Operators** — `rotate-encryption-key`, offline at-rest key rotation,
  atomic and resumable, refusing unknown schemas, with a doctor census and
  runbook (`47fb156`, `4b1abac`, `a916eba`); `audit-preupgrade`, the
  read-only sweep for rows the guards refuse (`19cb94b`); provenance
  announce and stale-binary refusal (`55eb706`); `create-organization` with
  absent `active` meaning ACTIVE and `admin_email` honored atomically
  (`f42c87b`); organization lifecycle filter on the list and deactivated
  organizations reachable on detail (`67a62f6`); activation returns the
  link that consumes the token or says why there is none (`6450c9b`);
  `INSECURE_DEV_MODE`, the named test-only rate-limit escape hatch
  (`da653e6`); a manual OpenID conformance harness, `make
  openid-conformance` (`1541270`).

### Changed

- **Auth path truthfulness (AUTH-503)** — a store error on the auth path
  answers `503` with an ERROR log line and a correlation id, never `401`;
  every `401` names its reason (`73070bd`); a logout that cannot revoke
  still clears the cookie but never passes silently (`9674215`).
- **Cookies** — the session cookie and the browser-login CSRF cookie take
  `Secure` from the request transport, decoupled from `gin.Mode`
  (`b71ff9f`, `ad02bc0`, `0a9cdb2`).
- **`site_admin` on tenant surfaces** — refused on the tenant OAuth-client
  surface, domains, protocol-settings, rbac-roles, service-accounts and
  api-resources (`1dcd479`, `15e235f`, `a813b4d`); scope templates invert to
  org_admin with the reserved-prefix validation wired (`ca42ea8`).
- **Refusal shapes tell the truth** — `weak_password` is `400`; sentinel
  `404`s only for misses, `409` for duplicates, `500` for faults across five
  write families and the update fallback (`75fba98`, `a6893b0`, `734e63c`);
  bulk rows name their class. A client that matched the old statuses will
  notice.
- **Update paths validated** — organization, user and client update paths
  distinguish "not supplied" from "supplied blank"; the client document
  validator runs at create and on the updated document (`92d3384`,
  `615d6fc`, `2bc4f1c`, `a4e718c`, `976432e`, `17f06a3`, `9bec8d4`);
  organization fields validated — "lexus" is no longer a domain
  (`92d3384`); org wire binds the five repository-supported fields and
  refuses slug and tier loudly (`c14b753`); users `active` wire contract
  fixed (`d952d06`).
- **Federated login, `acr`** — the performed context is stamped and
  `acr_values` is honored by step-up or refusal (`f0caeed`); a
  phishing-resistant rung with passkey step-up and downward-only ranking is
  the third advertised value (`f715b86`); the EFFECTIVE `amr` is copied onto
  the derived session (`27c044c`); an assumed ACR rung is no longer stamped
  on a federated session (`9127c53`); an upstream `acr` the ladder does not
  recognise is ASSUMED — stamped on no session, emitted in no id_token
  (`a42997d`, rule ACR-UNKNOWN-IS-ASSUMED-1). A relying party that requests
  `acr_values` from such a login gets step-up or
  `unmet_authentication_requirements` instead of a false assurance.
- **Soft-deleted users** — restore recovers them; approve/reset-mfa answer
  `404` not `500`; org_admin may delete same-org users; restore fails loud
  (`da226c7`, `78eb077`).
- **Discovery** advertises the issuer's signing algorithms (`d9ab771`); the
  unused second DPoP verifier is deleted (`c4c0af5`); the instance-lease
  uuid component is UUIDv7 (`ed56dca`).

### Toolchain and dependencies

- Go `1.27.0` → `1.27.1`; gin `1.11.0` → `1.12.0`; pgx/v5 `5.9.2` →
  `5.10.0`; goose/v3 `3.26.0` → `3.28.0`; prometheus/client_golang `1.23.2`
  → `1.24.1`; testify `1.11.1` → `1.12.1`; zap `1.27.0` → `1.28.0`;
  go-redis/v9 `9.17.2` → `9.22.0`; miniredis/v2 `2.35.0` → `2.39.0`;
  go-webauthn `0.15.0` → `0.18.0` (the one bump that needed code); jwt/v5
  `5.3.0` → `5.3.1`; x/crypto `0.53.0` → `0.56.0` (GO-2026-6303).

### Verification machinery (repository-visible, not in the binary)

- The rule ledger grew from 88 to **254 armed rules** (FLOOR 254); the
  `covers` map qualified on every rule; the ledger-diff gate reconciles a
  single-use amendment manifest at every verify (`bb650b8`).
- Every `make verify` and every CI run leaves a committed gate-run record
  (`5c0e107`, `e294d7c`); the first CI record this repository held
  (`91a8a7e`); records tie to the clean HEAD (`98ad34e`); the record is
  locked and two verify legs run concurrently (`7165378`, `7d7f56a`).
- **`make witness`** is the only way a witness commit is made, byte-identical
  with identuum-ui and pinned by `witness-parity` (`a6edb7f`).
- The e2e mint is COMPUTED by a reachability classifier, never judged
  (`dd4a171`, `bb1355e`); it applies under the ui's namespace and judges a
  stale e2e record by its two heads (`ad6a56b`).
- `openapi-check` compares the checked-in `openapi.yaml` byte for byte with
  its generator (`21a8b7e`); `workflow-yaml` parses every workflow with a
  pinned yq, held byte-identical with identuum-ui (`ac68b79`, `f98208c`);
  CI pins every gate tool and proves the versions it runs (`44990cf`,
  `9260c9c`); architecture boundaries declared and pinned (`5e304ed`).

## `v0.3.6`

Feature release: self-service password change, end to end. Measured delta
`v0.3.5..v0.3.6`: 5 commits, 21 files changed, +832/−62 (the release-prep
commit itself carries the Go 1.27.0 toolchain move); no migrations, no
dependency changes.

### Added

- **`POST /api/v1/auth/change-password`** — authenticated self-service
  password change. The target is always the caller's own account (no user
  id on the wire); the CURRENT password must verify; the new password is
  validated against the per-org password policy. Responses: `204` on
  success; `400 weak_password` with a safe displayable `message` on a
  policy violation; `403 invalid_current_password` — deliberately OPAQUE
  across wrong-password, federated (non-local) account, and
  no-local-hash; `401` for stale principals. Audit row `password_changed`
  with identifier-shaped metadata. This makes the UI's account-settings
  rotation (which always called this route) work against OSS.
- **Session revocation on password change (R2)** — a successful change
  revokes every OTHER session (revocation reason `password_changed`) and
  ALL OAuth refresh tokens; the session that made the change stays valid.
  The audit row records `other_sessions_revoked`,
  `session_revocation_clean`, `current_session_preserved`, and
  `refresh_tokens_revoked_count`.

### Changed

- **Toolchain: Go 1.27.0** (owner-directed) — `go.mod` and the image
  builder move together to `golang:1.27.0-bookworm` (digest-pinned;
  TOOLCHAIN-PARITY-1 enforces the pair). No dependency changes
  (`go mod tidy -diff` empty). Two v0.3.3-era test files were reflowed by
  go1.27's gofmt (formatting only; neither is ledger-pinned). The two EC
  JWK→key sites (DPoP proofs, private_key_jwt assertions) now construct
  keys via `ecdsa.ParseUncompressedPublicKey` — same on-curve validation
  and behavior, replacing the `ecdsa.PublicKey.X/.Y` construction Go 1.26
  deprecated; one dead assignment removed (both flagged by the go1.27-era
  staticcheck).
- **Customer compose pins refreshed** — the appliance file now pulls
  `identuum-idp-oss:v0.3.5` and `identuum-ui:v0.2.0`, each pinned by its
  published digest so tags cannot be silently retargeted.
- **Test infrastructure** (no runtime surface): the integration gate now
  serializes test packages (`go test -p 1`) — the DB-backed packages share
  one `*_test` database and raced under default package parallelism.

## `v0.3.5`

Security release. **`v0.3.4` was tagged but never published**: its image was
built by a `golang:1.26.5` builder while the host toolchain (and every
host-side scan) was already 1.26.6, so the image alone carried the 1.26.5
standard library — and the publish workflow's Trivy gate stopped it with 8
HIGH `gobinary` findings before GHCR login ever ran (run 32392773901; nothing
was pushed). The `v0.3.4` tag is public and stays (public tags are never
rewritten); the shipped release is `v0.3.5`, which is `v0.3.4`'s content plus
the fixed toolchain. All functional changes listed under `v0.3.4` below ship
first in `v0.3.5`.

### Security

- **Builder toolchain bumped to Go 1.26.6** (`deployment/Dockerfile.local`
  builder now `golang:1.26.6-bookworm`, digest-pinned; `go.mod` `go 1.26.6`;
  no dependency changes — `go mod tidy -diff` empty). This closes the 8 HIGH
  stdlib CVEs the v0.3.4 image carried, all fixed in Go 1.26.6:
  - CVE-2026-33818 — `encoding/asn1`: DoS via excessive recursion
  - CVE-2026-39821 — `net/http` / `golang.org/x/net/idna` (via stdlib): privilege escalation
  - CVE-2026-46600 — `golang.org/x/net/dns/dnsmessage` (via stdlib): DoS
  - CVE-2026-56853 — `net/http`: unencrypted HTTP/2 (h2c) DoS
  - CVE-2026-56858 — `html/template`: XSS via pathological input
  - CVE-2026-56859 — `encoding/xml`: DoS via decoding recursion depth
  - CVE-2026-56860 — `net/url`: DoS from quadratic complexity
  - CVE-2026-56862 — `crypto/tls`: DoS via indefinite KeyUpdate
  Verified locally with the publish gate's own scanner shape
  (`trivy image --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1`):
  exit 0, `gobinary` 0 findings on the rebuilt image (the v0.3.4-toolchain
  image reproduces 8 HIGH under the same scan).
- **TOOLCHAIN-PARITY-1** — a unit test now parses the Dockerfile builder's Go
  version and `go.mod`'s `go` directive and fails on any skew (digest pin
  required), so a host/image toolchain divergence can never again pass every
  host-side gate while shipping a stale stdlib in the image.

## `v0.3.4`

Operator-experience release: one-command appliance lifecycle operations,
health-visible failure states, and a setup wizard that can no longer lose
the operator's credentials. Measured delta `v0.3.3..HEAD` at preparation:
33 commits, 89 files changed, +3475/−90, one new migration (0031) — plus
this release-prep commit itself (34 commits to the tag).

### Added

- **`doctor` subcommand** — read-only appliance diagnosis printing named
  states (`version`, `db`, `at-rest-key` source, `setup`,
  `signing-key-seal`); exit `0` healthy, non-zero with a `FAILING:` line
  naming each failing state. DSNs and key material are never printed.
- **`factory-reset` subcommand** — returns the database to factory state
  (schema wipe + re-applied migrations → empty, migrated,
  `setup_required`). Refused, with no database contact, unless the exact
  `--i-understand-this-destroys-all-data` flag is passed.
- **`GET /api/v1/health/details`** (site_admin) — OSS runtime health:
  `status` + `version` always; `database` / `audit_system` when wired;
  Redis and audit queue-depth fields absent rather than zero-faked.
  Registered in the canonical endpoint surface (api-docgen).
- **Admin state on the organizations read surface** — `is_claimed` /
  `can_assign_admin` are projected from live org_admin counts on
  `GET /api/v1/organizations` and `GET /api/v1/organizations/:id`; a
  wiring gap yields ABSENT fields (never `false`) plus a health fault.
- **Migration 0031** — the database refuses to mark setup complete unless
  a live site_admin exists, so setup-state and site_admin existence can
  no longer disagree.
- **`docs/OPERATOR-GUIDE.md`** — every appliance lifecycle operation as
  one copy-paste `docker exec` command for image-only installs (no shell
  in the container, no DSN assembly).
- **Machine-checked rule ledger** (`RULE-FLOOR.md`) — 85 armed rules, all
  red-proved, verified by `make verify` and CI; internal quality
  infrastructure with no runtime surface.

### Changed

- **Setup wizard adopt-and-reset** — completing setup against a database
  that already has a site_admin now ADOPTS that account and resets its
  credentials; the completion screen reports the pinned
  `site_admin@system.local` login (never the operator-typed contact
  address), and `bootstrap` marks setup complete so a bootstrapped
  database can no longer present the wizard with a credential-eating
  split-brain.
- **Signing-key seal is health-visible** — active signing keys that no
  longer decrypt under the current at-rest key put the process into
  NOT-SERVING: `/health` answers `503` with a named `signing-key-seal`
  fault instead of a silent every-login-fails brick.
- **One-shot subcommands know their own database** — `migrate`,
  `bootstrap`, `recover-site-admin`, `show-setup-code`, `doctor`, and
  `factory-reset` all fall back to `IDENTUUM_IDP_DATABASE_URL`, then
  `IDENTUUM_IDP_OSS_DB`, when no URL argument is given; an explicit
  argument wins and the URL is never printed.
- **`recover-site-admin` works on the distroless image** — the make
  wrapper execs the binary directly (no `sh`), and the subcommand reads
  the at-rest key from the appliance data volume when the environment
  does not carry it.
- **Test infrastructure** (no runtime surface): integration suites run
  against a dedicated `*_test` database with a harness guard that refuses
  non-test DSNs; the session-rotation replay test measures its grace
  window on a single clock so host-vs-VM drift cannot flake it.

## `v0.3.3`

First public release.

### Added

- `LICENSE`: All Rights Reserved (view/evaluation only) —
  `SPDX-License-Identifier: LicenseRef-AllRightsReserved`. `NOTICE` keeps
  the third-party-attribution paragraph, which covers this module's own
  Go dependencies (declared in `go.mod`/`go.sum`) and is unaffected by
  this repository's own license.
- `README.md` Project Status section: published for viewing and
  evaluation only, not currently open source, external contributions
  not accepted.

No code or protocol behavior changes in this release; the binary
version is not bumped (no `ldflags` stamp, no version-string commit).

Full notes in `docs/releases/v0.3.3.md`.
