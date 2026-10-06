# Changelog — identuum-idp-oss

All notable changes to `identuum-idp-oss` are recorded here, starting from
the first public release. Format roughly follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning
follows [Semantic Versioning](https://semver.org/).

## `v0.9.8`

identuum-ui `d009997` embedded (`v0.9.7` embedded `1354a72`). The delta
since `v0.9.7` (`git rev-list --count v0.9.7..HEAD` and `git diff
--shortstat v0.9.7..HEAD`, measured at `a7e2c6f`, before the notes commit)
is 37 commits, 53 files, +1910/−132. One migration, `0051` (the
`service_account_expiry_days` column default becomes `0`; no row changes).
The endpoint count stays 159 (`go run ./tools/api-docgen --dry-run`).

The embedded console gains, from identuum-ui `1354a72..d009997`: the
org_admin's **Service accounts** card in organization settings (expiry in
days, `0` = none); sign-in that sends the browser to single sign-on only on
this server's own `/api/v1/auth/idp/<id>/login`, and a new organization's
activation link shown as a link only when it is `https` or on this console's
own origin; and an export that runs under the new script policy (zod runs
without its `eval` probe).

- **The console page carries a script policy and no-referrer.** Every
  response that serves the console's page (not the API) now sends
  `Content-Security-Policy: default-src 'self'; script-src 'self'; style-src
  'self'; img-src 'self'; font-src 'self'; connect-src 'self'; object-src
  'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'` and
  `Referrer-Policy: no-referrer`, so only the console's own scripts run and an
  account link's credential (`/claim`, `/invite`, `/reset-link`) is never
  sent as a `Referer`. API responses keep their headers. A reverse proxy must
  not remove or replace them (OPERATOR-GUIDE, "Security headers").

- **A token minted for an API resource can be introspected by that
  resource.** Until now introspection answered `{"active":false}` for a
  `client_credentials` token issued with `audience=<API resource>`, even to
  that resource. Now it is active to the API resource it names, when the
  resource and the token belong to the same organization, and to the client
  it was issued to; every other caller, the site_admin path included, still
  gets `{"active":false}`. A deleted or inactive resource's tokens stay
  inactive, and such a token is still refused as a bearer on the IdP's own
  API and at userinfo. Tokens addressed to the IdP are answered as before.

- **New organizations start with the service-account expiry off.** A new
  organization's `service_account_expiry_days` is `0` (no default expiry)
  unless its create request names a value; its org_admin turns it on
  (1 to 3650 days) through `PUT /api/v1/organizations/:id` or the console's
  organization settings. Migration 0051 makes the column default `0`, as the
  create path already stored; no existing organization row changes.

- **An organization's service-account expiry is applied.** A service account
  created without `expires_at`, in the console or with its OAuth client, now
  expires the organization's `service_account_expiry_days` after creation.
  `0` means no default expiry; an explicit future `expires_at` is kept.
  Accounts that exist are not changed, and changing the value later changes
  no existing account. If the organization's value cannot be read, the
  account is not created. Upgrade note: an organization whose stored value is
  above `0` (check it in the console's organization settings) gives its new
  accounts that expiry unless a date is set.

- **Gate tidy-up** (maintainer tooling; no product change). `wiki-fresh`
  is no longer a verify-plan entry: the wiki's own check judges this
  repository's page pin at the close, so a slice here can reach green
  without writing the wiki. `make witness` first runs `ledger-census`,
  the wiki's retirement-ledger census, so a tools/ line-count change is
  refused here, naming the ledger row to edit. A new planned check,
  `record-home-paths`, refuses a tracked GATE-RUN*.txt line that names a
  user's home directory. A dry-run selftest proves test-full's tier
  dispatch (quick only when the classifier owes e2e-quick) without a
  stack or a container.
- **ledger-diff-gate judges where the ledger rebase sits** (maintainer
  tooling; no product change). In the cycle after the newest witness
  reachable from HEAD, the first commit must change ledger-amendments.json
  and nothing else, and no later commit may change it; otherwise the gate
  fails naming the commits and saying what to do. A HEAD that is itself a
  witness has an empty cycle, and older cycles are never judged. The
  base_commit check is unchanged and still runs first. identuum-ui's
  `make ledger-diff-gate` runs this same judge.
- **Development targets never touch the owner's own containers** (maintainer
  tooling; no product change). `make fast-up` reuses a PostgreSQL that
  already answers 127.0.0.1:5513 with the dev user (it used to fail on the
  bound port, and the way out was to stop that server), and refuses an
  incompatible one without stopping it. Every container target first runs
  `protected-guard`, which refuses when the compose project or a container
  name resolves to `identuum-idp-oss` or `identuum-idp-oss-postgres`, or the
  published compose file is used; `make protected-check SCRIPT=<file>`
  refuses a proof script that would stop, remove, recreate or rename them.
  `DEV_APP_CONTAINER` now defaults to the dev compose's own name
  (`identuum-idp-oss-dev`), not `identuum-idp-oss`. The published compose is
  unchanged.

## `v0.9.7`

identuum-ui `1354a72` embedded (`v0.9.6` embedded `57482c5`). From this
release identuum-ui follows this repository's version numbers (owner ruling,
2026-10-05): the embedded export is identuum-ui `v0.9.7`. The delta since
`v0.9.6` (`git rev-list --count v0.9.6..HEAD` and `git diff --shortstat
v0.9.6..HEAD`, measured at `abb76e9`, before the notes commit) is 12
commits, 42 files, +1651/−75. No migration. The endpoint count is 159
(157 + 2: `POST /api/v1/mfa/setup/initiate` and `/complete`; `go run
./tools/api-docgen --dry-run`).

These close the remaining Medium findings of the 2026-10-05 functionality
review and the two items `v0.9.6` left open; each code fix has a test that
failed first.

- **Account settings can add an authenticator** (FUNC-M1). The console posts
  to `/api/v1/mfa/setup/initiate` (`{password}` → secret and otpauth URL,
  once) and `/complete` (`{code}` → ten recovery codes, once), the contract
  identuum-idp-ce serves; OSS mounted neither and answered `404`. A wrong
  password answers `401 invalid_proof` and counts on the per-user proof
  budget; a spent budget answers `429 login_throttled` with `Retry-After`;
  an enrolled user gets `409 mfa_already_enrolled`.
- **Step-up and the other proof routes give sign-in's wait answer.** Past
  the wrong-code budget, MFA disable, recovery-code regeneration and skip
  consent answer `429 login_throttled` with `Retry-After`, and the step-up
  page says to wait (it said the code was invalid).
- **HTTP Basic client credentials are form-decoded** (RFC 6749 §2.3.1,
  FUNC-M8): a resource server whose audience is a URL authenticates with
  HTTP Basic at introspection; it was refused `401`.
- **A database that is down at boot is waited for** (FUNC-M9). The binary
  and the container no longer exit: they print `NOT-SERVING`, answer
  `/livez` and `/healthz` `200`, `/health` `503` with the `database` fault
  and every other route `503`, retry (1 s doubling to 30 s), and start
  serving when the database answers. The compose install crash-looped
  before.
- **`last_login_at` is recorded** on every completed sign-in (FUNC-M15); the
  console's "Last login" column was always empty.
- **The setup wizard says why it refuses a password** (FUNC-M6):
  `400 weak_password` with the policy sentence (it answered
  `setup_complete_failed`), and the wizard's hint states the whole rule.
- **Console** (identuum-ui `v0.9.7`): held sign-ups show Awaiting approval
  (FUNC-M4), scope templates show (FUNC-M5), the service-account form says
  what the IdP does (FUNC-M7), an active organization's administrator can be
  re-invited (FUNC-M13), the audit log reaches older events (FUNC-M16), and a
  new **Sign-in provider** page configures the organization's upstream OIDC
  provider.
- **Docs**: losing the at-rest key stops the whole IdP, and how to restore
  it (FUNC-M11); signing-key rotation, and the RS256 sentence corrected
  (FUNC-M12); resetting a user's password without email (FUNC-M14); the
  service-account bundle route (FUNC-M7); the database-down boot.

## `v0.9.6`

identuum-ui `57482c5` embedded (`v0.9.5` embedded `4ff1270`): the sign-in
code field takes a recovery code, and the password and code steps say how
long to wait. The delta since `v0.9.5` (`git rev-list --count v0.9.5..HEAD`
and `git diff --shortstat v0.9.5..HEAD`, measured at `9eb51ac`, before the
notes commit) is 12 commits, 62 files, +2000/−266. No migration, and the
endpoint count stays 157 (`go run ./tools/api-docgen --dry-run`).

These close the High and sign-in Medium findings of the 2026-10-05
functionality review; each has a test that failed first.

- **A public client redeems its authorization code.** An app registered with
  `token_endpoint_auth_method: none` (the console's "Public client") sends
  `client_id` and the PKCE `code_verifier` with no secret, and receives an
  access token and an ID token. It gets no refresh token: the refresh grant
  needs client authentication. Discovery lists `none` for the token endpoint
  (not for introspection or revocation). Before, the exchange answered
  `401 invalid_client`.
- **A recovery code signs in.** Where the sign-in page that `/authorize`
  shows (and `POST /api/v1/auth/login` with a code) asks for the
  authenticator code, an unused recovery code now completes the sign-in, once,
  counted against the same wrong-code budget, and records
  `user_session.login.mfa_recovery_code_consumed`. The console's code field
  takes one. Step-up and the other proofs still take only an authenticator
  code.
- **Upstream OIDC works as the guide says.** `docs/guides/oidc-upstream-login.md`
  now shows the request body the API takes (it listed flat fields the API
  refused with `400`). A provider configured without `config.redirect_uris`
  uses the callback the guide says to register,
  `{issuer}/api/v1/auth/idp/{provider_id}/callback` (before, login start
  answered `404`). The new **test** setting
  `IDENTUUM_IDP_TEST_ALLOW_PRIVATE_UPSTREAM_ISSUER=true` (off by default,
  logged as a `WARNING` at startup) lets the sign-in reach a provider on
  loopback or a private network over `http`, so the success path can be
  tested end to end. Do not use it in production. A provider's
  `email_domains` are now stored: until now they were dropped on save, so
  the allow-list refused every user of a provider configured through the
  API. **Set them again** (`PUT` on the same path) for a provider configured
  before v0.9.6.
- **A correct password is never answered "invalid credentials".** While a
  per-address sign-in bound holds (5 failures for one account from one
  address, or 10 failing accounts from one address, in 15 minutes) the
  answer is now `429 login_throttled` with `Retry-After` until the oldest
  counted failure leaves the window — the answer the account-wide
  slow-down already gave. The bounds are unchanged. Rule `LOCKOUT-1` is
  amended to this answer.
- **A spent wrong-code budget says to wait.** At 5 wrong codes for one user
  in 15 minutes, every code at the sign-in code step, the right one included,
  answers `429 login_throttled` with `Retry-After` instead of
  `401 invalid_code`. `reset-org-admin-mfa` clears the wrong codes counted
  against the removed factor, and fails if it cannot.
- **The OpenID conformance harness runs again.** `make openid-conformance`
  had stopped at provisioning since `v0.9.5`: its provisioner now sets the
  organization's MFA policy as the org admin and creates its test user with
  `must_change_password: false`, and no refusal body reaches the log.
  `docs/TESTING-OPERATORS.md` records it as a release step.
- **Withdrawn:** the review's report that a refreshed access token was
  refused at `userinfo` and introspection came from its own test client,
  which replayed the old refresh token (reuse revokes the family). A guard
  test now proves both halves through the whole engine.

## `v0.9.5`

identuum-ui `4ff1270` embedded (`v0.9.4` embedded `5627ba2`): a site
administrator's organization form edits only the name and whether the
organization is active, an org admin's settings page sets the organization's
name and MFA policy, and the sign-in form asks the user to wait during the
account-wide slow-down. The delta since `v0.9.4` (`git rev-list --count` and
`git diff --shortstat`, measured at `cace374`, before the notes commit) is
25 commits, 114 files, +3239/−260. Three migrations (`0048` to `0050`), and
the endpoint count stays 157.

- **A tenant organization's policy belongs to its org admin** (owner
  ruling). `PUT /api/v1/organizations/:id` is open to the organization's own
  org admin (scope `orgs:update`). A site administrator changes only
  `active` and `name` of a tenant organization; any other field answers
  `403 forbidden_field` and names the fields, before any value is read or
  written. The org admin changes `name`, `domain`, `local_admin_only` and
  every policy field, and never `active` (`403 forbidden_field`). The System
  organization is unchanged: the site administrator edits it as before. The
  audit event names the actor and the fields. **An organization with no org
  admin keeps its policy until one is appointed.**
- **An org admin restores its own organization's deleted users.**
  `POST /api/v1/users/:id/restore` admits an org admin (scope
  `users:delete`) for a user of its own organization; another
  organization's user answers `404`. A site administrator is still refused
  for a tenant user (`403`, D-025). The audit event names the actor and the
  organization.
- **An org admin reaches its own apps' back-channel logout deliveries.** The
  list, read and replay routes under
  `/api/v1/admin/backchannel-logout-deliveries` admit an org admin for the
  apps of its own organization (`clients:read` to read, `clients:update` to
  replay); another organization's delivery answers `404`. A site
  administrator still lists every delivery, but sees `user_id` and
  `session_id` only for apps of the System organization, and replays only
  those and apps with no organization (`403` otherwise).
- **`reset-org-admin-mfa`, a host-only operator command.** An organization
  whose only org admin lost every second factor gets that admin back:
  `identuum-idp reset-org-admin-mfa --org <id> --email <address> [db-url]`
  removes the admin's authenticator, recovery codes and passkeys, revokes the
  admin's sessions and refresh tokens, and records `org_admin_mfa_reset`
  (actor `system`, `via=cli`). It refuses the System organization and any
  user who is not an org admin. It needs the database, so it runs on the host
  (`docker exec`, or `docker run --entrypoint`); see
  `docs/OPERATOR-GUIDE.md`.
- **Repeated failed sign-ins slow one account down, from any address; it is
  never locked.** After 5 failed password sign-ins for one account in 15
  minutes, from any number of addresses, the next attempt must wait 1 second
  after the last failure, then 2, 4 and so on up to 60 seconds. Inside the
  wait the password is not checked and the answer is
  `429 {"error":"login_throttled","retry_after_seconds":n}` with
  `Retry-After`; the browser sign-in page says to wait. A successful sign-in
  resets the count. The per-address rules are unchanged.
- **An app's access token no longer carries the user's role.** A token
  issued to an app (it carries the app's `client_id`) has no `role` claim,
  and `userinfo` answers it without `role`. Console session tokens are
  unchanged.
- **`/authorize` refuses an app not registered for the code grant.** An app
  whose registered grant types do not include `authorization_code` gets
  `unauthorized_client` at its redirect URI, and no code. An app with no
  grant types recorded keeps working.
- **The proof routes' wrong-code budget survives a restart** (migration
  `0048`). The per-user count of wrong second-factor codes at step-up, MFA
  disable, recovery-code regeneration and turning skip consent on (5 in 15
  minutes) is kept in the database; when it cannot be read, the code is
  refused. Old rows are swept by the cleanup job.
- **An RFC 7592 client update keeps the limits of the initial access token
  that registered it** (migration `0049`). The registration stores the
  token's allowed grant types and auth methods with the client, and an
  update that asks for more answers `403 invalid_client_metadata`. No
  shipped binary mounts the client-management route yet; the limits are
  kept so that it is right when one does.
- **A deleted organization releases its API resources' audiences**
  (migration `0050`). Deleting an organization marks its API resources
  deleted, and the installation-wide audience rule counts only resources
  that are not. Restoring the organization brings back each resource whose
  audience is still free. The migration marks the resources of
  organizations already deleted.
- **Sign-in through an upstream identity provider keeps one binding cookie per
  sign-in**, so a second sign-in started in the same browser no longer
  voids the first. A sign-in in progress during the upgrade starts again.
- **Smaller fixes.**
  - Every public self-registration answer takes at least 300 ms, so the
    answer time does not show whether an address has an account (a policy
    refusal is not delayed).
  - A request that ends while it waits for an Argon2id slot frees its place
    in the queue; a cancelled sign-in is not counted as a failure.
  - Shutdown waits for the mail sent after a response before it closes the
    database, and says so when the shutdown deadline cuts it off.
  - The untrusted-proxy warning (`forwarded_header_ignored`) remembers the
    last 64 peers and logs at most 10 warnings a minute, so a new peer is
    still named after the first 64.
  - The setup banner's command to show the setup code names the running
    binary's path (`/app/identuum-idp` in the image); the deployment README,
    the compose comments and the manual test guide say the same.

## `v0.9.4`

identuum-ui `5627ba2` embedded (`v0.9.3` embedded `9cfd09b`): the
authenticator-code field and the "Skips consent" badge for first-party apps,
the recent-sign-in message for account passkeys, an organization page that no
longer offers a site administrator a Reset MFA button, and application forms
that keep what was typed when a save is refused. The delta since `v0.9.3`
(`git rev-list --count` and `git diff --shortstat`, measured at `9556d2a`,
before the notes commit) is 58 commits, 191 files, +8882/−338.
Four migrations (`0044` to `0047`), and the endpoint count stays 157.

- **Users sign in only to apps of their own organization** (D-027).
  `/authorize` issues a code only when the app belongs to the signing-in
  user's organization; an app of another organization answers like an
  unknown client. An app with no organization (registered by the site
  administrator) stays available to every organization. The consent page
  answers another organization's app the same way (no name shown, no consent
  stored, no redirect), and a refresh token issued earlier to another
  organization's app stops at its next use (`invalid_grant`).
- **`/authorize` and the consent page act only for a browser session.** A
  bearer access token no longer drives them (it gets the sign-in page); the
  person at the browser decides what an app is granted.
- **A token issued to an app is not a credential for the IdP's own API.** A
  user token minted for an app (it carries the app's `client_id`) is still
  accepted by `userinfo` and token introspection, and no longer by the
  admin and account routes under `/api/v1`. The access token the refresh
  grant mints for an app is held to the same rule, and an app's token that was
  revoked, or whose session, user or organization is gone, is refused on every
  route that reads it (`GET /api/v1/validate` included).
- **Site administrators do not edit tenant users** (D-025). Changing,
  disabling, deleting, restoring or resetting MFA of a tenant user, and
  deciding a self-registration, are refused (`403`) for a site administrator.
  What remains is appointing the first org admin of an organization that has
  none (including re-sending that invite). The console's organization page
  shows an organization's admins as status only, with no Reset MFA button.
  **A deleted tenant user cannot be restored over HTTP in this release:** the
  restore route admits only a site administrator, and no route lets an org
  admin do it yet.
- **An app introspects and revokes only its own tokens.** An app that calls
  `POST /api/v1/oauth/introspection` or `POST /api/v1/oauth/revoke` with its
  own client credentials gets `{"active":false}`, or an empty `200` that
  changes nothing, for a token that was not issued to it (`client_id`) and is
  not addressed to it (`aud`). A resource server authenticating with its API
  resource's credentials introspects any token presented to it, as before,
  and an agent-communication participant token is answered to any
  authenticated relay holding it. Revocation stays the issuing app's alone.
  Introspection also reports inactive a token whose session was revoked,
  whose user or organization is gone, or whose service account was disabled
  (a session row already swept reads inactive, not unavailable), and a
  `token_type_hint` that points at the wrong type no longer leaves a refresh
  token live.
- **A service-account token stops when its account does.** Disabling a service
  account, letting it expire, or deactivating or deleting its organization now
  stops its tokens at the next request instead of at the token's expiry
  (`401`; `503` when the check cannot run).
- **Cookies are `Secure` whenever the configured issuer is `https`.** The flag
  followed only the request's `Host` header, so a request that claimed
  `Host: localhost` could receive a cookie a browser would also send in clear.
  An `http` or unset issuer keeps the local-development exception.
- **`make dev-seed` works again.** `tools/devseed` invites the first org admin
  and redeems the invite (a site administrator no longer edits a tenant user)
  and creates the seeded org user without a forced password change.
- **Sign-out accepts an expired `id_token_hint`.** The signature and issuer are
  still verified; only the token's lifetime is no longer held against a hint
  used to end a session (OIDC RP-Initiated Logout 1.0 §2). The hint must be an
  ID token: an access token presented as one is refused (`400`), and the
  hint's `sid` names the session it ends.
- **A presence-only passkey no longer earns the phishing-resistant level.** The
  passkey step-up asks the authenticator to verify the user and refuses an
  assertion in which it did not (`401 user_verification_required`, no uplift);
  a passkey sign-in that was presence-only (allowed only where the
  organization does not require MFA) is recorded at the lowest level instead
  of the top one. Sign-in with a user-verified passkey is unchanged.
- **Passkeys follow account recovery and need a recent sign-in.** An
  organization admin's MFA reset now removes the user's passkeys as well as
  the authenticator. Starting a passkey registration, and removing a passkey,
  need a sign-in (or step-up) from the last 10 minutes; an older session gets
  `403 reauth_required` and the account page asks the person to sign in
  again.
- **An API resource's audience is unique across the installation** (migration
  `0045`), and is never the issuer or an application's client id. Creating
  or renaming onto a taken audience answers `409 audience_exists`; an
  audience equal to the issuer or a client id answers `400`. **If two
  organizations already hold the same audience, the migration stops and names
  it; rename or delete all but one, then migrate again.** It changes no row
  itself.
- **`client_credentials` for an API resource is held to the client's
  registration.** A request with an `audience` succeeds only when the
  audience is in the client's `allowed_audiences` and the resource belongs to
  the client's organization; otherwise `invalid_target`. **A client that asks
  for an audience without listing it now fails; add it to the client's
  allowed audiences.** A request with no `audience` is unchanged.
  `/authorize` holds an `audience` to the same organization rule (an active
  API resource of the app's organization, else `invalid_target`), since the
  audience rides on to the refresh token. A store failure while checking a new
  resource's audience answers `500`, not `400`.
- **MFA wrong codes are bounded per user.** The per-sign-in limit is joined by
  a per-user limit: 5 wrong codes in 15 minutes across all of a user's
  pending sign-ins, after which even the correct code is refused until the
  window passes. The routes that prove the second factor to a signed-in
  caller — step-up, self-service MFA disable, recovery-code regeneration and
  turning "skip consent" on — share their own budget of wrong codes per user
  (5 in 15 minutes, counted in memory), with the same refusal. One user's
  codes are checked one at a time, so wrong codes sent in parallel are
  counted one by one and cannot pass a bound together.
- **"Skip consent" has four guards** (D-026). An application an org admin
  marked **First-party (skip consent)**:
  - must be a confidential app created in the console; an app created
    through dynamic client registration can never have it (migration `0044`
    adds `oauth_clients.dynamically_registered`, marks apps that already hold
    a registration access token, and clears their `skip_consent`);
  - signs the user in silently only for `openid`, `profile` and `email`. A
    request for anything more (`offline_access`, another scope, an API
    resource through `audience`, or an address or phone claim through the
    `claims` parameter) shows the consent screen for it. **An
    existing first-party app that asks for more than identity now shows
    consent for those scopes.**
  - needs the org admin's current TOTP code to be turned on:
    `POST /api/v1/clients` and `PUT /api/v1/clients/:id` take `mfa_code`
    when `skip_consent` becomes `true` (`400 mfa_code_required`,
    `400 mfa_not_enrolled`, `403 invalid_mfa_code`);
  - is recorded: `client.created` and `client.updated` carry
    `mfa_verified`, beside the existing `skip_consent_before` and
    `skip_consent_after`, and the audit event names who made the change.
- **A refresh-token family stops rotating after 90 days.** Each rotation gave
  the successor a fresh 30-day lifetime, so a refresh token that stayed in use
  never expired. The family's age (read from its UUIDv7 id) now caps it: past
  90 days from the sign-in that created it, `grant_type=refresh_token` answers
  `invalid_grant` and the user signs in again. Tokens issued before the family
  id existed keep sliding as before.
- **A scope narrows a role.** An org admin's token that carries none of the
  org-admin scopes (an identity-only token) is read as a plain member, so the
  routes that check the role alone refuse it. Console sessions carry the
  org-admin scopes and are unaffected.
- **An org admin cannot give an app more than the admin holds.**
  `POST /api/v1/clients`, `PUT /api/v1/clients/:id` and
  `POST /api/v1/organizations/:id/service-accounts/with-client` answer
  `400 invalid_scope` when `scope` names a scope of the IdP's own catalogue
  the admin does not hold (`keys:rotate`, `orgs:create`, `identuum-admin:admin`
  and the like). Identity scopes, `connector:litellm` and an organization's own
  API scopes are unaffected. A scope an app already holds is not judged again,
  so an app stored before this change can still be edited and saved; a scope
  an edit adds is judged. **An org admin can no longer create a
  service-account client with the gateway scopes `mcp:access_*` or
  `identuum-admin:*`, which an org admin's session does not hold.**
- **An upstream-provider sign-in finishes only in the browser that started
  it.** `GET /api/v1/auth/idp/:id/login` plants a host-only, HttpOnly,
  `SameSite=Lax` cookie (`idp_login_state`, ten minutes) holding the sign-in
  state, and the callback refuses (`400 invalid or expired login state`, state
  not consumed) a request without it. A callback link handed to another person
  no longer signs them in as the person who began it. The login link and the
  callback must be on the same host.
- **Sign-in is harder to brute-force and to exhaust.**
  - The attempts of one account from one address are serialized, so a burst of
    parallel wrong passwords is stopped at the failure threshold instead of
    all being checked before the first failure is recorded.
  - The routes where a caller proves a secret share a per-address limit of
    120 requests a minute (`IDENTUUM_IDP_RATE_LIMIT_CREDENTIAL_REQUESTS` and
    `_WINDOW`); the next request answers `429`.
  - Argon2id runs in flight are capped between 2 and 8 (by CPU count), so a
    burst of sign-ins queues instead of holding 64 MiB each at once.
  - A sign-in for an email with no account compares against a dummy hash with
    the same Argon2id cost as a real one (it used 2 lanes against 4), so the
    response time no longer tells whether an account exists.
- **Password reset, verification resend and self-registration no longer show,
  by their response time, whether an address has an account.** The token, the
  mail and the audit row of a reset or a resend are produced after the response
  (a mail send took tens to hundreds of milliseconds only when the account
  existed). A self-registration for a taken address spends the hashing time a
  new account's password does, and the mails of both go out after the response.
  The mail therefore arrives a moment after the `200` or `202`, and a failed
  send is logged, not seen by the caller (it never was). What still differs
  between a new and a taken address is a few database writes, a millisecond or
  two.
- **The session cookie is persistent only when "remember me" is ticked.** The
  browser-login session cookie carried an expiry whether or not the box was
  ticked, so it outlived the browser. Unticked, it now has no expiry and ends
  with the browser session; a sign-in through an upstream provider, which has
  no such box, gets the same. The server-side session lifetime is unchanged.
- **Sign-out asks before ending a session when no `id_token_hint` vouches for
  the request.** `GET /api/v1/oidc/logout` can be fired from any page the user
  visits, so a request that arrives with the session cookie and no verified
  hint, or with a hint for another person or another session, now shows a
  "Sign out?" page and ends nothing; its link carries a value only the browser
  holding the cookie was shown (RP-Initiated Logout 1.0 §2). Requests whose
  verified hint belongs to this browser's session, and requests with no
  session, behave as before. `GET /api/v1/oidc/frontchannel-logout` asks the
  same way when a browser opens it as a page; loaded in an iframe, its use, it
  is unchanged. Each app's logout token names the user of the session that app
  held.
- **Newly generated MFA recovery codes carry 80 bits.** They were 8 base32
  characters (40 bits), stored as an unkeyed SHA-256, which a reader of the
  database could test offline in seconds. They are now 16 characters (80 bits),
  too large to guess. Codes issued earlier keep working until they are
  regenerated (`POST /api/v1/me/mfa/recovery-codes/regenerate`), which is the
  way to move an existing user to the longer ones.
- **The IdP's own pages carry a content security policy that loads nothing and
  runs no script.** Sign-in (with its password-change and MFA-enrolment steps),
  consent and step-up answered only `frame-ancestors 'none'`; they now also
  send `default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'`, so a
  markup-injection bug in one of them cannot execute code. The passkey step-up
  page, which runs one script, allows exactly that script by a per-response
  nonce and calls back only to its own origin. The JSON API and the embedded
  console keep the engine-wide policy.
- **The grant types an app registers are stored and enforced** (RFC 7591).
  `POST /api/v1/oauth/register` echoed `grant_types` but kept nothing, so an app
  registered for `authorization_code` could still ask for a `client_credentials`
  or `refresh_token` token. Migration `0046` adds `oauth_clients.grant_types`;
  a registration now records what it asked for (`authorization_code` when it
  asked for nothing), the RFC 7592 read returns it and the update can change it,
  and the token endpoint answers `unauthorized_client` for a grant outside the
  set. **An app that needs refresh tokens must now register `refresh_token`.**
  Apps created in the console, and every app registered before this change,
  carry no set and stay unrestricted. `offline_access` hands no refresh token
  to an app whose set lacks `refresh_token`; an initial access token's grant
  limit is judged on what a registration records (`authorization_code` when it
  names none); an update with an empty `grant_types` list changes nothing; a
  missing `grant_type` stays `invalid_request` and an unknown one
  `unsupported_grant_type`.
- **ID tokens carry `sid`.** The session an ID token was issued for is named by
  the standard `sid` claim (OIDC Front-Channel and Back-Channel Logout), so a
  relying party can match a logout token or a front-channel request to the
  session it holds. Access tokens keep their `session_id` claim.
- **Back-channel logout reaches every app that holds an ID token for the
  session.** It reached only the app that asked for the sign-out, and only when
  that request named a `post_logout_redirect_uri`. Migration `0047` adds
  `session_relying_parties`; the token endpoint records each (session, app) it
  issues an ID token for, and `GET /api/v1/oidc/logout` now posts a logout token
  (with `sub` and `sid`) to every recorded app that registered a
  `backchannel_logout_uri`, after the response and whether or not a redirect was
  requested. A delivery that fails is retried by the existing retry driver and
  never stops the others or the sign-out. Sessions whose tokens were issued
  before this change have no record and are notified only through the app that
  asked, as before.
- **The runtime image moves from distroless `base` to distroless `static`, and
  the builder and prep digests are refreshed.** The `base` flavour ships libc6
  and libssl3, and a scan of its newest build still showed 2 Critical and 7
  High findings in them (the libssl3 fixes were not in the base and libc6 is
  will-not-fix); none is reachable from the static, CGO-free binary. `static`
  has neither package and scans with no findings. Nothing else in the image
  changes: the binary, the CA bundle, the account files and the data directory
  are copied exactly as before.
- **A reverse proxy that is not listed as trusted is now reported.** The default
  of trusting no proxy is right against a forged `X-Forwarded-For`, but behind a
  proxy the operator did not list every user shares the proxy's address, so the
  per-address limits and the sign-in lockout (ten different accounts failing
  from one address in fifteen minutes) count them all together. The first
  request from such a peer that carries a forwarding header now logs one
  `forwarded_header_ignored` warning naming the peer (at most 64 peers), and the
  operator guide says what the lockout does. The lockout itself is unchanged.

## `v0.9.3`

identuum-ui `9cfd09b` embedded, unchanged since `v0.9.2`. The delta since
`v0.9.2` (`git rev-list --count`, measured at `e4be7d6`, before the notes
commit) is 41 commits, 78 files, +8024/−609. `THIRD_PARTY_NOTICES` is most
of the added lines. There is no migration, and the endpoint count stays
157. `go.sum` gains `github.com/google/licensecheck`, which only the
notices tool uses.

- **Security hardening** (each change has a test that failed first):
  - the sign-in and step-up `return_to` target is a local path only;
  - consent "deny" redirects only to a registered URI;
  - registered redirect URIs carry no fragment or userinfo and use https
    off loopback;
  - the PKCE `code_verifier` has the RFC 7636 shape;
  - `private_key_jwt` assertions are bounded from now, and the replay
    record outlives them;
  - an admin-set password revokes the user's sessions and refresh tokens;
  - a completed password reset retires the user's other links;
  - the activation link redeems only for a pending org admin, and resend
    refuses an activated one (`409`);
  - passkey sign-in fails closed (`503`) when the org policy cannot be
    read;
  - outbound redirects are limited (GET only, https, same host, at most
    three);
  - the encryption-key file must be a regular file;
  - client-secret regeneration returns fixed messages;
  - logs carry user ids instead of email addresses, and redact `/bff`
    token paths.
- **Deployment:** the compose file pins PostgreSQL by digest;
  `deployment/README.md` documents changing the database password; stale
  compose comments are corrected.
- **CI:** read-only `permissions`; grype is installed from a
  checksum-verified release archive.
- **Contributing guide and issue forms.** `CONTRIBUTING.md` says how to
  report a bug or request a feature (pull requests are not accepted yet);
  the bug and feature templates are now issue forms that ask for the
  version, install method and PostgreSQL version.
- **Third-party notices ship.** `THIRD_PARTY_NOTICES` lists every Go module
  the binary is built from and every npm package of the embedded UI, with
  version, SPDX id and licence text; the binary prints it (`identuum-idp
  licenses`) and the image carries it at `/app/THIRD_PARTY_NOTICES`.
  Maintainer-only material moved to `docs/maintainers/`.

- **Docs:** the README names no version that can go stale (it points to the
  Releases page and `CHANGELOG.md`; the bare-binary example reads the latest
  release), states Go 1.27.1 as `go.mod` does, and `SECURITY.md` covers the
  latest release line and drops pre-release and internal-path wording.

- **Release publishes run only on their tag.** `publish-binaries.yml`
  (release mode) and `publish-image.yml` refuse, before anything is built,
  a dispatch ref other than `refs/tags/<version_tag>`, since GitHub's
  attestations and the image's provenance record the dispatch ref (v0.9.2's
  name `refs/heads/main`).

## `v0.9.2`

identuum-ui `v0.6.2` embedded (`9cfd09b`, tree digest
`a90ba076fed87eb95fadb6c2d3691e1a802ce9c5c6f4c35ecd86b2bf6436947c`). Delta
`v0.9.1..` (`git rev-list --count`, measured at `f803824`, before the notes
commit): 27 commits, 26 files, +513/−185 — the re-vendor is the product
change, the rest is gate and CI tooling. No migration; `go.mod`/`go.sum`
unchanged. The canonical endpoint count stays 157. No route, field or
response shape removed or renamed.

- **The embedded UI is identuum-ui `v0.6.2`**: /platform-status shows the
  commit the IdP serves after its version ("0.9.2 (commit <short>)"), read
  from the public `/system/info` `build_commit`.
- **CI's verify job runs its DB-backed tests under `-race` again.** Since
  `ci-verify` moved to `lictor witness run`, the job's database settings
  never reached `go test -race` (lictor's environment allowlist), so 17
  DB-backed tests skipped there under a green record; the Integration job
  still ran them. `go-test-race` now receives the settings as make
  command-line variables, and `IDENTUUM_IDP_REQUIRE_DB_TESTS` turns a
  missing database into a failure.
- **Gate tooling**: `make verify` runs through `lictor witness run --all`
  (v0.4.4); the Integration job's record is lictor's and `make ci-fetch`
  fetches it; toolchain-parity prints each tool's resolved path; the
  ci-verify subtractions are declared once and held to the plans; grype
  0.120.0. None of it is in the binary.

## `v0.9.1`

Fixes; identuum-ui `v0.6.1` embedded (`1f743e9`, tree digest
`8c2232e0a1f190d5f90b1242920fce119245d07a0c1dd62ee97c4aedade02bf6`). Delta
`v0.9.0..` (`git rev-list --count`, measured at `c805b46`, before the ledger,
vendor and notes commits): 12 commits, 17 files, +263/−54. No migration;
`go.mod`/`go.sum` unchanged. The canonical endpoint count stays 157. No
route, field or response shape removed or renamed.

- **The embedded UI is identuum-ui `v0.6.1`**: the sign-in no longer logs
  the organization-lookup miss or a pending self-registrant's refusal as a
  failed request, and the pending refusal reads "Your account is waiting for
  an administrator's approval.". Its identuum-idp-ce console changes key on
  capabilities this binary does not send, so nothing changes here.
- **The step-status opt-in covers two more expected answers.** With
  `X-Identuum-Login-Step-Status: 200`, a pending self-registrant's correct
  password (`403 registration_pending` at `POST /api/v1/auth/login`) and an
  organization-lookup miss (`404 organization_not_found` at
  `GET /api/v1/auth/organization-lookup`) answer 200 with the same body — no
  session, cookie or token. Without the header every answer is unchanged. The
  embedded console sends it on both calls, so neither is logged as a failed
  resource.
- **The image publish proves the image serves before pushing it.**
  `publish-image.yml` starts the loaded amd64 image against a throwaway
  Postgres (its own entrypoint: migrate, then serve) and requires `/readyz`
  200, the newest migration applied and `version` naming the tag and commit,
  before the scan and the push.

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
