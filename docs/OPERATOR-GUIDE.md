# Operator Guide — one-command appliance operations

Every lifecycle operation on a plain `docker compose up -d` install
(deployment/docker-compose.yml) is **one copy-paste command**. The container
already knows its own database (`IDENTUUM_IDP_DATABASE_URL` /
`IDENTUUM_IDP_OSS_DB` in its environment), so no command below assembles a
DSN, and none needs a shell inside the container (the runtime image is
distroless — it has none). Database URLs and key material are never printed
by any of these commands.

Running under compose from the deployment directory? `docker compose exec
identuum-idp` may be substituted for `docker exec identuum-idp-oss`
everywhere below.

Running the bare binary instead (no Docker)? Every command below is the same
subcommand of `./identuum-idp`; see README "Running the bare binary".

## Sign in the first time

After the setup wizard, sign in at `/login` as `site_admin@system.local`
with the password you chose in the wizard. This first sign-in enrols an
authenticator app (TOTP) and shows one-time recovery codes — store them; every
later sign-in asks for a code. Without the authenticator, enter one recovery
code (16 characters) where the sign-in asks for the code; each code works
once. The address you typed in the wizard is the site administrator's contact
email, not the login.

## Check health

```
docker inspect --format '{{.State.Health.Status}}' identuum-idp-oss
```

The image's healthcheck (`/app/identuum-idp healthcheck`) passes only when
`GET /healthz` (liveness: the process serves) and `GET /readyz` (the database
answers a ping) both answer 200. With PostgreSQL down the container turns
`unhealthy` within about a minute while `/healthz` stays 200; it turns
`healthy` again once the database is back.

If the database does not answer when the IdP starts, the IdP does not exit.
It prints `NOT-SERVING — the database does not answer at boot`, retries
(1 s, doubling, up to every 30 s), and meanwhile answers `/livez` and
`/healthz` with 200, `GET /health` with 503 naming the `database` fault, and
every other route with 503. When the database answers, it applies migrations
and starts serving; nothing needs restarting.

## Listen addresses: IPv4 by default, IPv6 opt-in

IPv4 is the default everywhere; IPv6 is supported and opt-in.

- **The binary** listens on `IDENTUUM_IDP_LISTEN` (or `--listen`), default
  `0.0.0.0:7113`: every IPv4 interface and **no IPv6**. An empty host
  (`:7113`) is IPv4 too. `[::]:7113` listens on IPv6 — and on IPv4 as well
  where the operating system gives a dual-stack socket (Linux does by
  default). An IPv6 literal (`[::1]:7113`, `[2001:db8::5]:7113`) listens on
  that address only. The metrics listener (`IDENTUUM_IDP_METRICS_ADDR`,
  default `127.0.0.1:9090`) follows the same rule. The healthcheck probes
  `127.0.0.1` for an IPv4 wildcard and `[::1]` for `[::]`.
- **The compose file** publishes `IDENTUUM_IDP_BIND_ADDRESS`, default
  `0.0.0.0`. `IDENTUUM_IDP_BIND_ADDRESS='[::]'` publishes on IPv6 instead;
  one variable publishes one family. To publish both, keep the default and
  add `"[::]:7113:7113"` in an override file (the compose file's header shows
  it). Inside the container the IdP keeps listening on IPv4.
- **Behind a reverse proxy**, list the proxy in `IDENTUUM_IDP_TRUSTED_PROXIES`
  — IPv4 and IPv6 addresses or CIDRs, comma-separated, e.g.
  `10.0.0.0/8,2001:db8:1::/48`. Only a listed proxy's `X-Forwarded-For` is
  honoured; unset, none is. A proxy you forget to list is not a silent
  failure: the first request that arrives from it with an `X-Forwarded-For`
  header logs one `forwarded_header_ignored` warning naming its address. Left
  unlisted, every user shares the proxy's address, so the per-address limits
  and the sign-in lockout (ten different accounts failing from one address in
  fifteen minutes lock sign-in for that address until the window passes) count
  all of them together.
- **Repeated sign-in failures slow sign-in down; nothing is told it is
  wrong.** Five failures for one account from one address, ten failing
  accounts from one address, or five failures for one account from anywhere
  (then a wait that doubles from 1 second up to a minute) make the next
  sign-in answer `429 login_throttled` with `Retry-After`, the right password
  included; the sign-in page says to wait. At the code step, five wrong codes
  for one user in fifteen minutes (any sign-in, any address) make every code,
  the right one included, answer the same `429` until the oldest leaves the
  window; the code step's per-address limits answer the same way. Step-up and
  the other second-factor proofs (MFA disable, recovery-code regenerate,
  skip consent) have their own budget of five wrong codes in fifteen minutes
  and answer the same wait (the step-up page says to wait). A success
  resets the account-wide count; the address limits pass with their
  fifteen-minute window.
- **Over IPv6 nothing degrades.** The audit log and sessions record the IPv6
  address. Rate limits and the sign-in lockout count an IPv6 client by its
  `/64`, so rotating addresses inside one `/64` does not escape a limit; an
  IPv4 client counts by its address, as before.
- **Sign-in requests per address.** The routes where a caller proves a secret
  (password sign-in, the second factor, the required password change, step-up,
  claim and organization activation) share one limit of 120 requests a minute
  per client address; the 121st answers `429`. Raise or lower it with
  `IDENTUUM_IDP_RATE_LIMIT_CREDENTIAL_REQUESTS` and
  `IDENTUUM_IDP_RATE_LIMIT_CREDENTIAL_WINDOW`. Behind a reverse proxy that is
  not listed in `IDENTUUM_IDP_TRUSTED_PROXIES`, every user shares the proxy's
  address and therefore one budget.

## Where data lives

- **PostgreSQL** (volume `identuum-idp-oss-postgres-data`): every
  organization, user, client, session, key and audit row. Sessions survive a
  restart of the IdP.
- **The data volume** (`identuum-idp-oss-data`, `/app/data`): the generated
  at-rest encryption key (unless you supply `IDENTUUM_IDP_ENCRYPTION_KEY`) and,
  until setup completes, the setup code. Losing the key makes MFA enrolments
  and signing keys unreadable: back it up with the database.
- **Bare binary:** the setup code goes to `IDENTUUM_IDP_DATA_DIR`, or when that
  is unset to `<user config dir>/identuum-idp` — never the working directory.

## Diagnose the appliance

```
docker exec identuum-idp-oss /app/identuum-idp doctor
```

Read-only. Prints one named state per line — `version`, `db`, `at-rest-key`,
`setup`, `signing-key-seal` — and exits `0` when healthy. On a fault it exits
non-zero and the final `FAILING:` line names each failing state (for example
`signing-key-seal` when active signing keys no longer decrypt under the
current at-rest key — the state that otherwise looks like "every login
fails").

## Show the setup code again

```
docker exec identuum-idp-oss /app/identuum-idp show-setup-code /app/data
```

Re-displays the one-time setup code after the boot log has scrolled away.
Only works while the appliance still reports `setup_required`; after setup
completes it refuses (the stale file is ignored).

## Reset the site_admin password (break-glass)

```
docker exec -e IDENTUUM_IDP_RECOVER_SITE_ADMIN_PASSWORD='<new-password>' identuum-idp-oss /app/identuum-idp recover-site-admin
```

Resets the `site_admin@system.local` password and clears its MFA enrollment
so the operator can sign in again. The password travels only through the
exec environment (mind your host shell history) and is never echoed.

### What this invalidates (the aftermath)

The reset rewrites `password_hash` AND wipes the MFA enrollment
(`mfa_enabled=false`, `mfa_secret=""`, `mfa_recovery_codes=[]` —
cmd/identuum-idp/recover.go). The moment the command returns, ALL of the
following are stale:

- **The authenticator app entry.** The old TOTP seed no longer exists
  server-side; delete the entry. On the **next login** the IdP forces a
  fresh enrolment and shows the new base32 seed **once, at that moment**
  — capture it then (scan it AND note the base32 string if you need it
  for fixtures below), or re-enrol later at `/account/settings?tab=mfa`.
- **Recovery codes.** The printed codes from the old enrolment are dead;
  new ones are shown at the fresh enrolment, also once.
- **Local e2e fixtures.** `identuum-ui/.env.playwright.idp-oss.local`
  carries `IDENTUUM_TEST_SITE_ADMIN_PASSWORD` and
  `IDENTUUM_TEST_SITE_ADMIN_TOTP_SECRET` — both now wrong. Update them
  from the reset password and the once-shown seed, or every Playwright
  run that logs in as site_admin fails (or worse, trips the login
  lockout with repeated wrong attempts). The pointers back to this
  section live in `identuum-ui/e2e/README.md` and
  `identuum-ui/docs/LOCAL_ORG_ADMIN_PLAYWRIGHT_FIXTURE.md`.
- **Any password manager entry** for site_admin, obviously.

## An organization's administrator lost every factor (break-glass)

A site administrator does not reset a tenant user's authenticator (D-025),
so when an organization's org_admin has lost the authenticator, the
recovery codes and every passkey, the operator resets it from the host:

```
docker exec identuum-idp-oss /app/identuum-idp reset-org-admin-mfa --org <organization-id> --email <admin-email>
```

or, without a running appliance, a one-shot container from the same image
on the appliance's network (the image's entrypoint is the appliance, so
name the binary as the entrypoint):

```
docker run --rm --network identuum-idp-oss_default --entrypoint /app/identuum-idp <image> reset-org-admin-mfa --org <organization-id> --email <admin-email> <database-url>
```

The organization id is on the organization's page in the console. The
command removes the org_admin's authenticator, recovery codes and passkeys,
revokes its sessions and refresh tokens, clears the wrong codes counted
against the old factor (so the new one is not refused for them), and records
`org_admin_mfa_reset`
(actor `system`, `via: cli`). The password is unchanged: the administrator
signs in with it and enrolls a new factor. It refuses the system
organization (use `recover-site-admin`) and any user who is not exactly an
org_admin. The database URL comes from the argument, else
`IDENTUUM_IDP_DATABASE_URL`, else `IDENTUUM_IDP_OSS_DB`, and is never
printed.

## Rotate the at-rest encryption key

Offline, atomic, both directions proven — the full ceremony (backup,
stop, rotate, set the new key, start, verify with doctor) lives in
[guides/encryption-key-rotation.md](guides/encryption-key-rotation.md).
Doctor's `at-rest-seals` lines are the post-rotation verification.

## Rotate the token signing key

The IdP signs tokens with its **active** signing key and publishes every
active and rotating key in JWKS (`/.well-known/jwks.json`). Rotation is done
over the API by the site administrator (bearer token); the console's keys
page lists the keys but does not rotate them. Each step is audited
(`key.generated`, `key.rotated`, `key.deprecated`). No restart is needed: the
next token is signed with whatever key is active.

1. Find the active key:

   ```
   GET /api/v1/keys
   ```

   Note the `kid` whose `state` is `active`.

2. Create the new key. It is published in JWKS at once but does not sign yet
   (`state` `rotating`):

   ```
   POST /api/v1/keys/generate   {"algorithm": "EdDSA"}
   ```

   `algorithm` is `EdDSA` (preferred), `ES256` or `RS256` (`RS256` never
   becomes the default signer; see the README). The answer carries the new
   `kid`; the private key is never returned.

3. Wait until your relying parties have fetched JWKS again (at least their
   JWKS cache time), so they know the new key before it signs.

4. Switch signing to the new key:

   ```
   POST /api/v1/keys/rotate   {"old_kid": "<old kid>", "new_kid": "<new kid>"}
   ```

   The new key signs from the next token on. The old key stays published
   (`rotating`), so tokens it already signed keep verifying. `deprecate_days`
   (optional) only records when the old key may be removed; it does not
   unpublish it.

5. When every token the old key signed has expired (your longest access and
   ID token lifetime), retire it:

   ```
   POST /api/v1/keys/deprecate   {"kid": "<old kid>"}
   ```

   It leaves JWKS at once. `expires_at` (RFC 3339, optional, default 30 days
   from now) says when it may be deleted; `DELETE /api/v1/keys/expired`
   removes deprecated keys past that time.

## Create the first admin + signing key (bootstrap)

```
docker exec -e IDENTUUM_IDP_BOOTSTRAP_PASSWORD='<password>' identuum-idp-oss /app/identuum-idp bootstrap
```

Idempotent alternative to the browser setup wizard: ensures an active signing
key exists and creates the `site_admin` row, then marks setup complete. Like
the wizard, a bootstrap that creates the `site_admin` is audited
(`setup.completed` and `user_created`, actor `system`, metadata
`via: bootstrap`); a re-run that finds it records nothing.

## Reading the audit log

The console's **Audit** page (site admin: every organization; organization
admin: its own) reads `GET /api/v1/audit/events`, newest first, with the
filters event type, outcome, actor, subject and a date range. Each row says:

- **who** — `actor_type` (`user`, `service_account`, `client`, `setup_token`,
  `system`, or `anonymous` when no one was signed in, such as a failed
  sign-in), with the actor's email and role, or its id; a client's
  `client_id` is in `metadata.actor_client_id`;
- **which organization** — `organization_id`, the organization acted upon,
  and `actor_organization_id`, the actor's own. A site admin who changes
  organization A writes a row with A's `organization_id` and the system
  organization as its own.

An organization admin sees every row of its organization, whoever acted — a
site admin included — and no row of another. Rows written before `v0.8.0`
carry `organization_id` only where their metadata named the organization;
the others stay visible to the organization they were filed under. The OSS
log is plain and retention-pruned (30 days by default); it carries no hash
chain.

## Apply database migrations

```
docker exec identuum-idp-oss /app/identuum-idp migrate
```

One-shot; safe to re-run (already-applied migrations are skipped). The
appliance entrypoint migrates on boot, so in the image this is normally only
needed when operating against an externally-managed database. **The bare
binary does not migrate on start:** run `./identuum-idp migrate
"$IDENTUUM_IDP_DATABASE_URL"` before the first `./identuum-idp` and after every
upgrade.

## Hand a new organization admin their activation

Creating an organization with an `admin_email` issues a **one-time activation
credential** for that administrator. It is shown to you once, at creation
time, and again if you re-issue it — never afterwards.

In the console: **Organizations → New**, then name, domain and the initial
admin email. The success page shows the activation link (with the raw token
underneath). The new organization is **inactive** until its administrator
activates it, so it appears under **Deactivated**, not in the default list;
its admin state reads *Admin active* in the list (*Administrator account
active* on its page) while the activation is valid, and *Invitation expired* /
*Pending invitation expired* once it has lapsed. The administrator
opens the link, sets a password, enrols an authenticator app on the same
page, and then signs in at `/login` with their email.

A new organization's service-account expiry (`service_account_expiry_days`)
starts at `0`, no default expiry, unless the create request names a value.
It is the organization's own setting: its org_admin turns it on in
**Settings**, and a site administrator does not change it for a tenant.

**This works with or without email delivery.** Those are the two supported
modes, and they differ only in whether the IdP also sends the message for
you:

- **Email delivery configured** (`IDENTUUM_IDP_SMTP_HOST` and friends): the
  IdP emails the activation link to the administrator. You still see the
  credential in the response, so you can deliver it yourself if the mail does
  not arrive.
- **Email delivery not configured** — the default on a fresh install: nothing
  is sent. Delivering the activation is *your* job, and the response gives you
  what you need to do it.

### What you get back, and which part to send

The response carries the raw token **and** the link that consumes it:

```
activation_token   the raw one-time credential (not a URL)
activation_url     the link to send — opens the activation page with the
                   token already filled in
```

**Send the link.** The activation page reads the token from the link's query
string; it has no field to paste a bare token into, so the token on its own
cannot be redeemed by hand. The site-admin UI shows the link as the primary
action, with the raw token underneath for the rare case you need it.

### If there is no link

When the IdP does not know the browser-facing address of the UI, it cannot
build a link, and it says so instead of guessing one:

```
activation_url_unavailable   no activation link can be built because
                             IDENTUUM_IDP_UI_PUBLIC_BASE_URL is not set ...
```

Set `IDENTUUM_IDP_UI_PUBLIC_BASE_URL` to the UI's browser-facing base URL
(for example `http://localhost:7113`, the binary's own origin since `v0.6.0`;
`http://localhost:7104` before) and re-issue the activation. A link is never
fabricated from the IdP's issuer: a UI served from a separate origin would not
load such a link.

### Re-issuing

If the credential is lost or expired (24 hours), re-issue it — this
invalidates the previous one. In the console: **Organizations**, open the
organization, **Re-issue activation link**, confirm; the new link (with
Copy), its token and its expiry are shown once. Over the API:

```
POST /api/v1/organizations/<org-id>/resend-activation
```

The response has the same shape, link included.

An **active** organization has no activation to re-issue (that call answers
`409`). When its administrator was invited and has not accepted, re-issue the
administrator's **invite** instead: in the console, the organization's page
shows **Waiting for the administrator to accept the invite** with **Re-issue
invite**; over the API, `POST /api/v1/users/<admin-user-id>/invite` (see
"Invite a user", "Re-issuing").

## Hand over an organization with a claim link

An organization that is active but has **no administrator** (one created
without an admin email, or one whose administrators are gone) can be handed
over with a **claim link**: whoever opens it sets a password and becomes the
organization's administrator, enrolling an authenticator at their first
sign-in. Only a site administrator issues one, and only while the
organization is active with no active administrator; otherwise the answer is
`409 organization_not_claimable`. An administrator who was invited and has
not activated yet counts as one: such an organization cannot be claimed —
re-issue its activation instead (see "Re-issuing" above). In the console:
**Organizations**, open the organization, **Issue claim link** (shown only
while it is active with no administrator).

```
POST /api/v1/organizations/<org-id>/claim      {"email": "owner@example.com"}   (email optional)
201 {"claim_url": "...", "expires_at": "...", "email_bound": true}
```

- **The link is shown once**, in this response. It works once and expires
  after 48 hours; three refused attempts (a password the policy rejects or,
  for a bound link, another email) retire it.
- **Email modes.** With an email the link is bound: only that address can
  claim it, and it is also mailed when email delivery (SMTP) is configured —
  a failed mail does not fail the issue, you still have the link. Without an
  email any address can claim it, and you hand it over yourself.
- **No UI address, no link.** When `IDENTUUM_IDP_UI_PUBLIC_BASE_URL` is not
  set the IdP cannot build a link and issues nothing:
  `409 {"error":"claim_url_unavailable", "claim_url_unavailable": "..."}`.
- **Re-issuing retires the earlier link.** Issue again if a link is lost or
  expired; every earlier link of that organization stops working at once.
- **Audit.** `claim.generated` (who issued it, whether it was bound, how many
  earlier links it retired) and `claim.consumed` (the new administrator);
  no row or log line carries the token or the link.

**Claim link or Assign administrator?** *Assign administrator* creates the
administrator's account under the email you type and sends them an
activation (or invite) for that account. A claim link creates nothing until it
is redeemed, and the person who redeems it chooses the email (unless you bound
one) — use it to hand an organization to someone whose address you do not
manage, or to hand it over in person.

## Self-registration

Strangers can sign up for an organization only when **two switches** are on;
both are **off** by default (D-021).

1. **The instance switch** (site admin) is the ceiling. While it is off no
   organization accepts sign-ups, whatever its own setting:
   ```
   PUT /api/v1/settings/self-registration   {"enabled": true}
   ```
   In the console: **Settings → Self-registration**, *Turn on*.
2. **The organization's policy** (its organization admin; a site admin cannot
   set a tenant's policy):
   ```
   PUT /api/v1/organizations/<org-id>/registration
   {"allow_public_registration": true, "require_registration_approval": false,
    "verify_email": false, "email_domains": ["example.com"]}
   ```
   Opening an organization while the instance switch is off answers `409
   instance_registration_disabled`. `verify_email: true` needs working email
   delivery (SMTP); without it the answer is `400 smtp_not_configured`.
   `email_domains`, when not empty, accepts only those domains.
   In the console: the organization admin's **Organization settings →
   Self-registration**. It is read-only, with a note, while the instance
   switch is off, and its email-verification switch is disabled where email
   delivery is not configured. Once open it shows the organization's sign-up
   link, `<console>/register/<org-slug>`, with *Copy*.

The console's sign-up page is `/register/<org-slug>`: a closed and an
unknown organization both read "Sign-up is not available", and every
accepted sign-up reads the same message for that organization's settings.
The sign-up endpoint is per organization, by its slug:
`GET /api/v1/auth/register/<org-slug>` says whether it is open (and the
password policy); `POST` the same path `{email, name, password}` signs up.

- **It discloses nothing.** A closed, unknown or `idp_only` organization, an
  address that already has an account and a refused domain all get the same
  `202 {"accepted": true}`; only a password the open organization's policy
  refuses answers `400 weak_password`. When an existing address is tried and
  SMTP is set, its owner gets a short notice by mail.
- **What is created:** always an `org_user`, never an admin. The account
  enrols an authenticator at its first sign-in when the organization's MFA
  policy requires one.
- **Email verification.** With `verify_email` on, the verification link is
  mailed and the account signs in only after it is used (resend:
  `POST /api/v1/auth/resend-verification`). With it off, the account signs
  in at once with `email_verified=false`. Accounts that were not
  self-registered keep the sign-in rule they always had.
- **Approval.** With `require_registration_approval` on, a new account
  cannot sign in (`403 registration_pending`) until its organization admin
  approves it: `GET /api/v1/organizations/<org-id>/registrations` lists them,
  `POST /api/v1/users/<id>/approve` lets one in, `POST /api/v1/users/<id>/reject`
  deletes it. In the console they are listed on the organization admin's
  **Users** page under "Sign-ups waiting for approval", with *Approve* and
  *Reject* (which asks first).
- **Limits and audit.** Sign-ups are rate-limited per client IP (an IPv6
  client by its /64) and per organization (`IDENTUUM_IDP_RATE_LIMIT_REGISTER_*`,
  default 10 per hour). Switch changes, sign-ups, refusals, approvals and
  rejections are audited.

## Invite a user

An organization admin can add a user **without choosing their password**: the
IdP creates the user *pending* and issues a **one-time invite link**. The user
opens it, sets their own password under the organization's policy, and is then
verified and active; at their first sign-in they enrol MFA if the
organization's policy asks for it. The link is shown to you once, at invite
time, and again if you re-issue it — never afterwards.

The same two modes apply as for an organization's activation:

- **Email delivery configured** (`IDENTUUM_IDP_SMTP_HOST` and friends): the
  IdP also emails the link to the user. You still get it in the response, so
  you can deliver it yourself if the mail does not arrive.
- **Email delivery not configured** — the default on a fresh install: nothing
  is sent. Hand the link to the user yourself, over a channel you trust.

### Inviting

In the console: **Users → Invite user**, then email, name and role (Member or
Admin). The link, its raw token and its expiry are shown once, with a Copy
button. A pending user reads **Invitation pending**, and their page offers
**Re-issue invitation**.

Over the API, create the user with an email (and optionally a name and role)
and **no password**, as an org_admin of the organization:

```
POST /api/v1/users   {"email": "…", "name": "…"}
```

The answer carries the user and the invite:

```
user                     the pending user (invitation_pending: true)
invite_token             the raw one-time credential (not a URL)
invite_url               the link to send — opens the invite page with the
                         token already filled in
expires_at               when the link stops working (24 hours)
```

**Send the link**, as with an activation. When the IdP does not know the UI's
browser-facing address it answers `invite_url_unavailable`, naming
`IDENTUUM_IDP_UI_PUBLIC_BASE_URL`, instead of a guessed link; set it and
re-issue.

### Creating a user with a password instead (API)

The invite is the console's way. Over the API an administrator may instead
set the first password (owner ruling D-017):

```
POST /api/v1/users   {"email": "…", "password": "…", "role": "org_user"}
```

The user is **active and verified at once** — the administrator vouches for
the account, and the creation is audited (`user.created` with
`password_set_by_admin: true`). No mail is sent. By default the user **must
change the password at first sign-in**: the password you set gets them only
to a "choose a new password" step (console and OpenID Connect sign-in
alike), then MFA enrolment when the organization's policy requires it, and
only then a session. The new password follows the organization's policy and
must differ from the one you set. Send `"must_change_password": false` to let
your password stand; that choice is audited too
(`must_change_password: false`).

### Re-issuing

If the link is lost or expired, re-issue it for the pending user — the
previous link stops working:

```
POST /api/v1/users/<user-id>/invite
```

The answer has the email, a new `invite_token`, `invite_url` (or
`invite_url_unavailable`) and `expires_at`. A verified user (one who has
redeemed, or was created with a password under D-017) is not pending:
`409 user_not_pending`.

A user created with a password in `v0.7.0` or earlier is still unverified
and cannot sign in without mail. The same call invites them (**Send
invitation** on the user's page in the console); accepting sets a new
password and verifies the account.

### What the user does

The invite page (identuum-ui `/invite`) checks the link with
`GET /api/v1/auth/invite/<token>` and submits the new password to
`POST /api/v1/auth/invite {token, password}`. A password that does not meet
the policy is refused and the link stays usable; an unknown, expired or
already-used link gets one answer (`invalid_token`). Both calls are
rate-limited like sign-in. The token is stored only as a hash, works once, and
never appears in a log line or an audit row (`user.invited`,
`user.invite_reissued`, `user.invite_redeemed`).

## A user forgot their password and email is not configured

Without email delivery, "Forgot password" sends nothing, and the sign-in page
tells the user to ask their administrator. The organization's administrator
sets a new password over the API (the console has no button for it yet), as
an org_admin of the user's organization:

```
PUT /api/v1/users/{user_id}   {"password": "…"}
```

- The password follows the organization's policy; a refusal answers
  `400 weak_password` with the rule it broke.
- The user is signed out everywhere: their sessions and refresh tokens are
  revoked before the password changes.
- The password you set is the user's password until they change it (Account
  settings → Password). Hand it over on a channel you trust.

The site administrator's own password has its own break-glass command (see
"Reset the site_admin password" above).

## Service accounts with a credential

**Service accounts → Create** in the console registers the identity only: no
credential is issued. The role is `org_user` unless you choose another. When
you set no expiry date, the account expires the organization's
`service_account_expiry_days` after it is created. A new organization starts
at `0` (unless its create request names a value), and `0` means new accounts
do not expire unless you set a date; the organization's org_admin turns it on
in **Settings** (1 to 3650 days). A date you set is kept. The value applies only to accounts created after
it is set: changing it never changes an existing account. Both creation routes,
this one and the one below, apply it, and an expired account cannot get a
`client_credentials` token.

A service account that signs in with `client_credentials` is created together
with its OAuth client in one call, by an org_admin of the organization:

```
POST /api/v1/organizations/{org_id}/service-accounts/with-client
```

```json
{
  "service_account": {"name": "reports-bot", "description": "nightly reports", "role": "org_user"},
  "client": {"name": "reports-bot", "scope": "<scopes>", "allowed_audiences": ["<audience>"]}
}
```

The answer is `201` with `service_account`, `client` (its `client_id`) and
`client_secret`, which is shown **once**. The client's scope is capped at the
scopes you hold. The service account then gets tokens from the token endpoint
(`/api/v1/oauth/token`) with `grant_type=client_credentials` and its
`client_id` and `client_secret` (HTTP Basic or the form body); the tokens
carry `actor_type` `service_account`. An application registered for
`client_credentials` without a service account is refused with
`unauthorized_client`.

## Console and application sign-ins are separate

Signing in to the console (`/login`) never signs a user in to an
application. An application's `/authorize` asks for its own sign-in at
`/api/v1/auth/browser-login`, even right after a console sign-in, and
RP-initiated logout (`end_session`) ends that OpenID Connect sign-in, not the
console's. Signing out of the console does not sign anyone out of an
application either. This is deliberate (owner ruling D-023): an administration
console is not a single sign-on session for applications, so a console session
can never grant application access silently.

## Register an application (OpenID Connect)

An organization admin registers a client in the console: **Applications →
New** — name, redirect URIs (one per line), optional post-logout redirect URIs
and audiences, and the default scope (for example
`openid profile email offline_access`). Clients are confidential unless you
tick **Public client**; the **client secret is shown once**, on the creation
page. The client's endpoints are in the discovery document:

```
GET /.well-known/openid-configuration
  authorization_endpoint   /api/v1/oauth/authorize
  token_endpoint           /api/v1/oauth/token
  userinfo_endpoint        /api/v1/oidc/userinfo
  end_session_endpoint     /api/v1/oidc/logout
```

- **Authorization code with PKCE** (`S256`). The token endpoint accepts
  `client_secret_basic`, `client_secret_post` and `private_key_jwt`, and
  `none` for a public client.
- **Public client** (single-page or mobile app, no secret): `/authorize`
  requires a `code_challenge` (S256), and the code exchange sends `client_id`
  and `code_verifier` with no secret. That exchange is the only token request
  a public client can make: it gets an access token and an ID token, but no
  refresh token (the refresh grant needs client authentication), so it signs
  in again through `/authorize` when the access token expires.
- **Sign-in happens on the IdP's own page.** `/authorize` signs the user in
  at `/api/v1/auth/browser-login` (email, password, and a TOTP code if they
  enrolled one); being signed in to the console does not carry over. The first
  authorization of a client shows a consent page (**Approve** / **Deny**); the
  decision is remembered. An organization admin may mark an application the
  organization runs itself **First-party (skip consent)** (D-018, D-026): its
  users are not asked for sign-in itself (`openid`, `profile`, `email`); a
  request for more, such as `offline_access` or an API resource, still shows
  the consent page, and so does `prompt=consent`. Only a confidential
  application created in the console can be first-party (not a public client,
  not one created through dynamic client registration). Turning it on asks for
  your current authenticator code, and the change is audited with who made it.
- **First sign-in under an MFA policy:** a user who must change an admin-set
  password (D-017) and has no authenticator enrols one on the same sign-in
  page — the key and its `otpauth://` link, the recovery codes once, then a
  code.
- **Refresh:** request `offline_access` to receive a refresh token;
  `grant_type=refresh_token` returns a new access token and a new refresh
  token (the old one is rotated out).
- **Sign-out:** `GET /api/v1/oidc/logout?id_token_hint=…` ends the IdP's
  browser session (the next `/authorize` asks for a sign-in again). With a
  registered `post_logout_redirect_uri` the browser returns there; without one
  the IdP shows its own "You are signed out" page (D-018). A request that
  carries no verified `id_token_hint` while the browser holds a session first
  shows a "Sign out?" page, and the session ends when the person follows its
  link (any page can fire a GET at this endpoint, so it asks). Access tokens
  already issued stay valid until they expire, and the console has its own
  session: **Sign out** there separately.

## Factory reset (DESTROYS ALL DATA)

```
docker exec identuum-idp-oss /app/identuum-idp factory-reset --i-understand-this-destroys-all-data
```

Destroys **every** organization, user, client, session, audit row, and
signing key, then re-applies migrations, returning the database to the
fresh-install `setup_required` state. Refused — with no database contact —
unless the exact `--i-understand-this-destroys-all-data` flag is passed.
Afterwards restart the appliance to begin setup again:

```
docker restart identuum-idp-oss
```

The data volume (at-rest encryption key) is kept, so the reset appliance
comes back up serving with the same key.

## Show the running version

```
docker exec identuum-idp-oss /app/identuum-idp version
```

Prints the version and the commit the image was built from, for example
`identuum-idp-oss 0.7.0 (commit 1a2b3c4d5e6f)`.
