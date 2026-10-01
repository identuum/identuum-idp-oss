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
later sign-in asks for a code. The address you typed in the wizard is the
site administrator's contact email, not the login.

## Check health

```
docker inspect --format '{{.State.Health.Status}}' identuum-idp-oss
```

The image's healthcheck (`/app/identuum-idp healthcheck`) passes only when
`GET /healthz` (liveness: the process serves) and `GET /readyz` (the database
answers a ping) both answer 200. With PostgreSQL down the container turns
`unhealthy` within about a minute while `/healthz` stays 200; it turns
`healthy` again once the database is back.

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
  honoured; unset, none is.
- **Over IPv6 nothing degrades.** The audit log and sessions record the IPv6
  address. Rate limits and the sign-in lockout count an IPv6 client by its
  `/64`, so rotating addresses inside one `/64` does not escape a limit; an
  IPv4 client counts by its address, as before.

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

## Rotate the at-rest encryption key

Offline, atomic, both directions proven — the full ceremony (backup,
stop, rotate, set the new key, start, verify with doctor) lives in
[guides/encryption-key-rotation.md](guides/encryption-key-rotation.md).
Doctor's `at-rest-seals` lines are the post-rotation verification.

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
  `client_secret_basic`, `client_secret_post` and `private_key_jwt`.
- **Sign-in happens on the IdP's own page.** `/authorize` signs the user in
  at `/api/v1/auth/browser-login` (email, password, and a TOTP code if they
  enrolled one); being signed in to the console does not carry over. The first
  authorization of a client shows a consent page (**Approve** / **Deny**); the
  decision is remembered. An organization admin may mark an application the
  organization runs itself **First-party (skip consent)** (D-018): its users
  are not asked, the change is audited, and `prompt=consent` still asks. A
  public client cannot be first-party.
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
  the IdP shows its own "You are signed out" page (D-018). Access tokens
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
