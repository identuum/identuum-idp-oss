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
key exists and creates the `site_admin` row, then marks setup complete.

## Apply database migrations

```
docker exec identuum-idp-oss /app/identuum-idp migrate
```

One-shot; safe to re-run (already-applied migrations are skipped). The
appliance entrypoint migrates on boot, so this is normally only needed when
operating against an externally-managed database.

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
