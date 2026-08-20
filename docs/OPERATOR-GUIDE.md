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
