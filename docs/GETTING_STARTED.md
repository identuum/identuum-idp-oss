# Building and running from source

This guide is for developers working from a source checkout. To install the
published product, use the [README's self-hosted install](../README.md#self-hosted-install-single-node).
For backups, upgrades and recovery, use the [operator guide](OPERATOR-GUIDE.md).

## Prerequisites

- Git and Go at the version specified by [go.mod](../go.mod).
- PostgreSQL 18 or newer; the initial migration uses its built-in `uuidv7()`.
- Docker and the Compose plugin for the optional local development stack and
  full `make validate` check; the Docker engine must be running for these.
- PostgreSQL client tools (`psql`, `createdb`) for database-backed tests.
- `staticcheck` at the version and build used by CI. The current Homebrew
  build includes the Go export-data compatibility patches used by CI's
  `go-toolchain` action; the upstream `go install ...@latest` build does not.
  `make toolchain-parity` checks the installed tools against the CI pins.

## First build and source checks

For a first build, leave `IDENTUUM_IDP_TEST_DATABASE_URL` unset. Some
untagged database-backed tests skip when that variable is unset; setting it
opts those tests into using a database.

```bash
git clone https://github.com/identuum/identuum-idp-oss.git
cd identuum-idp-oss
make build
make test
make staticcheck
go build -o identuum-idp ./cmd/identuum-idp
```

- `make build` compiles all packages with `go build ./...`.
- `make test` runs the untagged tests with `go test ./... -count=1`; it does
  not start or stop Docker. Database-backed tests can run when configured as
  described above; build-tagged integration tests are excluded.
- `make staticcheck` analyzes both untagged and integration-tagged code. It
  does not execute the integration tests.

The final `go build` command writes the runnable `identuum-idp` binary.

The binary embeds the console export already committed to this repository.
A separate frontend checkout is not required to build it. Run
`./identuum-idp help` for the commands and flags.

### Full validation with a disposable Docker database

`make validate` is the full build, test and static-analysis check, including
the database-backed integration tests. It requires Docker with the Compose
plugin, a running Docker engine and the PostgreSQL client tools. **It resets
the selected development stack's database volume before running. Do not use
it with development data you need to keep.**

With the default settings, it performs these steps after the source checks:

1. Compile the integration-tagged packages with `go build -tags integration ./...`.
2. Run `fast-clean`: Compose `down --volumes` with the app profile stops and
   removes the `identuum-idp-oss-dev` app (if present), the
   `identuum-idp-oss-dev-postgres` container and the
   `identuum-idp-oss-dev_default` network. It deletes the named volume
   `identuum-idp-oss-dev_postgres-idp-oss-data-v18`, including its database data.
3. Run `fast-up`: reuse a compatible PostgreSQL already answering on
   `127.0.0.1:5513`, or start PostgreSQL 18 in the development Compose stack.
   Starting the stack creates its PostgreSQL container, network and volume;
   the app profile is not enabled for this step. An incompatible server on
   the port is refused rather than stopped.
4. Run `integration-test`: create `identuum_idp_oss_test` if absent, apply its
   migrations, build `bin/identuum-idp`, run the integration-tagged tests
   across all packages serially, and run the integration Rulefloor checks.
   The tests truncate test data and replay setup.
5. Run `fast-down`: Compose `down` with the app profile stops and removes the
   selected development containers and network. It preserves the newly
   created database volume. An earlier failed step prevents this final step;
   teardown is not guaranteed on failure.

These names come from `deployment/docker-compose.dev.yml` and its default
project `identuum-idp-oss-dev`. `IDENTUUM_IDP_COMPOSE_PROJECT` changes the
project-scoped names; `COMPOSE_FILE` selects the Compose file. The
`protected-guard` prerequisite refuses the protected names `identuum-idp-oss`
and `identuum-idp-oss-postgres`, or the published `deployment/docker-compose.yml`.
It does not protect data in the selected development volume from `fast-clean`.

`DEV_PG_HOST_PORT` changes the Compose port and `fast-up` probe, but `test-db`
still creates its database on port **5513**. Keep that default for this chain.
`IDENTUUM_IDP_TEST_DATABASE_URL` can direct the tests to another database;
`test-db` still creates and migrates the default test database. A reused server
can therefore have test data changed even though it was not started by this
command. Use only disposable test data.

## Run the local development stack

The development Compose file builds the application from this checkout:

```bash
IDENTUUM_IDP_UI_PUBLIC_BASE_URL=http://localhost:7113 make oss-up
```

This starts the development application on `http://localhost:7113` and
PostgreSQL on loopback port 5513. If either port is occupied, use
`DEV_APP_PORT` and `DEV_PG_HOST_PORT` with free ports and set
`IDENTUUM_IDP_UI_PUBLIC_BASE_URL` to the application's browser-facing URL.
Use the same values on subsequent Make commands. Keep the default development
project name; do not point these targets at an existing product installation.

The two Compose files have different database settings:

| Configuration | Database | PostgreSQL user | Network |
| --- | --- | --- | --- |
| Product: `deployment/docker-compose.yml` | `identuum_idp` | `identuum_idp` | Internal Compose network; no published database port |
| Development: `deployment/docker-compose.dev.yml` | `identuum_idp_oss` | `idp_oss_user` | Loopback port 5513 by default |

Use the settings of the file you actually run. The development app uses a
fixed public test encryption key by default. It is suitable only for
disposable development data; never use it for a product installation.

Open the application URL after `/health` answers successfully. A fresh
database takes you to `/setup`. Use the setup code shown by the application
to complete the wizard and create the site administrator. The wizard is the
product bootstrap path; `bootstrap` is a separate one-shot operator command.
See [first sign-in](OPERATOR-GUIDE.md#sign-in-the-first-time) for MFA enrolment.

```bash
curl -fsS http://localhost:7113/health
```

`/health` reports `healthy`, `degraded` or `not_serving`; see
[Check health](OPERATOR-GUIDE.md#check-health) for its fields and the separate
database readiness check. To stop only the development app while keeping its
database and volume:

```bash
make oss-down
```

## Run the binary against your own development database

Configure `IDENTUUM_IDP_DATABASE_URL`, `IDENTUUM_IDP_ISSUER`,
`IDENTUUM_IDP_LISTEN`, `IDENTUUM_IDP_UI_PUBLIC_BASE_URL` and
`IDENTUUM_IDP_DATA_DIR` for your development installation. Database URLs
contain credentials: keep them out of logs and command transcripts. Supply
`IDENTUUM_IDP_ENCRYPTION_KEY` through your local secret configuration. The
binary still accepts `AUTH_SERVICE_ENCRYPTION_KEY` for compatibility, but new
configurations should use the Identuum name. Keep the same key between runs;
existing encrypted MFA and signing-key records depend on it.

Apply the embedded migrations using `./identuum-idp migrate <database-url>`
before starting `./identuum-idp` with those settings. The migrations are in
[`migrations/`](../migrations/); do not infer schema compatibility from a
documentation count. The default action serves the application. A missing or
invalid encryption key leaves the process alive but not serving, with a fault
on `/health`. A fresh database then uses the same setup wizard as the product
install. Recovery is described in
[Reset the site_admin password](OPERATOR-GUIDE.md#reset-the-site_admin-password-break-glass).

## Database-backed integration tests

Use a dedicated disposable test database. The Make targets create and migrate
`identuum_idp_oss_test`; the suite refuses database names without the `_test`
suffix and truncates test data. Never use an installation's real database.

```bash
make fast-up
make integration-test
```

`fast-up` starts or reuses a compatible local PostgreSQL. Do not stop a reused
server that belongs to another installation. If you started a separate
development stack solely for this work, `make fast-down` stops that stack
while preserving its volume. `make validate` runs this integration sequence
too, with a destructive `fast-clean` before it and `fast-down` after a
successful run, as described above.

The full maintainer close gate is `make verify`. It includes additional
repository policies and requires the maintainer environment; it is not a
fresh-clone prerequisite. See the [maintainer documentation](maintainers/README.md).

## API documentation

[`openapi.yaml`](../openapi.yaml) describes the shipped API. To inspect the
annotation-derived endpoint inventory without updating it:

```bash
make api-docgen-dry-run
```

Use the generator output for the current endpoint inventory instead of a
count copied into this guide.

## Security reporting

Report vulnerabilities privately to **contact@identuum.ai**, following
[SECURITY.md](../SECURITY.md).
