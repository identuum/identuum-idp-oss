# Getting Started with identuum-idp-oss

This guide will help you get from a clean clone to a locally running instance of the Identuum Identity Provider OSS (Starter tier).

## Prerequisites

Before starting, ensure you have:

- Go 1.26 or higher installed
- Docker and Docker Compose plugin installed
- `staticcheck` installed (`go install honnef.co/go/tools/cmd/staticcheck@latest`)
- Git installed

## Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/identuum/identuum-idp-oss.git
cd identuum-idp-oss
```

### 2. Build and Test

Run basic validation:

```bash
make validate
```

This command will:
- Clean any existing database state
- Start a local PostgreSQL container
- Run all unit tests
- Run integration tests against the local database
- Stop the PostgreSQL container

## Local Configuration

The project uses environment variables for configuration. A sample configuration file is provided:

```bash
cp dev.env.example dev.env.local
```

Edit `dev.env.local` to adjust settings if needed, although the defaults are suitable for local development.

> **Single-replica by design.** identuum-idp-oss runs as **exactly one
> replica**. Its rate limiting, WebAuthn ceremony state, and browser
> CSRF secret are per-process and would be silently broken across
> replicas, so a DB-backed instance lease lets only one live instance
> serve — a second instance refuses to serve (`503`, with the fault on
> `GET /health`) instead. Rolling deploys still work: the outgoing
> instance releases the lease (or its heartbeat lapses after the TTL)
> and the incoming instance takes over. Horizontal scaling / HA is a
> Professional+ commercial capability; set
> `IDENTUUM_IDP_ALLOW_MULTI_REPLICA=true` to knowingly run multi-replica
> (a loud startup WARNING states what degrades). See the README's
> "Single-replica by design" section for details.

## Database Setup

### PostgreSQL Requirements

The identuum-idp-oss requires a PostgreSQL database with version 18 or higher (due to migration 0001 requiring PG18+ built-in uuidv7() function).

### Local Development Environment

For local development, the project uses Docker Compose to run PostgreSQL:

```bash
make fast-up
```

This will start a PostgreSQL container running on port 5513.

To stop and remove containers (volume preserved):

```bash
make fast-down
```

To perform a full clean reset (stop containers AND remove the named volume):

```bash
make fast-clean
```

## Migrations

Database migrations are embedded in the binary and applied by the `identuum-idp migrate <url>` one-shot subcommand (the container entrypoint runs it automatically before serving; the integration test harness applies them too). The project includes 23 migration files (`migrations/0001`–`0023`) that create the necessary database schema.

## Starting the Service Locally

### Option 1: Using Docker Compose (Recommended for local demo)

```bash
make oss-up
```

This will:
- Build the OSS application image
- Start PostgreSQL and the OSS application container
- The service will be available at `http://localhost:7113`

To stop:

```bash
make oss-down
```

### Option 2: Direct Binary Execution

Build the binary:

```bash
go build -o identuum-idp ./cmd/identuum-idp
```

Apply migrations (one-shot `migrate` subcommand — takes the Postgres URL as a
positional argument; the URL is never printed):

```bash
./identuum-idp migrate "postgres://idp_oss_user:dev-idp_oss_user-not-a-secret@127.0.0.1:5513/identuum_idp_oss?sslmode=disable"
```

Start the service. The default action (no subcommand) serves the full OSS IdP;
configuration comes from flags or the environment. Serving REQUIRES the at-rest
encryption key (`IDENTUUM_IDP_ENCRYPTION_KEY`, or its `AUTH_SERVICE_ENCRYPTION_KEY`
fallback) — without it the process comes up NOT-SERVING (503 on every route) by
design. The `0000…0001` value below is a well-known PUBLIC dev key — local dev
only; production supplies its own via the environment:

```bash
IDENTUUM_IDP_ENCRYPTION_KEY=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f \
  ./identuum-idp \
    --database-url "postgres://idp_oss_user:dev-idp_oss_user-not-a-secret@127.0.0.1:5513/identuum_idp_oss?sslmode=disable" \
    --issuer "http://localhost:7113" \
    --listen 127.0.0.1:7113
```

Equivalently, every flag has an environment default, so you can export
`IDENTUUM_IDP_DATABASE_URL`, `IDENTUUM_IDP_ISSUER`, and `IDENTUUM_IDP_LISTEN`
(see `dev.env.example`) and run `./identuum-idp` with no flags. Run
`./identuum-idp help` for the full surface.

## Initial Admin and Recovery Flow

After starting the service, you need to bootstrap it with an admin user.

### Bootstrap Process

```bash
IDENTUUM_IDP_BOOTSTRAP_PASSWORD='<choose-a-strong-local-demo-password>' \
make oss-bootstrap
```

This creates a site_admin user with:
- Email: site_admin@system.local
- Role: SiteAdmin
- The provided password is used to set the admin password

### Recovery Process

If you lose access to the bootstrap password, you can reset it:

```bash
IDENTUUM_IDP_RECOVER_SITE_ADMIN_PASSWORD='<choose-new-local-demo-password>' \
make oss-recover-site-admin
```

## Health Check and Basic Verification

Once the service is running, verify it's operational:

```bash
curl -s http://localhost:7113/system/info
curl -i http://localhost:7113/api/v1/organizations
curl -i http://localhost:7113/api/v1/organizations/00000000-0000-7000-0000-000000000000/protocol-settings
```

Confirm the health endpoint reports healthy:

```bash
curl -s http://localhost:7113/health
# → {"status":"healthy", ...}
```

## API Documentation

The identuum-idp-oss has a canonical 130 endpoints (pinned in-process by `tools/api-docgen/canonical_count_test.go` — see `AGENTS.md` for the full count history). Run the documentation generator:

```bash
make api-docgen-dry-run
```

This generates an API documentation file showing all available endpoints and their properties.

## Security Reporting

If you discover any security vulnerabilities in this software, please contact the Identuum security team at:
- **Security Contact**: contact@identuum.ai

## Troubleshooting

### Common First-run Problems

1. **Port 7113 already in use**: If a previous container or process is using port 7113, stop it before running `make oss-up`.

2. **Database connection issues**: Ensure PostgreSQL is running via `make fast-up` and check `dev.env.local` for correct database credentials.

3. **Missing dependencies**: Install required tools with: `go install honnef.co/go/tools/cmd/staticcheck@latest`

4. **Container startup issues**: If `make oss-up` fails, manually run `make fast-up` first to verify the PostgreSQL container starts correctly.

### Verification Commands

After setting up your environment, verify everything is working:

```bash
# Verify database setup
make fast-up
make integration-test
make fast-down

# Test that all validation checks pass
go build ./...
go test ./... -count=1
staticcheck ./...
govulncheck ./...
```
