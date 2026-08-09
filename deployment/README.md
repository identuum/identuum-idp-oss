# deployment/

Three Compose files live here. They serve different audiences.

| File | Audience | Purpose |
|------|----------|---------|
| [`docker-compose.yml`](docker-compose.yml) | **Customer / community** | Single-node self-hosted install: `postgres` + `identuum-idp` + `identuum-ui`. Image-only — pulls `ghcr.io/identuum/identuum-idp-oss` and `ghcr.io/identuum/identuum-ui` from the official registry. The canonical OSS appliance flow. |
| [`docker-compose.build.yml`](docker-compose.build.yml) | **Maintainer / developer** | Overlay that restores `build:` contexts so a sibling-tree checkout can rebuild the images from source. Layered on top of `docker-compose.yml`; never downloaded by a customer. |
| [`docker-compose.dev.yml`](docker-compose.dev.yml) | **Maintainer / developer** | Local Postgres-only stack used by `make fast-up` / `make integration-test`, plus the `app` profile used by `make oss-up`. Not the customer install path. |

## Customer-facing single-node install

```bash
curl -fsSLO https://downloads.identuum.com/idp-oss/docker-compose.yml
docker compose up -d
open http://localhost:7104
```

`docker compose up -d` pulls the published images from
`ghcr.io/identuum/identuum-idp-oss` and `ghcr.io/identuum/identuum-ui`.
The customer download is exactly one file — no sibling source checkout
is needed, and the customer never compiles anything locally.

The UI detects the first-run state and redirects to `/setup`. The
wizard prompts for the setup code, then for the initial organization
and site administrator. The setup code is printed to the IDP boot log
on every restart while setup is still required, along with the
in-container support command:

```bash
docker compose exec identuum-idp \
    identuum-idp show-setup-code /app/data
```

The setup code authorises the wizard only. It is not the
administrator password — that is created during the wizard.

### What ships in this slice

- Image-only customer-facing Compose file with three services:
  - `postgres` on the internal Compose network (no published host
    port, single-node default credentials)
  - `identuum-idp` on `localhost:7113`, named data volume at
    `/app/data` for the appliance setup foundation, image pulled from
    `ghcr.io/identuum/identuum-idp-oss` at the current release tag
  - `identuum-ui` on `localhost:7104`, runtime config baked into the
    Compose file via the top-level `configs:` block so the customer
    download remains exactly one file, image pulled from
    `ghcr.io/identuum/identuum-ui` at the current release tag
- No `.env.example`, no `openssl`, no `Makefile`, no manual database
  URL, no manual issuer URL, no manual signing-key generation, no
  manual bootstrap, no source checkout

### What is intentionally out of scope

Each of these is its own follow-up slice tracked under
`wiki/platform/idp-appliance-install-ux.md`:

- Generated-on-first-boot DB credentials (current default is a
  fixed-string Compose-internal password; Postgres is not exposed on
  the host)
- HA / external / customer-managed Postgres
- Reverse proxy with TLS in front of the published surfaces
- Backup automation (`pg_dump`, snapshot, retention)
- OSS-to-CE upgrade overlay

### Image availability

The customer command flow above becomes literal once the current
release tags of `ghcr.io/identuum/identuum-idp-oss` and
`ghcr.io/identuum/identuum-ui` are published. The manual
`workflow_dispatch` publish workflows live at:

- `identuum-idp-oss/.github/workflows/publish-image.yml`
- `identuum-ui/.github/workflows/publish-image.yml`

Each accepts a `version_tag` input plus an opt-in `latest_tag` toggle;
neither pushes `latest` automatically. The workflows are intentionally
manual so a release is always an explicit maintainer act.

## Maintainer / developer source build

When you want to rebuild the images from a local sibling-tree
checkout (i.e. you have both `identuum-idp-oss/` and `identuum-ui/`
checked out side-by-side), layer the build overlay on top of the
customer-facing file:

```bash
docker compose \
    -f deployment/docker-compose.yml \
    -f deployment/docker-compose.build.yml \
    up -d --build
```

The overlay adds `build:` contexts pointing at `..` (this repo) and
`../../identuum-ui` (the sibling UI repo). The base file's `image:`
tags are preserved, so a subsequent `docker compose up -d` (without
the overlay or without `--build`) will pull from the registry.

This overlay is **maintainer convenience only** and is not part of any
customer-facing instruction set.

## Developer compose stack

The Postgres-only and `oss-up` dev stack is documented in the repo
root [`Makefile`](../Makefile) (`make dev-reset`, `make fast-up`) and
[`MANUAL-TEST.md`](../MANUAL-TEST.md). None of the
customer-facing install assumes the dev stack is running, and the
customer-facing stack does not collide with dev container names,
volume names, or networks.
