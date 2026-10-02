# deployment/

Three Compose files live here. They serve different audiences.

| File | Audience | Purpose |
|------|----------|---------|
| [`docker-compose.yml`](docker-compose.yml) | **Customer / community** | Single-node self-hosted install: `postgres` + `identuum-idp`, which serves the API and the embedded `identuum-ui` export on one origin (`:7113`, since `v0.6.0`). Image-only — pulls `ghcr.io/identuum/identuum-idp-oss` from the official registry. The canonical OSS appliance flow. |
| [`docker-compose.build.yml`](docker-compose.build.yml) | **Maintainer / developer** | Overlay that restores the `build:` context so a checkout can rebuild the image from source. Layered on top of `docker-compose.yml`; never downloaded by a customer. |
| [`docker-compose.dev.yml`](docker-compose.dev.yml) | **Maintainer / developer** | Local Postgres-only stack used by `make fast-up` / `make integration-test`, plus the `app` profile used by `make oss-up`. Not the customer install path. |

## Customer-facing single-node install

```bash
curl -fsSLO https://github.com/identuum/identuum-idp-oss/releases/latest/download/docker-compose.yml
docker compose up -d
open http://localhost:7113
```

The file is the `docker-compose.yml` asset of the latest GitHub Release
(checksum: its `docker-compose.yml.sha256` asset). `docker compose up -d`
pulls the published image from `ghcr.io/identuum/identuum-idp-oss`.
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

- Image-only customer-facing Compose file with two services:
  - `postgres` on the internal Compose network (no published host
    port, single-node default credentials)
  - `identuum-idp` on `localhost:7113`, serving the API and the
    operator UI on one origin, named data volume at `/app/data` for the
    appliance setup foundation, a Docker healthcheck through
    `identuum-idp healthcheck`, image pulled from
    `ghcr.io/identuum/identuum-idp-oss` at the current release tag
- Until `v0.6.0` the UI was a third service, `identuum-ui` on
  `localhost:7104`. An install still on `v0.5.x` merges it once, as
  [`../docs/releases/v0.6.0.md`](../docs/releases/v0.6.0.md), "Upgrading
  from v0.5.x", describes; for any later upgrade, read the "Upgrading"
  section of the release you are installing, in `../docs/releases/`
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

The customer command flow above pulls the current release tag of
`ghcr.io/identuum/identuum-idp-oss`, pinned by digest in the compose
file. The manual `workflow_dispatch` publish workflow lives at
`identuum-idp-oss/.github/workflows/publish-image.yml`. It accepts a `version_tag` input plus an opt-in `latest_tag` toggle;
it never pushes `latest` automatically. The workflow is intentionally
manual so a release is always an explicit maintainer act.

### Releasing: the compose asset

Every release carries its pinned compose file as a GitHub Release asset;
the install line downloads it from `releases/latest/download`. After the
commit that pins the new image digest in `deployment/docker-compose.yml`:

1. Create the release from the tag's own notes and mark it latest, then
   upload that commit's `deployment/docker-compose.yml` and its checksum:

   ```bash
   gh release create vX.Y.Z --verify-tag --latest --title "identuum-idp-oss vX.Y.Z" \
     --notes-file docs/releases/vX.Y.Z.md
   cd deployment
   shasum -a 256 docker-compose.yml > docker-compose.yml.sha256
   gh release upload vX.Y.Z docker-compose.yml docker-compose.yml.sha256 --clobber
   ```

   `--verify-tag` refuses a tag that does not exist on the remote, so the
   release can never create one.

2. Check what a customer downloads — anonymously, through the latest URL:

   ```bash
   curl -fsSL https://github.com/identuum/identuum-idp-oss/releases/latest/download/docker-compose.yml | shasum -a 256
   curl -fsSL https://github.com/identuum/identuum-idp-oss/releases/latest/download/docker-compose.yml | grep 'image: ghcr.io/identuum/identuum-idp-oss:'
   ```

   The sha256 must equal the uploaded file's, and the image line must be
   the new tag and digest.

A release whose compose asset is missing, or whose latest download differs
from the pinned file, has failed: the install line would serve nothing or
an older release.

### Releasing: the binaries

From `v0.7.0` every release also carries the bare binary for `linux/amd64`
and `linux/arm64` and a `SHA256SUMS` over both, built and attested by the
manual workflow `.github/workflows/publish-binaries.yml`:

1. Optionally, rehearse on `main` first: dispatch it with `dry_run` true (the
   default). It builds `main` as `0.0.0-dryrun`, attests both binaries and
   keeps them as workflow artifacts only.
2. After the tag and its GitHub Release exist, dispatch it on the tag with
   `version_tag` set to the tag and `dry_run` false:

   ```bash
   gh workflow run publish-binaries.yml --ref vX.Y.Z -f version_tag=vX.Y.Z -f dry_run=false
   ```

   It refuses a tag that does not point at the checked-out commit, and
   uploads `identuum-idp-oss_X.Y.Z_linux_amd64`, `…_linux_arm64` and
   `SHA256SUMS` to the existing release without `--clobber`, so an asset of
   the same name (the compose file included) is never replaced.
3. Check what an operator downloads:

   ```bash
   curl -fsSLO https://github.com/identuum/identuum-idp-oss/releases/download/vX.Y.Z/identuum-idp-oss_X.Y.Z_linux_amd64
   curl -fsSLO https://github.com/identuum/identuum-idp-oss/releases/download/vX.Y.Z/SHA256SUMS
   sha256sum --ignore-missing -c SHA256SUMS
   gh attestation verify identuum-idp-oss_X.Y.Z_linux_amd64 -R identuum/identuum-idp-oss
   ```

## Maintainer / developer source build

When you want to rebuild the image from a local checkout, layer the
build overlay on top of the customer-facing file:

```bash
docker compose \
    -f deployment/docker-compose.yml \
    -f deployment/docker-compose.build.yml \
    up -d --build
```

The overlay adds a `build:` context pointing at `..` (this repo); the
UI is the export vendored under `internal/uiexport`, so no sibling UI
checkout is needed. The base file's `image:` tag is preserved, so a subsequent `docker compose up -d` (without
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
