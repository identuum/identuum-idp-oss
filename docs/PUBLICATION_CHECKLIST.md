# identuum-idp-oss — Publication Checklist

This is the **single canonical** in-repo checklist for publishing
`identuum-idp-oss`. It absorbs the prior `PUBLICATION_DRY_RUN.md`,
which is now a thin pointer to this file. Use these steps for both
dry-runs and the actual publication.

Current state:

- GitHub repository exists at `https://github.com/identuum/identuum-idp-oss`
  and is public.
- First public release tag is `v0.3.3`.
- Security contact is `contact@identuum.ai`.
- Do not publish unless validation passes on the exact commit that will be public.

Owner runs all push, tag, visibility, branch-protection, and GitHub
release steps. The coding agent will not execute repository
visibility changes, push commands, tag commands, force-pushes, remote
tag deletion, release automation, GoReleaser, or GitHub Release
creation. Stop at any failure gate.

## 1. Preflight

Run:

    go build ./...
    go test ./... -count=1
    staticcheck ./...
    go build -tags integration ./...
    staticcheck -tags integration ./...
    go mod tidy -diff
    govulncheck ./...
    grype dir:. --fail-on high
    find . -maxdepth 2 -name go.work
    grep -E '^[[:space:]]*replace ' go.mod
    go list -deps ./... | grep -E 'identuum-idp-ce|identuum-idp/internal|identuum-ag|identuum-ui|auth-service|internal-tools'

Expected:

- all build/test/staticcheck commands pass
- `go mod tidy -diff` is empty
- `govulncheck` reports 0 vulnerabilities in called code
- `grype dir:. --fail-on high` exits 0 (no High or Critical findings)
- no `go.work`
- no `replace` directives
- dependency-boundary grep is empty

If the repo-local Makefile has a current `verify` target, use it. Older release trees may use `validate` instead.

If anything above fails, STOP. Do not proceed.

## 2. Confirm the security contact

Open `../SECURITY.md`. Confirm that `contact@identuum.ai` is a monitored inbox.

Do not publish if the inbox is not monitored.

## 3. Confirm GitHub repository state

Run:

    gh repo view identuum/identuum-idp-oss --json nameWithOwner,visibility,url,defaultBranchRef

Expected before final publication:

- `nameWithOwner`: `identuum/identuum-idp-oss`
- `defaultBranchRef.name`: `main`
- `visibility`: `PRIVATE`

## 4. Push `main` and publish `v0.3.3`

If `origin/main` and `v0.3.3` already exist, do not recreate them. Verify first:

    git rev-parse HEAD
    git rev-parse origin/main
    git rev-parse v0.3.3
    git ls-remote --heads origin
    git ls-remote --tags origin 'v0.3.3*'

Expected final public-release state:

    origin/main points to the intended release commit
    refs/tags/v0.3.3 points to the intended release commit

If the repo is still private and the existing `v0.3.3` tag points to a defective private-only candidate, the owner may choose to replace it before public visibility.

Once public, do not rewrite `v0.3.3`; publish a follow-up tag instead.

## 5. Verify `go get`

After the repository is public:

    mkdir -p /tmp/check-idp-oss
    cd /tmp/check-idp-oss
    go mod init check
    go get github.com/identuum/identuum-idp-oss@v0.3.3
    go list -m github.com/identuum/identuum-idp-oss

Expected:

    github.com/identuum/identuum-idp-oss v0.3.3

## 6. Flip repository visibility

Only after the exact release commit and tag are validated:

    gh repo edit identuum/identuum-idp-oss --visibility public

Then verify:

    gh repo view identuum/identuum-idp-oss --json nameWithOwner,visibility,url,defaultBranchRef

## 7. Post-publication

- Confirm CI is green on public `main`.
- Confirm README, LICENSE, SECURITY, and docs render correctly.
- Confirm `go get github.com/identuum/identuum-idp-oss@v0.3.3` works from a clean module.
- Create a GitHub Release for `v0.3.3` only if owner policy requires it.

## Reminders

- Do not publish if `govulncheck` reports vulnerabilities in called code.
- Do not publish if `grype dir:. --fail-on high` reports any High or Critical finding.
- Do not publish without confirming `contact@identuum.ai`.
- Do not rewrite `v0.3.3` after the repository is public.
- Do not force-push `main` on a public repository.
