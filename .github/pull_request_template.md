<!--
External contributions are not being accepted at this time — see
README.md.

Please read SECURITY.md before opening a PR.

Do NOT submit security vulnerabilities through public PRs. Follow the
private disclosure process in SECURITY.md and email
contact@identuum.ai.
-->

## Summary

What does this PR change, and why?

## Scope

- [ ] OSS / Starter-tier only (no CE features sneaked in)
- [ ] No new `replace` directives in `go.mod`
- [ ] No `go.work` introduced
- [ ] No new imports of `identuum-idp-ce`, `identuum-idp/internal`,
      `identuum-ag*`, `identuum-ui`, `auth-service`, or `internal-tools`

## Validation

Run the standard validation matrix before requesting review. Paste
abbreviated output (PASS / FAIL) into the checklist below.

- [ ] `go mod tidy -diff` — clean (empty output)
- [ ] `go build ./...` — PASS
- [ ] `go vet ./...` — PASS
- [ ] `go test ./... -count=1` — PASS
- [ ] `staticcheck ./...` — PASS
- [ ] `govulncheck ./...` — 0 vulnerabilities in called code
- [ ] `grype dir:. --fail-on high` — PASS (no High or Critical findings)
- [ ] `make verify` — PASS (or note which Makefile target was used)

For integration-tagged changes:

- [ ] `go build -tags integration ./...` — PASS
- [ ] `staticcheck -tags integration ./...` — PASS

## Migrations

- [ ] No new migration, OR
- [ ] New migration added under `migrations/`, numbered sequentially,
      both `+goose Up` and `+goose Down` present, and tested locally
      against PostgreSQL 18+.

## Security & secrets

- [ ] No `.env`, `dev.env`, `dev.env.local`, license files, private
      keys, or DB dumps included
- [ ] No raw tokens, cookies, TOTP secrets, recovery codes, or signing
      keys in logs / errors / test output / response bodies
- [ ] JWKS responses surface only public-key material (no `"d"`)

## Notes for reviewers

Anything reviewers should pay particular attention to (tricky edge
cases, performance considerations, behavior changes that affect
downstream consumers, etc.).
