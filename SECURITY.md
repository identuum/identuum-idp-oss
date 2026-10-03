# Security Policy

## Reporting a vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

If you discover a security vulnerability in `identuum-idp-oss`, please
report it privately so it can be assessed and patched before public
disclosure.

**Contact:** contact@identuum.ai

Please include:

- A clear description of the vulnerability
- Steps to reproduce, if applicable
- Affected component, package, or file path
- Your assessment of severity and exploitability

You will receive an acknowledgement within 5 business days. We aim to
provide a patch or workaround within 30 days of confirmation, depending
on severity.

## What to include and what to avoid

**Do include:**

- Reproducible steps, proof-of-concept code (no working exploits)
- Log snippets with secrets redacted
- Your suggested remediation if you have one

**Do not include:**

- DB credentials, API keys, or tokens in any form
- Raw JWTs, access tokens, refresh tokens, id_tokens, or logout_tokens
- Session cookies, auth codes, state values, or PKCE verifiers
- TOTP secrets, recovery codes, or setup tokens
- Signing key material in any form
- Screenshots with credentials visible
- DB URLs or DSNs

## Supported versions

`identuum-idp-oss` is the Starter-tier extraction of the Identuum identity
provider, currently published for viewing and evaluation only (see
`LICENSE`).

The latest release (`v0.9.x`) receives security fixes: they land on `main`
and ship in its next patch release. Older releases are not patched; upgrade
to the latest release (see the
[Releases](https://github.com/identuum/identuum-idp-oss/releases) page).

## Scope

This policy covers:

- The `identuum-idp-oss` module
- Its Go source code, test harness, migrations, and supporting tooling

Out of scope:

- The commercial edition, Identuum CE, a separate product (report CE-only
  issues through the same contact above)
- The `identuum-ui` operator UI embedded in this binary: report its issues
  at https://github.com/identuum/identuum-ui (if unsure which one an issue
  belongs to, report it through this policy)
- Third-party dependencies (report to their respective maintainers)

## Disclosure timeline

After a fix is available:

1. Patch is merged to `main`.
2. We notify the reporter with the fix details.
3. We publish a security advisory on this repository.
4. A CVE may be requested for significant vulnerabilities.
