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

This repository is **pre-release**: `identuum-idp-oss` is the
Starter-tier extraction of the Identuum identity provider, currently
published for viewing and evaluation only (see `LICENSE`). There is no
versioned release yet.

Security fixes are applied to the `main` branch. There is no backport
policy until a stable release is tagged.

## Scope

This policy covers:

- The `identuum-idp-oss` module
- Its Go source code, test harness, migrations, and supporting tooling

Out of scope:

- The production monolith at `identuum-idp/` (separate disclosure channel)
- The commercial edition at `identuum-idp-ce/` (covered by the Identuum
  CE license; report CE-only issues to the Identuum security team
  through the same contact above)
- The agentic governor at `identuum-ag*/` (separate workstream)
- The `identuum-ui` Next.js frontend (separate workstream)
- Third-party dependencies (report to their respective maintainers)

## Disclosure timeline

After a fix is available:

1. Patch is merged to `main`.
2. We notify the reporter with the fix details.
3. We publish a security advisory on the GitHub repository when the
   repository is public.
4. A CVE may be requested for significant vulnerabilities.
