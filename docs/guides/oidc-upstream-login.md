# Operator guide — upstream OIDC login (Google, Microsoft/Entra, generic)

This guide configures **basic single-provider upstream OIDC login** — the OSS IdP acting as a
**relying party (RP)** that delegates authentication to **one** external OIDC provider **per
organization**. It is OSS-core and shipped end-to-end.

Google and Microsoft/Entra are **configuration instances of one generic, discovery-based flow** — not
special code paths. Any spec-compliant OIDC provider works the same way. (Per-org **managed /
multi-IdP** federation and **LDAP/AD** are Commercial Edition features and are out of scope here.)

## Model

- **One OIDC provider per organization.** An org has at most one active `type=oidc` identity
  provider. Configuring a second is rejected.
- **Discovery-based.** You supply the provider's issuer/discovery URL; the IdP reads
  `/.well-known/openid-configuration` for the authorization, token, and JWKS endpoints.
- **JIT provisioning, gated by `email_domains`.** On first login the IdP provisions a passwordless
  federated local user, but only for a provider-verified email whose domain is allow-listed (unless
  external domains are explicitly allowed).

## Configure a provider (org admin)

Send the provider config to the org identity-provider API (org admin, own org only):

```
POST /api/v1/organizations/{org_id}/identity-provider
```

Fields:

| Field | Meaning |
|---|---|
| `type` | Must be `oidc`. |
| `issuer_url` | The provider's issuer / discovery base (must be `https://`). Discovery is read from `{issuer_url}/.well-known/openid-configuration`. |
| `client_id` | The OAuth client ID registered with the provider. |
| `client_secret` | The client secret (stored encrypted; write-only — never returned by GET). |
| `scopes` | Must include `openid`. Add `email profile` to receive the email + name claims. |
| `email_domains` | Allow-list of email domains permitted to JIT-provision (e.g. `["example.com"]`). |
| `allow_external_domains` | When `true`, bypass the allow-list (use with care). |

### Redirect URI

Register this exact callback with the provider (it is the OSS callback route):

```
https://<your-idp-host>/api/v1/auth/idp/{provider_id}/callback
```

`{provider_id}` is the identity-provider row's ID (returned when you create it).

### Google

- **Issuer / discovery:** `https://accounts.google.com`
- **Scopes:** `openid email profile`
- Register the redirect URI above as an "Authorized redirect URI" on the OAuth 2.0 Client in Google
  Cloud Console.

### Microsoft / Entra ID

- **Issuer / discovery:** `https://login.microsoftonline.com/{tenant}/v2.0` — the **tenant is baked
  into the authority URL** (`{tenant}` is your directory/tenant ID, or `organizations` /
  `common` per your policy).
- **Scopes:** `openid email profile`
- Register the redirect URI above under the app registration's "Web" platform redirect URIs.

### Generic OIDC provider

Any provider exposing a standards-compliant discovery document works: set `issuer_url` to its issuer,
`client_id`/`client_secret` to the registered client, include `openid` in `scopes`, and register the
callback redirect URI.

## The login flow

1. The pre-auth UI calls `GET /api/v1/auth/organization-lookup?domain=<email-domain>`; when the org
   has an active OIDC provider the response's `login_url` is
   `/api/v1/auth/idp/{provider_id}/login`.
2. `GET /api/v1/auth/idp/{provider_id}/login` starts the flow (state + nonce + PKCE) and redirects the
   browser to the provider.
3. The provider authenticates the user and calls back to
   `GET /api/v1/auth/idp/{provider_id}/callback`.
4. The IdP validates the ID token against the provider JWKS, applies the `email_domains` gate,
   JIT-provisions or matches the local user, mints a local session, and redirects to the stored
   return URL.

## Security notes

- The client secret and PKCE verifier are stored **encrypted**; nothing sensitive is logged.
- ID-token validation is strict: signature vs the provider JWKS by `kid`, `alg` allow-list
  (rejects `alg=none` and alg-confusion), and `iss` / `aud` / `exp` / `nonce` checks.
- All outbound calls (discovery, token exchange, JWKS) are SSRF-guarded.
- The `email_domains` gate is fail-closed: an unverified email, or a domain not on the allow-list
  (without `allow_external_domains`), is refused before any account is created.
- A returning user is matched by their stable external identity (`issuer|sub`) first, so a
  provider-side email change cannot take over another local account.
- Expired, never-completed login states are swept periodically from `oidc_states`.

## Hardening: hide federated domains from the public lookup

The public, unauthenticated organization-lookup
(`GET /api/v1/auth/organization-lookup`) returns each active provider's
`email_domains` so the login page can auto-select which provider to use for a typed email. That
list also **discloses which email domains an org federates**. Operators who consider that sensitive
can hide it:

```
IDENTUUM_IDP_PUBLIC_HIDE_IDP_EMAIL_DOMAINS=true
```

| Value | Behavior |
|---|---|
| unset / `false` / `0` (**default**) | `email_domains` is **exposed** on the public lookup — current behavior, no change. |
| `true` / `1` | `email_domains` is **omitted** from the public lookup response. |
| anything malformed | treated as the safe default (**exposed**). |

**Scope and tradeoff (honest):**

- The flag gates **only** the public lookup. The **authenticated org-admin identity-provider API**
  (`/api/v1/organizations/{org_id}/identity-provider`) **still returns `email_domains`** — org
  admins continue to view and manage it.
- `id`, `type`, `name`, and `login_url` are **always** returned, so **SSO login keeps working**.
- The only UX effect: when an org has **multiple** providers, the login page can no longer
  auto-select by the typed email's domain and instead shows a one-click provider picker.
  **Single-provider orgs (the OSS model) are unaffected** — the login page redirects straight to the
  one provider's `login_url` without ever consulting `email_domains`.
- No UI change is required: the field is optional in the login UI and its absence is already handled.
