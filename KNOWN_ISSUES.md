# Known issues

Issues we know about in released versions of identuum-idp-oss, with what to do until they are fixed.
Newest release first. Each entry says which versions are affected and where the fix is tracked.

## v0.9.13

### One email address in two organizations stops email sign-in for both accounts

- **Affected:** v0.9.13 and v0.9.12 (the same code), and earlier versions with organization-scoped user accounts.
- **What happens:** an address may belong to a live account in more than one organization: an organization
  administrator can create or invite a user with any address, the initial administrator of a new organization is
  not checked against other organizations, and a provider sign-in can create a second account. Sign-in by email
  looks the address up across all organizations. When it finds two live accounts, password sign-in and passkey
  sign-in by email fail for both accounts.
- **Until it is fixed:** keep every email address unique across the organizations of a server. Before you create
  a user, an invitation or a new organization's administrator, check that no other organization uses the address.
  `409 email_exists` on `POST /api/v1/organizations` is not enforced across organizations until v0.9.14.
- **Fix planned for v0.9.14:** one address per server.
- **Tracked:** the identuum-idp-oss queue (owner decision EMAIL-SCOPE (a), 2026-10-13).

### A passkey or provider sign-in does not ask for the password change an administrator requested

- **Affected:** every version with administrator-set passwords that must be changed (D-017), including the
  v0.9.13 changes (the same rule on `PUT /api/v1/users/{id}`, and the 24-hour expiry).
- **What happens:** only password sign-in reads the change request and the 24-hour expiry. A member who also has a
  passkey, or who signs in through the organization's identity provider, gets a session without choosing a new
  password, and the administrator-set password stays as it was.
- **Until it is fixed:** for a member who has a passkey or a provider login, give a reset link
  (`POST /api/v1/users/{id}/recovery/reset-link`) instead of setting a password, so the member chooses one.
- **Tracked:** the identuum-idp-oss queue (OSS-0913-B).

## v0.9.11

### "Email verified" can be shown for an address that was never proven by email

- **Affected:** v0.9.11 and earlier versions that include one-time invite links (OSS-ONBOARD-A, decision D-016).
- **What happens:** when a user is invited without a password, the administrator receives a one-time invite link.
  Redeeming that link (or an activation or claim link) marks the user's email address as verified, even when the
  link was handed over directly by the administrator and never travelled by email. The member Overview then shows
  "Email verified: Verified".
- **Why it matters:** the flag is also used when identuum counts an organization's verified administrators (for
  example in account-recovery checks), so it is more than a label.
- **Until you upgrade:** no setting makes the status mean "this person controls the mailbox", because the
  administrator always also receives the link, even when it is emailed. Treat "Email verified" in v0.9.11 and
  earlier as "account activated". Relying parties that need a proven address should not rely on
  `email_verified` from these versions.
- **Fixed in v0.9.12:** an address counts as verified only when the user opened a verification email from
  identuum, or their sign-in provider confirmed it. This holds for the `email_verified` claim in tokens and
  userinfo and for the console screens, including the member Overview (identuum-ui `a932627`, embedded in
  v0.9.12). Accounts verified before the upgrade keep their status. See the v0.9.12 release notes,
  "Upgrading from v0.9.11".

  _Corrected on 2026-10-12: this entry first said that configuring SMTP was a workaround and that the fix would
  trust a link "delivered by email". Neither holds: the administrator receives the same link either way.
  Corrected again on 2026-10-12: the fix line said the screens were fixed too and that accounts "created"
  before v0.9.12 keep their status; only accounts verified before it do. Updated for the v0.9.12 release on
  2026-10-12: the console update (identuum-ui `a932627`) is now embedded, so the screens are fixed too._
