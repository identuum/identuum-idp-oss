# Known issues

Issues we know about in released versions of identuum-idp-oss, with what to do until they are fixed.
Newest release first. Each entry says which versions are affected and where the fix is tracked.

## v0.9.11

### "Email verified" can be shown for an address that was never proven by email

- **Affected:** v0.9.11 and earlier versions that include one-time invite links (OSS-ONBOARD-A, decision D-016).
- **What happens:** when a user is invited without a password, the administrator receives a one-time invite link.
  Redeeming that link (or an activation or claim link) marks the user's email address as verified, even when the
  link was handed over directly by the administrator and never travelled by email. The member Overview then shows
  "Email verified: Verified".
- **Why it matters:** the flag is also used when identuum counts an organization's verified administrators (for
  example in account-recovery checks), so it is more than a label.
- **Until it is fixed:** no setting makes the status mean "this person controls the mailbox", because the
  administrator always also receives the link, even when it is emailed. Treat "Email verified" as "account
  activated". Relying parties that need a proven address should not rely on `email_verified` from v0.9.11 or
  earlier.
- **Fixed in v0.9.12 for tokens and userinfo:** the `email_verified` claim is true only when the user opened a
  verification email or the sign-in provider confirmed the address. The console screens, including the member
  Overview, show the new status with the console update that reads it (tracked as UI-0912-A4); until then they
  still show the activation. Accounts verified before v0.9.12 keep their status.

  _Corrected on 2026-10-12: this entry first said that configuring SMTP was a workaround and that the fix would
  trust a link "delivered by email". Neither holds: the administrator receives the same link either way.
  Corrected again on 2026-10-12: the fix line said the screens were fixed too and that accounts "created"
  before v0.9.12 keep their status; only accounts verified before it do._
