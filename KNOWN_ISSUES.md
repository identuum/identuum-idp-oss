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
- **Until it is fixed:** when you need the verified status to mean "this person controls the mailbox", configure
  SMTP and let users activate from the email they receive instead of handing out the link directly.
- **Planned fix:** a later release marks an address verified only when the link was delivered by email, shows
  "Not verified" with a way for the user to verify otherwise, and re-checks every use of the flag.
