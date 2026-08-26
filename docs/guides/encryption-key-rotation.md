# Rotating the at-rest encryption key

`IDENTUUM_IDP_ENCRYPTION_KEY` (32-byte hex) seals every at-rest secret the
IdP holds: signing-key private material, MFA TOTP seeds (enrolled and
pending), upstream-IdP client secrets and LDAP bind passwords inside
provider configs, and in-flight PKCE verifiers. The
`rotate-encryption-key` subcommand re-encrypts all of it from a retired
key to a new one, offline, in one transaction.

## The ceremony

0. **Back up first.** The rotation is atomic, but an operator ceremony
   deserves an exit that does not depend on the tool being right:

   ```
   pg_dump -F c <database> > identuum-idp-pre-rotation-$(date +%F).dump
   ```

   Keep the dump outside the deployment tree. No dump, no rotation.

1. **Stop the IdP.** Rotation is offline-only: it takes the
   single-replica instance lease with a single attempt and REFUSES,
   naming the incumbent, while any process is serving.

   ```
   docker compose stop <idp-service>    # the SERVICE name from your
                                        # compose file (the dev compose
                                        # calls it `app`), or your
                                        # process manager
   ```

   A gracefully stopped server releases the lease immediately —
   rotation can start at once (measured). After a crash or `kill -9`
   the dead instance's lease lingers until its ~45-second TTL expires;
   the tool refuses, naming the stale incumbent — wait a minute and
   run it again.

2. **Rotate.** Both keys come from the environment — key material is
   never accepted on the command line (argv is visible in `ps`).
   `IDENTUUM_IDP_ENCRYPTION_KEY` is the NEW key (what the platform runs
   with from now on); `IDENTUUM_IDP_OLD_ENCRYPTION_KEY` is the key being
   retired.

   ```
   IDENTUUM_IDP_ENCRYPTION_KEY=<new-64-hex> \
   IDENTUUM_IDP_OLD_ENCRYPTION_KEY=<old-64-hex> \
     identuum-idp rotate-encryption-key <database-url>
   ```

   The run prints per-family converted / already-current counts and the
   old and new key ids (ids are hash prefixes — safe in logs, never the
   key). It is **atomic**: everything happens in one transaction, and a
   value that decrypts under neither key aborts the whole run with zero
   rows changed — the usual cause is a wrong
   `IDENTUUM_IDP_OLD_ENCRYPTION_KEY`. It is **idempotent**: re-running
   with the same pair converges (values already under the new key are
   skipped), so an interrupted run is finished by running it again.

   The run also carries an **unknown-schema guard**: before touching
   anything it probes the database for sealed-looking values in columns
   outside its family list and refuses by name if it finds any — that
   means the database belongs to a newer or different build (point the
   matching binary at it instead).

3. **Set the new key** wherever the deployment supplies it (env file,
   secret store, appliance key file) and **remove the old one** once
   verified.

4. **Start the IdP.**

5. **Verify with doctor.** The `at-rest-seals` lines report which key id
   every sealed family's rows sit under:

   ```
   IDENTUUM_IDP_ENCRYPTION_KEY=<new-64-hex> identuum-idp doctor <database-url>
   ...
   identuum-idp: doctor: at-rest-seals: signing_keys.private_key: 3b1eabdd6f6cbab7(3)
   identuum-idp: doctor: at-rest-seals: users.mfa_secret: 3b1eabdd6f6cbab7(12)
   ```

   After a complete rotation every non-empty family shows a single key
   id — the new one. A second id still listed means rows remain under
   the old key (an interrupted run: run step 2 again). `plaintext` or
   `legacy` entries are pre-encryption values; rotation seals plaintext
   signing-key PEMs and converts legacy-format ciphertexts on the way
   through. If the IdP was started with the wrong key, `/health` reports
   NOT-SERVING and doctor's `signing-key-seal` line says `SEALED`.

## What rotation does NOT cover

- **Org backups.** Backup files are encrypted with a **user-supplied
  password** (argon2id-derived key, per-file salt — see
  `internal/domain/org_backup.go`), not with the platform key. Rotation
  does not touch them and does not need to: they remain restorable with
  their passwords after any number of platform-key rotations.
- **Password hashes, recovery codes, token/secret hashes.** These are
  one-way hashes, not ciphertexts — there is nothing to re-encrypt.
- **A LOST key.** Rotation converts data it can decrypt. If the old key
  is gone, the sealed values are gone with it; MFA enrollments must be
  reset and signing keys re-minted. The doctor `signing-key-seal: SEALED`
  state names this condition.
