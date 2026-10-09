# Release checklist

This is the release order for the IdP binary, its embedded console, the
container image and the downloadable assets. Get explicit authorization for
the version, pushes, tags, workflow dispatches and GitHub release before
starting. Stop publication when a required check fails. Do not move an
existing tag or replace published binaries. Replace `X.Y.Z` below with the
approved version.

1. **Check Lictor pins first.** Before any release change, confirm that every
   release consumer declares the same `LICTOR_VERSION`, with no missing or
   duplicate pin. Run each repository's `make toolchain-parity` to check its
   local and CI tools. Resolve mismatches before continuing.
2. **Set the console version before vendoring.** In the public
   [identuum-ui repository](https://github.com/identuum/identuum-ui), set
   `package.json` to `X.Y.Z`, run its required checks, commit and push the
   version change. Push its approved `vX.Y.Z` tag. That tag runs
   `publish-ui-export.yml` and creates the console release; wait for success.
   Record the exact pushed console commit.
3. **Vendor that console commit into the IdP.** Use a clean console checkout
   at the recorded commit:

   ```bash
   make ui-vendor UI_DIR=<console-checkout> UI_SHA=<pushed-console-commit>
   make ui-vendor-check
   ```

   `UI_DIR` is a caller-supplied checkout, not a required workspace layout.
   Check that `internal/uiexport/manifest.json` names the intended commit.
4. **Regenerate third-party notices.** Run `make notices UI_DIR=<console-checkout>`
   at the same console commit, then `make notices-check`. The generator uses
   the release targets `linux/amd64` and `linux/arm64`, not the host platform.
5. **Write the release content.** Move the intended Unreleased changes into
   the version's CHANGELOG section and create `docs/releases/vX.Y.Z.md`.
   State whether a migration was added, changes an operator must act on,
   known limitations and rollback requirements. Link to
   [Upgrading and rolling back](../OPERATOR-GUIDE.md#upgrading-and-rolling-back).
   Include the console commit and the verification evidence. Stage only the
   intended files and commit the release content.
6. **Verify the final release tree.** Run the repository's full required
   gates, including `make verify`, and follow `make mint-decide` for the
   required end-to-end proof. For a release, run the full release tests and
   `make openid-conformance`; record the plan summaries and any committed
   expected failures without claiming certification. Check vulnerability
   results and make the required witness. Push the work and its records;
   require CI success for the pushed revision before tagging it. If a later
   change alters the release tree, verify that tree again.
7. **Tag the approved IdP revision.** Create and push the authorized
   `vX.Y.Z` tag on the verified revision. Do not tag an untested commit.
8. **Publish the image on that tag.** Dispatch the image workflow using its
   existing inputs:

   ```bash
   gh workflow run publish-image.yml --repo identuum/identuum-idp-oss --ref vX.Y.Z -f version_tag=vX.Y.Z -f latest_tag=false
   ```

   Require success and record the published multi-platform index digest.
   The workflow verifies the tag, binary version, live image and security
   checks before pushing. Keep `latest_tag=false`; releases do not publish a
   floating `:latest` image.
9. **Create the GitHub release from the tag's notes.**

   ```bash
   gh release create vX.Y.Z --repo identuum/identuum-idp-oss --verify-tag --latest --title "identuum-idp-oss vX.Y.Z" --notes-file docs/releases/vX.Y.Z.md
   ```

   `--verify-tag` requires the remote tag to exist. Do not mark the release
   complete while its assets are still being assembled.
10. **Publish the Linux binaries on that tag.** Once the GitHub release
    exists, dispatch the binary workflow:

    ```bash
    gh workflow run publish-binaries.yml --repo identuum/identuum-idp-oss --ref vX.Y.Z -f version_tag=vX.Y.Z -f dry_run=false
    ```

    Require success. Check both Linux architectures, `SHA256SUMS` and their
    provenance attestations. The workflow refuses existing asset names.
    An optional rehearsal uses `main` with `dry_run=true`; it does not upload
    release assets and cannot replace the tag-based publish run.
11. **Commit the compose image pin after publication.** Set the image tag
    and index digest in `deployment/docker-compose.yml` to the values from
    step 8. Review its live comments and upgrade instructions, validate the
    configuration and commit this pin separately. Run its required checks
    and push; keep the release tag on the revision whose image was built.
    Upload this pin commit's compose file and checksum using
    [the compose asset procedure](../../deployment/README.md#releasing-the-compose-asset).
    The compose file therefore comes from the pin commit after the tag;
    binaries and image come from the tag.
12. **Verify public downloads and an upgrade.** Check the release's compose
    file and checksum, both binaries and `SHA256SUMS`, and that the anonymous
    latest download names the intended image digest. Verify attestations with
    `gh attestation verify`. Exercise the documented upgrade from the previous
    release on a disposable installation, check health and sign-in, and retain
    the result with the release evidence. Fetch the repository's CI record
    with `make ci-fetch RUN=<successful-run-id>` as required by its close
    process; record-only commits ride with the next real change.

The [deployment guide](../../deployment/README.md) contains asset upload,
checksum and attestation commands. Release notes describe version-specific
requirements; the operator guide owns the general backup and rollback steps.
