# Final revision OpenID Connect conformance record for v0.9.11

This is a measured conformance record, not an OpenID certification claim.
Tested revision `e17835e3a2b6b60f93ee7b71683d23cd2607390a`; Git tree `1c9c01de64590a6fa7e9d14c6b72038d04c28de0`.
Started 2026-10-11T19:33:49Z; finished 2026-10-11T19:46:36Z.
Suite release-v5.2.4, pin `ab35a8df4864da35b49eff11483e204e01aa7961`. All results below belong to this one revision.

## Plans and counting rules

Counts are module verdicts from plan summaries, using the controlled rerun for rotation, not condition counts.
UNKNOWN or a non-FINISHED status is incomplete. No missing module counts as a pass.
The public-client none plan uses an explicit per-client PKCE opt-out; completion is required.
The suite runner's separate total includes an extra entry per completed plan.

- [basic](assets/basic.html): 35 counted modules; FAILED 0, INTERRUPTED 0, PASSED 32, REVIEW 3, SKIPPED 0, UNKNOWN 0, WARNING 0.
- [bc-logout](assets/bc-logout.html): 2 counted modules; FAILED 0, INTERRUPTED 0, PASSED 2, REVIEW 0, SKIPPED 0, UNKNOWN 0, WARNING 0.
- [comp-basic](assets/comp-basic.html): 36 counted modules; FAILED 0, INTERRUPTED 0, PASSED 32, REVIEW 4, SKIPPED 0, UNKNOWN 0, WARNING 0.
- [comp-none](assets/comp-none.html): 36 counted modules; FAILED 0, INTERRUPTED 0, PASSED 31, REVIEW 4, SKIPPED 1, UNKNOWN 0, WARNING 0.
- [comp-pkjwt](assets/comp-pkjwt.html): 37 counted modules; FAILED 0, INTERRUPTED 0, PASSED 33, REVIEW 4, SKIPPED 0, UNKNOWN 0, WARNING 0.
- [comp-post](assets/comp-post.html): 36 counted modules; FAILED 0, INTERRUPTED 0, PASSED 32, REVIEW 4, SKIPPED 0, UNKNOWN 0, WARNING 0.
- [config](assets/config.html): 1 counted modules; FAILED 0, INTERRUPTED 0, PASSED 1, REVIEW 0, SKIPPED 0, UNKNOWN 0, WARNING 0.
- [fc-logout](assets/fc-logout.html): 2 counted modules; FAILED 0, INTERRUPTED 0, PASSED 2, REVIEW 0, SKIPPED 0, UNKNOWN 0, WARNING 0.
- [rp-logout](assets/rp-logout.html): 11 counted modules; FAILED 0, INTERRUPTED 0, PASSED 3, REVIEW 8, SKIPPED 0, UNKNOWN 0, WARNING 0.

## Expected posture and comparison

The appliance enables RS256 advertisement; discovery must pass. Only the
public test-client pair opts out of required PKCE. The ordinary runner
does not rotate keys; those original attempts are retained separately. Each
comprehensive primary census uses its controlled rotation verdict. A real-rotation
attempt has historically failed because this suite condition does not understand OKP.
Controlled rotation generates and activates RS256 and ES256 keys, retaining old keys.
Only a recorded VerifyNewJwksHasNewSigningKey unknown-OKP failure qualifies as a suite limitation.
REVIEW denotes uploaded-page checks needing a human. Retained sanitized captures
and instructions are in the candidate's local REVIEW.md. This summary-only bundle
omits screenshots, request/response traces, private metadata and identities.
It cannot resolve REVIEW, prove a certification, or prove untested plans.
New failures remain visible; the comparison does not alter the repository gate floor.
The separate rotation asset repeats comp-basic's controlled result; never add it to primary totals.
[Comparison](assets/compare.txt), [census](assets/census.json),
[rotation operations](assets/rotation-evidence.json), [unassisted attempts](assets/unassisted-rotation.json),
[provenance](assets/run.json) and [teardown](assets/teardown.txt).

## Policy expectations and human review

- Test oidcc-refresh-token in plan comp-none is expected SKIPPED. Intended server policy: public clients deliberately receive no refresh token. A public client (token_endpoint_auth_method none) is not handed one because the refresh_token grant refuses a credential-less client; the suite skips oidcc-refresh-token when the token response carries none. The earlier PASSED was a coverage projection from comp-basic, never measured: the historical comp-none export holds two modules.
  Code reference: identuum-idp-oss internal/handlers/token.go:508-511 at e17835e; commit 86646ad (2026-10-05, FUNC-H2); owner decision 2026-10-11 20:03 (OSS-FINAL-CONFORMANCE-RERUN Q5 option a).

REVIEW modules: 27 (uploaded-page checks that the suite leaves to a human).
Judge disposition: REVIEW-ACCEPTED for 27 of 27 captures, recorded in
`nuntius-workspace/reviews/OSS-CONFORMANCE-REVIEW-CAPTURES-0.9.11.md` (sha256 `68691cf6f8da67c2570ac926158cf83245b691c1a045cf6aa005e5fa8327ae56`). This is a reviewer disposition, not a suite PASS.
