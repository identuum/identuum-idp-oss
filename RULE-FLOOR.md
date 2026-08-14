FLOOR: 72

| ID | one-sentence rule | enforced-by | check | red-proof | hash |
|---|---|---|---|---|---|
| SETUP-CODE-1 | A fresh appliance prints a one-time setup code and refuses after setup completes | go-test | cmd/identuum-idp/setup_show_code_test.go @ unit | - | 7b9993252c7c |
| RECOVER-1 | recover-site-admin resets only the sentinel-guarded site_admin row | go-test | cmd/identuum-idp/recover_test.go @ unit | - | aaca81397daf |
| LOCKOUT-1 | Lockout answers exactly like a wrong password: invalid_credentials | go-test | internal/handlers/login_risk_unavailable_test.go @ unit | - | 6607b26ad69a |
| LOGIN-PIN-1 | Login identity is site_admin@system.local; contact_email never logs in | go-test | internal/setup/rg15_login_identity_test.go @ unit | - | e656142e21f9 |
| R1 | The pinned model values are the shared OSS/CE contract. | go-test | internal/domain/r_suite_test.go @ unit | - | fd3b666ad93f |
| R4 | The System organization has the lowest possible UUIDv7 id. | go-test | internal/domain/r_suite_test.go @ unit | - | b25844fef644 |
| R5 | The site_admin has the lowest possible UUIDv7 id plus one. | go-test | internal/domain/r_suite_test.go @ unit | - | ae0102bb1983 |
| R6 | The site_admin login identifier constant is site_admin@system.local. | go-test | internal/domain/r_suite_test.go @ unit | - | e438a0bd3876 |
| R8 | The System Organization name and slug are pinned to System Organization and system-local. | go-test | internal/domain/r_suite_test.go @ unit | - | 99a5118b530e |
| R16 | The org_admin scope set covers exactly the granted admin areas. | go-test | internal/domain/r_suite_test.go @ unit | - | 9f0806e3c23c |
| R18 | site_admin is not an assignable organization role. | go-test | internal/domain/r_suite_test.go @ unit | - | 047adcbd036a |
| R21 | org_user carries no administrative scopes. | go-test | internal/domain/r_suite_test.go @ unit | - | 4c672323260a |
| MODEL-SYSJOIN-1 | Only the site_admin may be a member of the System organization. | go-test | internal/service/model_sentinel_guards_test.go @ unit | - | 9dcd37ab8724 |
| MODEL-DELETABLE-1 | Ordinary users stay deletable; sentinel protection covers only the sentinels. | go-test | internal/service/model_sentinel_guards_test.go @ unit | - | 43ad8f009e33 |
| MODEL-SA-NODELETE-1 | The site_admin cannot be deleted by any actor. | go-test | internal/service/model_sentinel_guards_test.go @ unit | - | ad1ed1db3c6f |
| MODEL-SYSORG-NODELETE-1 | The System organization cannot be deleted. | go-test | internal/service/model_sentinel_guards_test.go @ unit | - | fcb5dfba5a60 |
| MODEL-SYSORG-NORENAME-1 | The System organization cannot be renamed. | go-test | internal/service/model_sentinel_guards_test.go @ unit | - | f31693aa103b |
| MODEL-404-SA-1 | An org_admin sees the site_admin account as 404, never 403. | go-test | internal/handlers/model_404_test.go @ unit | - | fcfb763ce73f |
| MODEL-404-CROSSORG-1 | An org_admin sees another organization's user as 404, never 403. | go-test | internal/handlers/model_404_test.go @ unit | - | fc751e8cbfbc |
| TRIO-OWN-1 | An org_admin can create users in their own organization. | go-test | internal/handlers/session_scope_trio_test.go @ unit | - | beeb7efbca7e |
| TRIO-OTHER-1 | An org_admin acting on another organization gets 403. | go-test | internal/handlers/session_scope_trio_test.go @ unit | - | c00ec4f58f37 |
| TRIO-USER-1 | An org_user attempting admin actions gets 403. | go-test | internal/handlers/session_scope_trio_test.go @ unit | - | 8068a8b474b7 |
| SA-TENANT-FIRST-1 | site_admin may seed a tenant organization's first org_admin. | go-test | internal/service/site_admin_tenant_write_test.go @ unit | - | 39bd8e883964 |
| SA-TENANT-SECOND-1 | site_admin cannot add a second org_admin once one is active. | go-test | internal/service/site_admin_tenant_write_test.go @ unit | - | 5e33a3079876 |
| SA-TENANT-USER-1 | site_admin cannot create a regular org_user inside a tenant. | go-test | internal/service/site_admin_tenant_write_test.go @ unit | - | f5f18254dc0d |
| SA-TENANT-SYSORG-1 | The System organization is not a tenant for delegation purposes. | go-test | internal/service/site_admin_tenant_write_test.go @ unit | - | 8134de2b8c57 |
| RG10 | Cross-org write probes are indistinguishable from a miss. | go-test | internal/handlers/rg10_no_existence_oracle_test.go @ unit | - | 4992c27d5a20 |
| CONTACT-EMAIL-1 | The installer's typed address is stored as contact email, trimmed and optional. | go-test | internal/setup/rg15_login_identity_test.go @ unit | - | 72a17995a3af |
| P0-REFRESH-1 | A reused refresh token is detected and revokes exactly its token family. | go-test | internal/service/refresh_token_family_test.go @ unit | - | 7a4254a50927 |
| P0-JTI-1 | Bearer JTI revocation fails closed: a store error rejects the token. | go-test | internal/mw/bearer_revocation_test.go @ unit | - | ce337e4e2118 |
| P0-CLIAUTH-1 | A client authenticates only with its exact registered token-endpoint method. | go-test | internal/service/oauth_client_auth_service_test.go @ unit | - | 7f2a12978f45 |
| P0-TENANT-1 | Organization liveness decisions use the single IsOperational predicate. | go-test | internal/domain/domain_methods_test.go @ unit | - | 2a32ce42024f |
| P0-BEARER-1 | Resource APIs authenticate only via Authorization Bearer; no header is 401. | go-test | internal/mw/bearer_test.go @ unit | - | 7f54833e14d7 |
| AUTH-WRONGPW-1 | A wrong password is refused with the generic 401 invalid_credentials. | go-test | internal/handlers/auth_sessions_test.go @ unit | - | e9156be44ea7 |
| USER-BAN-LOGIN-1 | A banned user's login collapses to invalid_credentials. | go-test | internal/service/local_login_service_test.go @ unit | - | 31678701a8dd |
| INTROSPECT-REVOKED-1 | A revoked token introspects as active false. | go-test | internal/service/introspection_service_test.go @ unit | - | 2d153e4dc3ea |
| INTROSPECT-AUTH-1 | Introspection refuses an unauthenticated client with 401. | go-test | internal/handlers/introspection_test.go @ unit | - | e612bc45fd7b |
| MFA-RECOVERY-1 | Recovery codes are stored hashed and each is accepted exactly once. | go-test | internal/service/mfa_at_rest_test.go @ unit | - | b1d4f226db31 |
| RATE-TOKEN-1 | Past the per-IP limit the rate-limited endpoint answers 429. | go-test | internal/mw/rate_limit_test.go @ unit | - | 4b94877cb698 |
| AUTHCODE-REPLAY-1 | An authorization code is single-use; replay revokes what it minted. | go-test | internal/service/authcode_reuse_revocation_test.go @ unit | - | 6da8c2f64474 |
| MFA-ADMIN-ENROLL-1 | An admin without MFA gets enrollment_required and no cookies. | go-test | internal/handlers/auth_mfa_policy_test.go @ unit | - | f1abf989ab94 |
| MFA-EVERY-LOGIN-1 | An MFA-enabled admin logging in without a code gets mfa_required and no cookies. | go-test | internal/handlers/auth_mfa_policy_test.go @ unit | - | 3dfd49389c4a |
| RG1 | The System organization cannot be suspended or soft-deleted at the database layer. | go-test | internal/postgres/model_update_teeth_test.go @ integration | blocked: TestRg1 in internal/postgres/model_update_teeth_test.go is go:build integration + live Postgres | bd59e986089f |
| RG2 | The site_admin cannot be banned, demoted, or soft-deleted at the database layer. | go-test | internal/postgres/model_update_teeth_test.go @ integration | blocked: TestRg2 in internal/postgres/model_update_teeth_test.go is go:build integration + live Postgres | b651173dc65b |
| USER-ORG-1 | Every user belongs to exactly one organization. | go-test | internal/service/burndown_rules_test.go @ unit | - | 4a42217b440a |
| SA-SINGLETON-1 | There is exactly one site_admin per installation. | go-test | cmd/identuum-idp/bootstrap_test.go @ unit | - | 49670a09a4f2 |
| SA-IN-SYSORG-1 | The site_admin belongs to the System organization. | go-test | cmd/identuum-idp/bootstrap_test.go @ unit | - | 094c9ac3636b |
| ORG-MOVE-1 | No actor may move a user across organizations. | go-test | internal/service/burndown_rules_test.go @ unit | - | dc07a268184d |
| ORG-LIFECYCLE-1 | Organization lifecycle is infrastructure authority only. | go-test | internal/handlers/identity_admin_batch_test.go @ unit | - | d35704f0cd6c |
| ORG-CREATE-403-1 | An org_user is refused organization creation with 403. | go-test | internal/handlers/identity_admin_batch_test.go @ unit | - | 6769c9a718ef |
| ORG-RESTORE-1 | A soft-deleted organization 404s on read yet remains restorable. | go-test | internal/handlers/identity_admin_batch_test.go @ unit | - | 86d8661015b4 |
| USER-PW-REQUIRED-1 | User creation without a password fails with a clear 4xx. | go-test | internal/service/burndown_rules_test.go @ unit | - | 2515a32f857f |
| USER-RESET-TOKEN-1 | A password reset with a bogus token is refused. | go-test | internal/service/password_reset_service_test.go @ unit | - | 9e846d66c467 |
| USER-VERIFY-TOKEN-1 | Email verification with a bogus token is refused. | go-test | internal/service/email_verification_service_test.go @ unit | - | 001799e39a8b |
| SECRET-ONCE-1 | A client secret is returned exactly once and never re-shown. | go-test | internal/service/oauth_admin_services_test.go @ unit | - | fa646c4eb832 |
| PKCE-S256-1 | Discovery advertises S256 as the only PKCE method. | go-test | internal/api/oauth_discovery_test.go @ unit | - | c937e5e5d461 |
| TOKEN-SPLIT-1 | The token endpoint refuses a user-session refresh token with invalid_grant. | go-test | internal/handlers/token_test.go @ unit | - | 7d116bcf83f6 |
| MFA-BADCODE-1 | A bad TOTP code is refused. | go-test | internal/service/mfa_enrollment_service_test.go @ unit | - | 3b3e9c634b7d |
| CLIENT-SCOPE-1 | An org_admin's client list is bound to their own organization only. | go-test | internal/handlers/clients_org_bound_test.go @ unit | - | dc8743424e1d |
| SECRET-ROTATE-1 | A secret rotation returns the new plaintext exactly once and rotates the stored hash. | go-test | internal/service/oauth_admin_services_test.go @ unit | - | 389e549f5cc3 |
| NO-FATAL-1 | A fatal wiring fault is recorded, never a panic: the process degrades to not-serving. | go-test | internal/service/classc_failsafe_test.go @ unit | - | 4637321cbe12 |
| ROLE-ASSIGN-SCOPE-1 | Role assignment obeys the same tenant authority line as user creation. | go-test | internal/service/org_role_user_tenant_guard_test.go @ unit | - | 4fe2eef85e5b |
| OIDC-STATE-1 | An upstream OIDC login state is single-use; replay is refused. | go-test | internal/service/oidc_callback_service_test.go @ unit | - | 9a61d77ed018 |
| OIDC-JIT-GATE-1 | JIT provisioning refuses a non-allowlisted email domain before any account exists. | go-test | internal/service/oidc_callback_jit_test.go @ unit | - | 6726e50dc6af |
| OIDC-TAKEOVER-1 | Upstream identity matching goes by external id before email; an email change cannot take over another account. | go-test | internal/service/oidc_callback_jit_test.go @ unit | - | 182ed2bb8666 |
| RG3 | The DB refuses System-org rename, slug and id changes. | - | NONE | blocked: 0027 trigger guards; no teeth test yet — extend model_update_teeth_test.go | - |
| RG4 | The DB caps live site_admins at one and restricts System-org membership to site_admin. | - | NONE | blocked: 0027 index+CHECK; no teeth test yet | - |
| LEASE-1 | Exactly one instance serves at a time via the DB singleton lease; a lease-less instance answers 503. | - | NONE | blocked: lease tests are DB-backed runtime tests; candidate for the integration profile | - |
| DOMAIN-UNIQUE-1 | Organization domains are globally unique with at most one primary per organization. | - | NONE | blocked: no OSS unit pin located; UI half armed as DOMAINS-PRIMARY-1 | - |
| PKJWT-ALGS-1 | OSS private_key_jwt accepts only the documented assertion algorithms bound to client and audience. | - | NONE | blocked: no single pin located in the sweep | - |
| ORG-DELETE-REVOKE-1 | Deleting an organization revokes its credentials at delete time. | - | NONE | blocked: no unit pin located in the sweep | - |
| SOFTDEL-RESOLVE-1 | A soft-deleted client or identity provider never resolves, even when its organization is live. | - | NONE | blocked: no unit pin located in the sweep | - |
