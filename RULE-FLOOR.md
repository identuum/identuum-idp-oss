FLOOR: 4

| ID | one-sentence rule | enforced-by | check | red-proof | hash |
|---|---|---|---|---|---|
| SETUP-CODE-1 | A fresh appliance prints a one-time setup code and refuses after setup completes | go-test | cmd/identuum-idp/setup_show_code_test.go @ unit | - | 7b9993252c7c |
| RECOVER-1 | recover-site-admin resets only the sentinel-guarded site_admin row | go-test | cmd/identuum-idp/recover_test.go @ unit | - | aaca81397daf |
| LOCKOUT-1 | Lockout answers exactly like a wrong password: invalid_credentials | go-test | internal/handlers/login_risk_unavailable_test.go @ unit | - | 6607b26ad69a |
| LOGIN-PIN-1 | Login identity is site_admin@system.local; contact_email never logs in | go-test | internal/setup/rg15_login_identity_test.go @ unit | - | e656142e21f9 |
