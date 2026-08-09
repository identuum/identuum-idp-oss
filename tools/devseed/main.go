// Command devseed seeds a DISPOSABLE development database with a known,
// test-only tenant: one organization, one org_admin, one org_user, and one
// confidential OAuth client with a fixed redirect URI.
//
// WHY IT EXISTS (CONF-3 + the manual-test seed, one implementation):
//
// The conformance suite's four uncovered dimensions — PKCE end-to-end,
// refresh rotation and reuse detection, liveness at token use, and the token
// endpoint's error surface — each need a FULL authorization-code flow, and a
// code flow needs an authenticated END USER, not just an admin bearer. That is
// the "per-engine login seeding" CONF-3 names as its blocker. The same seed is
// what a human needs to hand-test login, and keeping ONE implementation means
// the flows the suite proves and the flows the operator walks cannot drift.
//
// AUTHORITY, AND WHY IT IS NOT A BACK DOOR:
//
// devseed authenticates the way an operator does. It calls the supported
// `recover-site-admin` operator command to set a KNOWN TEST password on the
// site_admin of the dev database, then logs in over PUBLIC HTTP — completing
// first-login TOTP enrolment exactly as the product demands, rather than
// weakening or configuring the requirement away — and creates everything else
// through the PUBLIC admin API. It writes no rows directly, hashes no
// passwords itself, and skips no guard. If a guard would refuse an operator,
// it refuses devseed.
//
// SAFETY:
//
//   - It REFUSES to run without --i-know-this-is-a-dev-database. There is no
//     env-var form of that flag: an accidental export cannot arm it.
//   - It REFUSES any issuer that is not loopback unless --allow-remote is also
//     passed, because "seed known credentials" pointed at a real deployment is
//     an attack, not a convenience.
//   - Every credential it creates is printed to stdout ONCE, on purpose: these
//     are throwaway values for a throwaway database. It never reads, prints or
//     derives anything from dev.env or any operator secret.
package main

import (
	"bytes"
	"encoding/base32"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/identuum/identuum-idp-oss/pkg/totp"
)

// Seeded test credentials. Fixed, not random: a human re-reads MANUAL-TEST.md
// and a test re-runs, and both need the same values every time. These are only
// ever valid in a database someone explicitly declared disposable.
const (
	siteAdminEmail = "site_admin@system.local"
	siteAdminPass  = "DevSeed-SiteAdmin-Passw0rd!"

	orgName   = "DevSeed Organization"
	orgDomain = "devseed.local"

	orgAdminEmail = "devseed-admin@devseed.local"
	orgAdminPass  = "DevSeed-OrgAdmin-Passw0rd!"

	orgUserEmail = "devseed-user@devseed.local"
	orgUserPass  = "DevSeed-OrgUser-Passw0rd!"

	clientName        = "devseed-client"
	clientRedirectURI = "http://127.0.0.1:9999/callback"
	clientScope       = "openid profile email offline_access"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "devseed: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("devseed", flag.ContinueOnError)
	fs.SetOutput(out)
	issuer := fs.String("issuer", "http://127.0.0.1:7113", "base URL of the running OSS IdP to seed against")
	dbURL := fs.String("database-url", "", "Postgres URL passed to `recover-site-admin`. Never printed.")
	binPath := fs.String("bin", "", "path to an already-built identuum-idp binary (default: go run ./cmd/identuum-idp)")
	repoDir := fs.String("repo", ".", "repository root used when building the binary")
	confirm := fs.Bool("i-know-this-is-a-dev-database", false, "REQUIRED. Confirms the target database is disposable.")
	allowRemote := fs.Bool("allow-remote", false, "permit a non-loopback issuer (refused by default)")
	jsonOut := fs.Bool("json", false, "emit the seeded credentials as JSON")
	adminEmail := fs.String("site-admin-email", "", "log in as this EXISTING site_admin instead of "+
		"bootstrapping/recovering the canonical one. For a stack already bootstrapped under another "+
		"address — the conformance harness does exactly that — where the sentinel id is taken and "+
		"`recover-site-admin` (which only knows the canonical address) cannot help.")
	adminPassword := fs.String("site-admin-password", "", "password for --site-admin-email. Required with it.")
	adminBearerFlag := fs.String("site-admin-bearer", "", "use this ALREADY-AUTHENTICATED site_admin bearer "+
		"instead of logging in. For callers that have authenticated already — the conformance harness "+
		"logs in and enrols the admin's TOTP before seeding, and devseed keeps no copy of a secret it "+
		"did not generate, so re-authenticating is impossible and unnecessary.")
	container := fs.String("container", "", "run the operator subcommands INSIDE this docker container "+
		"instead of locally. Required for a compose-run dev stack: the at-rest encryption key lives in a "+
		"file inside the container, and this is how devseed uses it WITHOUT ever reading it out.")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if !*confirm {
		return errors.New("refusing to seed: pass --i-know-this-is-a-dev-database.\n" +
			"devseed OVERWRITES the site_admin password of the target database with a public,\n" +
			"documented test value. That is correct for a dev stack and catastrophic anywhere else,\n" +
			"so the confirmation is a flag with no environment-variable form")
	}
	if err := requireLoopback(*issuer, *allowRemote); err != nil {
		return err
	}
	if strings.TrimSpace(*dbURL) == "" && *container == "" {
		return errors.New("--database-url is required (it is passed to recover-site-admin and never printed). " +
			"With --container the DSN the container already holds is used instead")
	}

	base := strings.TrimRight(*issuer, "/")
	fmt.Fprintf(out, "devseed: seeding %s\n", base)

	useEmail, usePass := siteAdminEmail, siteAdminPass
	if *adminBearerFlag != "" {
		useEmail, usePass = "(supplied bearer)", "(not used)"
	}
	if *adminEmail != "" {
		if *adminPassword == "" {
			return errors.New("--site-admin-email requires --site-admin-password")
		}
		useEmail, usePass = *adminEmail, *adminPassword
		fmt.Fprintln(out, "devseed: using the supplied existing site_admin (no bootstrap/recover)")
	} else if *adminBearerFlag != "" {
		// nothing to bootstrap: the caller is already authenticated.
	} else {
		if err := recoverSiteAdmin(*binPath, *repoDir, *dbURL, *container); err != nil {
			return err
		}
		fmt.Fprintln(out, "devseed: site_admin password reset to the documented test value")
	}

	var bearer, siteAdminTOTP string
	if *adminBearerFlag != "" {
		bearer = *adminBearerFlag
		fmt.Fprintln(out, "devseed: using the supplied site_admin bearer")
	} else {
		var err error
		bearer, siteAdminTOTP, err = login(base, useEmail, usePass)
		if err != nil {
			return fmt.Errorf("site_admin login: %w", err)
		}
		fmt.Fprintln(out, "devseed: site_admin logged in (first-login TOTP enrolment completed as the product demands)")
	}

	orgID, err := ensureOrganization(base, bearer)
	if err != nil {
		return fmt.Errorf("organization: %w", err)
	}
	fmt.Fprintf(out, "devseed: organization %s ready (%s)\n", orgDomain, orgID)

	// The org_admin is created by site_admin under the delegation rule: an
	// organization with no active org_admin may receive exactly one. The
	// org_user is then created BY THE ORG ADMIN, because site_admin creating
	// tenant users is precisely what the authority model forbids.
	orgAdminID, err := ensureUser(base, bearer, orgAdminEmail, orgAdminPass, "org_admin", orgID)
	if err != nil {
		return fmt.Errorf("org_admin: %w", err)
	}
	fmt.Fprintln(out, "devseed: org_admin ready")

	_ = orgAdminID

	// THE AUTHORITY MODEL, walked exactly as it is written.
	//
	// site_admin seeded the organization and its FIRST org_admin — the one
	// tenant write the model permits (SITE-ADMIN-TENANT-WRITE). Everything
	// inside the tenant is the ORG ADMIN's work: it logs in and creates the
	// org_user and the OAuth client with its own role-derived, org-bound
	// session scopes (ORG-ADMIN-SCOPES). A site_admin doing that here would be
	// refused now, and rightly.
	adminBearer, orgAdminTOTP, err := login(base, orgAdminEmail, orgAdminPass)
	if err != nil {
		return fmt.Errorf("org_admin login: %w", err)
	}

	// No organization_id: an org_admin's creates are pinned to its own org,
	// and naming it is at best redundant.
	if _, err := ensureUser(base, adminBearer, orgUserEmail, orgUserPass, "org_user", ""); err != nil {
		return fmt.Errorf("org_user: %w", err)
	}
	fmt.Fprintln(out, "devseed: org_user ready (created BY the org_admin, as the authority model requires)")

	creds, err := ensureClient(base, adminBearer, orgID, useEmail, usePass)
	if err != nil {
		return fmt.Errorf("oauth client: %w", err)
	}
	// TOTP is not optional in this product: a seeded account cannot be logged
	// into BY HAND without its secret, so the seed that creates the account
	// hands the secret over with it. Same rationale as the passwords above —
	// throwaway values, throwaway database.
	creds.SiteAdminTOTP = siteAdminTOTP
	creds.OrgAdminTOTP = orgAdminTOTP
	fmt.Fprintln(out, "devseed: oauth client ready")

	return report(out, *jsonOut, creds)
}

// requireLoopback refuses a non-loopback issuer. Seeding known credentials into
// a reachable deployment is an attack; the flag makes the operator say so.
func requireLoopback(issuer string, allowRemote bool) error {
	u, err := url.Parse(issuer)
	if err != nil {
		return fmt.Errorf("--issuer is not a URL: %w", err)
	}
	host := u.Hostname()
	if host == "localhost" {
		return nil
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return nil
	}
	if allowRemote {
		fmt.Fprintf(os.Stderr, "devseed: WARNING seeding a NON-LOOPBACK issuer (%s) because --allow-remote was passed\n", host)
		return nil
	}
	return fmt.Errorf("refusing to seed non-loopback issuer %q: devseed installs PUBLIC, documented "+
		"credentials, so pointing it at a reachable deployment hands that deployment away. "+
		"Pass --allow-remote only if the target is genuinely disposable", host)
}

func recoverSiteAdmin(binPath, repoDir, dbURL, container string) error {
	// Two supported operator commands, in order, because a dev database can be
	// in either state and NEITHER destroys existing data:
	//
	//   bootstrap           creates site_admin@system.local with the test
	//                       password when that row is absent. It looks up by
	//                       EMAIL, so a stack bootstrapped under some other
	//                       address (dev stacks often are) simply gains the
	//                       canonical row beside it.
	//   recover-site-admin  resets that row's password and MFA when it was
	//                       already there — bootstrap SKIPS an existing row
	//                       rather than rewriting its password, so without
	//                       this step a re-seed would leave the old password
	//                       in place and the login below would fail.
	//
	// bootstrap is allowed to fail: on an already-seeded database it has
	// nothing to do, and recover is the step that must succeed.
	boot := siteAdminCmd(binPath, repoDir, "bootstrap", dbURL, container)
	boot.Env = append(os.Environ(),
		"IDENTUUM_IDP_BOOTSTRAP_EMAIL="+siteAdminEmail,
		"IDENTUUM_IDP_BOOTSTRAP_PASSWORD="+siteAdminPass)
	boot.Stdout, boot.Stderr = io.Discard, io.Discard
	_ = boot.Run()

	cmd := siteAdminCmd(binPath, repoDir, "recover-site-admin", dbURL, container)
	cmd.Env = append(os.Environ(), "IDENTUUM_IDP_RECOVER_SITE_ADMIN_PASSWORD="+siteAdminPass)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	cmd.Stdout = io.Discard
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("recover-site-admin failed: %w\n%s", err, stderr.String())
	}
	return nil
}

func siteAdminCmd(binPath, repoDir, sub, dbURL, container string) *exec.Cmd {
	if container != "" {
		// DIRECT exec, no shell: the runtime image is distroless, so the old
		// `sh -c` wrapper (which loaded the key file into the environment and
		// expanded the container's DB URL into a positional) died with 127 —
		// there is no sh in the image. Both jobs moved into the binary, where
		// they belong: the subcommand falls back to $IDENTUUM_IDP_DATABASE_URL
		// / $IDENTUUM_IDP_OSS_DB when no positional is given, and
		// resolveSigningKeyCipher reads $IDENTUUM_IDP_DATA_DIR/encryption-key
		// when the env carries no key. The secret still never crosses the
		// process boundary: devseed never sees it, never logs it, and no
		// operator secret is read off disk on the host.
		return exec.Command("docker", "exec",
			"-e", "IDENTUUM_IDP_BOOTSTRAP_EMAIL="+siteAdminEmail,
			"-e", "IDENTUUM_IDP_BOOTSTRAP_PASSWORD="+siteAdminPass,
			"-e", "IDENTUUM_IDP_RECOVER_SITE_ADMIN_PASSWORD="+siteAdminPass,
			container, "/app/identuum-idp", sub)
	}
	if binPath != "" {
		return exec.Command(binPath, sub, dbURL)
	}
	cmd := exec.Command("go", "run", "./cmd/identuum-idp", sub, dbURL)
	cmd.Dir = repoDir
	return cmd
}

// login authenticates over public HTTP and completes first-login TOTP
// enrolment when the product demands it, walking the same path an operator
// walks. The TOTP code is computed with pkg/totp — the product's own
// implementation, not a reimplementation.
func login(base, email, password string) (string, string, error) {
	body, _ := json.Marshal(map[string]string{"email": email, "password": password})
	status, raw, err := postJSON(base+"/api/v1/auth/login", "", body)
	if err != nil {
		return "", "", err
	}
	var p struct {
		AccessToken           string `json:"access_token"`
		Token                 string `json:"token"`
		SessionID             string `json:"session_id"`
		MFAEnrollmentRequired bool   `json:"mfa_enrollment_required"`
		MFARequired           bool   `json:"mfa_required"`
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		return "", "", fmt.Errorf("login response is not JSON (status %d): %s", status, truncate(raw))
	}
	if p.MFAEnrollmentRequired {
		if p.SessionID == "" {
			return "", "", errors.New("mfa_enrollment_required with no session_id")
		}
		return enrolMFA(base, p.SessionID)
	}
	if p.MFARequired {
		// The account already has TOTP. devseed generated that secret in an
		// earlier run and deliberately kept no copy of it, so it cannot
		// answer the challenge — and it will not disable MFA to get past its
		// own product's security. Say so, and name the way out.
		return "", "", fmt.Errorf("%s already has TOTP enrolled, and devseed keeps no copy of the "+
			"secret it generated last time. Re-seed from a clean database: `make dev-reset` "+
			"(destroys the dev volume) then `make dev-seed`", email)
	}
	if status < 200 || status >= 300 {
		return "", "", fmt.Errorf("status %d: %s", status, truncate(raw))
	}
	if p.AccessToken != "" {
		return p.AccessToken, "", nil
	}
	if p.Token != "" {
		return p.Token, "", nil
	}
	return "", "", errors.New("login returned no bearer token")
}

func enrolMFA(base, sessionID string) (string, string, error) {
	initBody, _ := json.Marshal(map[string]string{"session_id": sessionID})
	status, raw, err := postJSON(base+"/api/v1/auth/login/mfa/enroll/initiate", "", initBody)
	if err != nil {
		return "", "", err
	}
	if status < 200 || status >= 300 {
		return "", "", fmt.Errorf("mfa enroll initiate → %d: %s", status, truncate(raw))
	}
	var init struct {
		Secret string `json:"secret"`
	}
	if err := json.Unmarshal(raw, &init); err != nil || init.Secret == "" {
		return "", "", fmt.Errorf("mfa enroll initiate returned no secret: %s", truncate(raw))
	}
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).
		DecodeString(strings.ToUpper(strings.TrimSpace(init.Secret)))
	if err != nil {
		return "", "", fmt.Errorf("enrolment secret is not base32: %w", err)
	}
	// RFC 6238 defaults, matching internal/service.defaultTOTPPeriod /
	// defaultTOTPDigits — both unexported, and devseed is deliberately a
	// black-box HTTP client, so it does not import the service package to
	// read them. Drift is not silent: a period change makes enrolment reject
	// this code and the seed fails loudly at the enrol step.
	const totpPeriod, totpDigits = 30, 6
	code := totp.Code(key, uint64(time.Now().UTC().Unix()/totpPeriod), totpDigits)
	doneBody, _ := json.Marshal(map[string]string{"session_id": sessionID, "code": code})
	status, raw, err = postJSON(base+"/api/v1/auth/login/mfa/enroll/complete", "", doneBody)
	if err != nil {
		return "", "", err
	}
	if status < 200 || status >= 300 {
		return "", "", fmt.Errorf("mfa enroll complete → %d: %s", status, truncate(raw))
	}
	var done struct {
		AccessToken string `json:"access_token"`
		Token       string `json:"token"`
	}
	_ = json.Unmarshal(raw, &done)
	if done.AccessToken != "" {
		return done.AccessToken, init.Secret, nil
	}
	if done.Token != "" {
		return done.Token, init.Secret, nil
	}
	return "", "", errors.New("mfa enrolment completed but returned no bearer token")
}

func ensureOrganization(base, bearer string) (string, error) {
	body, _ := json.Marshal(map[string]any{
		"name":   orgName,
		"domain": orgDomain,
		"active": true,
	})
	status, raw, err := postJSON(base+"/api/v1/organizations", bearer, body)
	if err != nil {
		return "", err
	}
	if status >= 200 && status < 300 {
		return extractID(raw)
	}
	// Already seeded: find it rather than failing. Re-running the seed must be
	// safe, or nobody will trust it mid-session.
	if status == http.StatusConflict || status == http.StatusBadRequest {
		if id, lookupErr := findOrganization(base, bearer); lookupErr == nil && id != "" {
			return id, nil
		}
	}
	return "", fmt.Errorf("create organization → %d: %s", status, truncate(raw))
}

func findOrganization(base, bearer string) (string, error) {
	status, raw, err := getJSON(base+"/api/v1/organizations", bearer)
	if err != nil {
		return "", err
	}
	if status < 200 || status >= 300 {
		return "", fmt.Errorf("list organizations → %d", status)
	}
	var envelope struct {
		Data          []map[string]any `json:"data"`
		Organizations []map[string]any `json:"organizations"`
	}
	_ = json.Unmarshal(raw, &envelope)
	rows := envelope.Data
	if len(rows) == 0 {
		rows = envelope.Organizations
	}
	if len(rows) == 0 {
		_ = json.Unmarshal(raw, &rows)
	}
	for _, row := range rows {
		if fmt.Sprint(row["domain"]) == orgDomain {
			return fmt.Sprint(row["id"]), nil
		}
	}
	return "", errors.New("seeded organization not found")
}

func ensureUser(base, bearer, email, password, role, orgID string) (string, error) {
	// organization_id, NOT organization_domain: HandleCreateUser binds
	// `organization_id uuid.UUID`. types.CreateUserRequest documents an
	// OrganizationDomain field, but that is not the struct this endpoint
	// binds — sending the domain leaves the UUID at zero and the create is
	// refused with a bare 400 "invalid request".
	payload := map[string]any{"email": email, "password": password, "role": role}
	if orgID != "" {
		payload["organization_id"] = orgID
	}
	body, _ := json.Marshal(payload)
	status, raw, err := postJSON(base+"/api/v1/users", bearer, body)
	if err != nil {
		return "", err
	}
	switch {
	case status >= 200 && status < 300:
		// A newly created account is UNVERIFIED, and login refuses it with
		// account_unverified. Dev has no SMTP ("email delivery: NOT
		// CONFIGURED"), so the verification mail cannot arrive and the seeded
		// account would be unusable by hand. email_verified is an
		// admin-settable field on PUT /api/v1/users/:id — the supported
		// capability, not a bypass — so the seed uses it. The verification
		// FLOW itself is untouched and is a matrix row of its own.
		id, idErr := extractID(raw)
		if idErr != nil {
			return "", fmt.Errorf("created %s but could not read its id: %w", role, idErr)
		}
		verified := true
		vBody, _ := json.Marshal(map[string]any{"email_verified": verified})
		vStatus, vRaw, vErr := putJSON(base+"/api/v1/users/"+id, bearer, vBody)
		if vErr != nil {
			return "", vErr
		}
		if vStatus < 200 || vStatus >= 300 {
			return "", fmt.Errorf("mark %s verified → %d: %s", role, vStatus, truncate(vRaw))
		}
		return id, nil
	case status == http.StatusConflict:
		return "", nil // already seeded
	default:
		return "", fmt.Errorf("create %s → %d: %s", role, status, truncate(raw))
	}
}

func putJSON(url, bearer string, body []byte) (int, []byte, error) {
	req, err := http.NewRequest(http.MethodPut, url, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	return do(req)
}

type seeded struct {
	Issuer        string `json:"issuer"`
	SiteAdminUser string `json:"site_admin_email"`
	SiteAdminPass string `json:"site_admin_password"`
	OrgDomain     string `json:"organization_domain"`
	OrgAdminUser  string `json:"org_admin_email"`
	OrgAdminPass  string `json:"org_admin_password"`
	OrgUserUser   string `json:"org_user_email"`
	OrgUserPass   string `json:"org_user_password"`
	SiteAdminTOTP string `json:"site_admin_totp_secret"`
	OrgAdminTOTP  string `json:"org_admin_totp_secret"`
	ClientID      string `json:"client_id"`
	ClientSecret  string `json:"client_secret"`
	RedirectURI   string `json:"redirect_uri"`
	Scope         string `json:"scope"`
}

func ensureClient(base, bearer, orgID, siteAdminUser, siteAdminPassword string) (seeded, error) {
	out := seeded{
		Issuer: base, SiteAdminUser: siteAdminUser, SiteAdminPass: siteAdminPassword,
		OrgDomain: orgDomain, OrgAdminUser: orgAdminEmail, OrgAdminPass: orgAdminPass,
		OrgUserUser: orgUserEmail, OrgUserPass: orgUserPass,
		RedirectURI: clientRedirectURI, Scope: clientScope,
	}
	body, _ := json.Marshal(map[string]any{
		"name":                       clientName,
		"redirect_uris":              []string{clientRedirectURI},
		"post_logout_redirect_uris":  []string{clientRedirectURI},
		"scope":                      clientScope,
		"is_public":                  false,
		"token_endpoint_auth_method": "client_secret_basic",
	})
	status, raw, err := postJSON(base+"/api/v1/clients", bearer, body)
	if err != nil {
		return out, err
	}
	if status < 200 || status >= 300 {
		return out, fmt.Errorf("create client → %d: %s", status, truncate(raw))
	}
	// The create response wraps the record: {"client":{...},"client_secret":...}.
	// `data` and a bare top-level object are accepted too so the seed does not
	// break on an envelope change it can already understand.
	type clientBody struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
	}
	var p struct {
		clientBody
		Client clientBody `json:"client"`
		Data   clientBody `json:"data"`
	}
	_ = json.Unmarshal(raw, &p)
	for _, cand := range []clientBody{p.clientBody, p.Client, p.Data} {
		if cand.ClientID != "" {
			out.ClientID = cand.ClientID
			if cand.ClientSecret != "" {
				out.ClientSecret = cand.ClientSecret
			}
			break
		}
	}
	// The secret is commonly returned ONCE, alongside the record rather than
	// inside it — take it from wherever it appeared.
	if out.ClientSecret == "" {
		for _, cand := range []clientBody{p.clientBody, p.Client, p.Data} {
			if cand.ClientSecret != "" {
				out.ClientSecret = cand.ClientSecret
				break
			}
		}
	}
	if out.ClientID == "" {
		return out, fmt.Errorf("create client returned no client_id: %s", truncate(raw))
	}
	return out, nil
}

func report(out io.Writer, asJSON bool, s seeded) error {
	if asJSON {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(s)
	}
	fmt.Fprintf(out, `
SEEDED TEST CREDENTIALS — disposable dev database only
  issuer            %s
  site_admin        %s / %s
    TOTP secret     %s
  organization      %s
  org_admin         %s / %s
    TOTP secret     %s
  org_user          %s / %s
    (no TOTP yet — enrolled on this account's first login)
  client_id         %s
  client_secret     %s
  redirect_uri      %s
  scope             %s
`, s.Issuer, s.SiteAdminUser, s.SiteAdminPass, orNone(s.SiteAdminTOTP), s.OrgDomain,
		s.OrgAdminUser, s.OrgAdminPass, orNone(s.OrgAdminTOTP), s.OrgUserUser, s.OrgUserPass,
		s.ClientID, s.ClientSecret, s.RedirectURI, s.Scope)
	return nil
}

func orNone(s string) string {
	if s == "" {
		return "(already enrolled — devseed kept no copy)"
	}
	return s
}

var httpClient = &http.Client{Timeout: 20 * time.Second}

func postJSON(url, bearer string, body []byte) (int, []byte, error) {
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	return do(req)
}

func getJSON(url, bearer string) (int, []byte, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return 0, nil, err
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	return do(req)
}

func do(req *http.Request) (int, []byte, error) {
	resp, err := httpClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, raw, err
}

func extractID(raw []byte) (string, error) {
	var p struct {
		ID   string `json:"id"`
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		return "", fmt.Errorf("response is not JSON: %s", truncate(raw))
	}
	if p.ID != "" {
		return p.ID, nil
	}
	if p.Data.ID != "" {
		return p.Data.ID, nil
	}
	return "", fmt.Errorf("response carries no id: %s", truncate(raw))
}

func truncate(raw []byte) string {
	s := strings.TrimSpace(string(raw))
	if len(s) > 300 {
		return s[:300] + "…"
	}
	return s
}
