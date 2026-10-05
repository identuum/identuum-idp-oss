package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// FUNC-M10 (audits/oss-functionality-2026-10-05.md): `make openid-conformance`
// stopped at provisioning — conformance/provision.mjs set the tenant's
// mfa_policy as the site_admin (403 forbidden_field since D-029) and created
// its test user without saying it need not change the password (401
// password_change_required at the self-check since D-017) — and it echoed
// refusal bodies, a pending session id among them, into the log. The whole
// harness runs in Part B of a release; this pins the provisioner's two calls
// and the redaction where a unit test can reach them.
func TestConformanceProvisioner_FollowsTheSignInRulesAndEchoesNoBody(t *testing.T) {
	repo, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(repo, "conformance", "provision.mjs"))
	if err != nil {
		t.Fatal(err)
	}
	prov := string(raw)
	var policyLine, userCreate string
	for _, l := range strings.Split(prov, "\n") {
		if strings.Contains(l, `mfa_policy: "optional"`) {
			policyLine = l
		}
	}
	if i := strings.Index(prov, `"/api/v1/users", {`); i >= 0 {
		userCreate = prov[i:min(len(prov), i+300)]
	}
	if !strings.Contains(policyLine, "oaToken") || strings.Contains(policyLine, "saToken") {
		t.Errorf("the mfa_policy PUT is not sent as the organization's org_admin (D-029): %q", strings.TrimSpace(policyLine))
	}
	if !strings.Contains(userCreate, "must_change_password: false") {
		t.Error("the test user is created without must_change_password: false (D-017): the suite's browser sign-in would be asked to change it")
	}
	for _, echo := range []string{"JSON.stringify(r.json", "JSON.stringify(check.json"} {
		if strings.Contains(prov, echo) {
			t.Errorf("provision.mjs still echoes a response body (%s)", echo)
		}
	}

	// run.sh masks secret classes in what it prints on a red run.
	cmd := exec.Command("bash", "-c", `source <(sed -n '/^redact() {/,/^}/p' conformance/run.sh); printf '%s' "$1" | redact`, "_",
		`/cb?code=c0de&state=st4te {"access_token":"t0k","session_id":"s1d"} eyJhbGci.eyJzdWIi.c2ln`)
	cmd.Dir = repo
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("run.sh redact: %v %s", err, out)
	}
	for _, secret := range []string{"c0de", "st4te", "t0k", "s1d", "eyJhbGci"} {
		if strings.Contains(string(out), secret) {
			t.Errorf("run.sh redact let %q through: %s", secret, out)
		}
	}
}
