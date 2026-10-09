package runtime_test

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/identuum/identuum-idp-oss/pkg/extension"
	"github.com/identuum/identuum-idp-oss/pkg/runtime"
)

type quotaCeiling int64

func (c quotaCeiling) Ceiling(context.Context, extension.QuotaFacts) (int64, error) {
	return int64(c), nil
}

type snapshot bool

func (s snapshot) Snapshot(context.Context) (extension.EntitlementSnapshot, error) {
	return extension.EntitlementSnapshot{Available: bool(s)}, nil
}

// OSS-SEAM-5 through the runtime: Options.Quotas bounds API resource create
// with 409 quota_exceeded, and an unavailable snapshot is 403 restricted with
// no row written. The rig seeds one API resource in the organization.
func TestQuota_RuntimeAnswersQuotaExceededAndRestricted(t *testing.T) {
	rig := seedResourceRig(t, "quota")
	count := func() int {
		var n int
		if err := rig.db.QueryRow(`SELECT count(*) FROM api_resources WHERE org_id = $1::uuid`, rig.orgA).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	// create answers the status and, for a refusal, its body; a created
	// resource's body carries its secret and is never returned.
	create := func(aud string) (int, string) {
		resp := rig.do(t, http.MethodPost, "/api/v1/api-resources", rig.adminA, `{"name":"q","audience":"`+aud+`"}`)
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode < 400 {
			return resp.StatusCode, "<created>"
		}
		return resp.StatusCode, strings.TrimSpace(string(b))
	}
	startResourceRig(t, rig, runtime.Options{Entitlements: snapshot(true), Quotas: quotaCeiling(2)})
	if st, _ := create("https://q1.api.test"); st != http.StatusCreated {
		t.Fatalf("the second resource under a ceiling of 2: %d; want 201", st)
	}
	if st, body := create("https://q2.api.test"); st != http.StatusConflict || body != `{"error":"quota_exceeded"}` {
		t.Fatalf("a third resource: %d %s; want 409 quota_exceeded", st, body)
	}
	startResourceRig(t, rig, runtime.Options{Entitlements: snapshot(false), Quotas: quotaCeiling(100)})
	if st, body := create("https://q3.api.test"); st != http.StatusForbidden || body != `{"error":"restricted"}` {
		t.Fatalf("an unavailable snapshot: %d %s; want 403 restricted", st, body)
	}
	if n := count(); n != 2 {
		t.Fatalf("the organization holds %d API resources; want 2", n)
	}
}
