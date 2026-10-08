package runtime_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/pkg/extension"
	"github.com/identuum/identuum-idp-oss/pkg/runtime"
)

// recordingRestriction answers every Check with answer and records the
// Decisions it was given.
type recordingRestriction struct {
	mu     sync.Mutex
	seen   []extension.Decision
	answer func() error
}

func (r *recordingRestriction) Check(_ context.Context, d extension.Decision) error {
	r.mu.Lock()
	r.seen = append(r.seen, d)
	r.mu.Unlock()
	return r.answer()
}

func (r *recordingRestriction) calls() []extension.Decision {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]extension.Decision(nil), r.seen...)
}

func newRestrictedRig(t *testing.T, name string, rs []extension.Restriction) *resourceRig {
	t.Helper()
	rig := seedResourceRig(t, name)
	startResourceRig(t, rig, runtime.Options{Restrictions: rs})
	return rig
}

// call sends one API resource request and returns the status and the JSON
// "error" field of the answer, if any.
func (r *resourceRig) call(t *testing.T, method, path, token, body string) (int, string) {
	t.Helper()
	resp := r.do(t, method, path, token, body)
	defer func() { _ = resp.Body.Close() }()
	var out struct {
		Error string `json:"error"`
	}
	b, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(b, &out)
	return resp.StatusCode, out.Error
}

const createBody = `{"name":"made","audience":"https://made.api.test"}`

// OSS-SEAM-4 proofs 1 and 2: a restriction that allows everything never
// turns an OSS refusal into an allow, never sees a foreign tenant's
// resource, and gives site_admin no tenant authority; it sees each allowed
// write once, after the OSS checks, with the facts OSS resolved.
func TestRestrictions_NeverWidenAnOSSRefusal(t *testing.T) {
	allow := &recordingRestriction{answer: func() error { return nil }}
	rig := newRestrictedRig(t, "allow", []extension.Restriction{allow})
	refusals := []struct {
		name, method, path, token, body string
		status                          int
	}{
		{"base invalid input", http.MethodPost, "/api/v1/api-resources", rig.adminA, `{"name":"","audience":""}`, 400},
		{"org_user is not an admin", http.MethodPost, "/api/v1/api-resources", rig.userA, createBody, 403},
		{"site_admin create", http.MethodPost, "/api/v1/api-resources", rig.siteAdmin, createBody, 403},
		{"site_admin update", http.MethodPut, "/api/v1/api-resources/" + rig.resB, rig.siteAdmin, `{"name":"x"}`, 403},
		{"site_admin delete", http.MethodDelete, "/api/v1/api-resources/" + rig.resB, rig.siteAdmin, "", 403},
		{"tenant A updates B", http.MethodPut, "/api/v1/api-resources/" + rig.resB, rig.adminA, `{"name":"x"}`, 404},
		{"tenant A creates in B", http.MethodPost, "/api/v1/api-resources", rig.adminA,
			`{"organization_id":"` + uuid.NewString() + `","name":"x","audience":"https://x.api.test"}`, 404},
	}
	for _, c := range refusals {
		if got, code := rig.call(t, c.method, c.path, c.token, c.body); got != c.status {
			t.Errorf("%s: answered %d %q; want OSS's %d", c.name, got, code, c.status)
		}
	}
	// Tenant A deleting B's resource deletes nothing, as today, and the
	// restriction never sees it.
	if got, _ := rig.call(t, http.MethodDelete, "/api/v1/api-resources/"+rig.resB, rig.adminA, ""); got != 200 {
		t.Errorf("tenant A deletes B: answered %d; want today's idempotent 200", got)
	}
	var left int
	if err := rig.db.QueryRow(`SELECT count(*) FROM api_resources WHERE id = $1`, rig.resB).Scan(&left); err != nil || left != 1 {
		t.Errorf("tenant B's resource after A's delete: %d row(s), %v; want 1", left, err)
	}
	if n := len(allow.calls()); n != 0 {
		t.Fatalf("the restriction saw %d request(s) OSS refused or a foreign tenant's resource; want 0", n)
	}

	for _, c := range []struct{ method, path, body, op string }{
		{http.MethodPost, "/api/v1/api-resources", createBody, extension.OperationAPIResourceCreate},
		{http.MethodPut, "/api/v1/api-resources/" + rig.resA, `{"name":"renamed"}`, extension.OperationAPIResourceUpdate},
		{http.MethodDelete, "/api/v1/api-resources/" + rig.resA, "", extension.OperationAPIResourceDelete},
	} {
		if got, _ := rig.call(t, c.method, c.path, rig.adminA, c.body); got != 200 && got != 201 {
			t.Fatalf("%s allowed by OSS and the restriction: answered %d", c.op, got)
		}
		calls := allow.calls()
		d := calls[len(calls)-1]
		if d.Operation() != c.op || d.Tenant() != rig.orgA || d.Actor() == "" || d.Target() == "" {
			t.Errorf("%s: the restriction saw operation %q tenant %q actor %q target %q", c.op, d.Operation(), d.Tenant(), d.Actor(), d.Target())
		}
		if c.op != extension.OperationAPIResourceCreate && d.Target() != rig.resA {
			t.Errorf("%s: target %q; want %s", c.op, d.Target(), rig.resA)
		}
	}
	if n := len(allow.calls()); n != 3 {
		t.Fatalf("the restriction saw %d write(s); want the 3 OSS allowed", n)
	}
}

// OSS-SEAM-4 proofs 4 and 5: a restriction that refuses, fails or panics
// denies the write with ruling aa's status and code, and no row changes.
func TestRestrictions_DenialWritesNothing(t *testing.T) {
	cases := []struct {
		name   string
		answer func() error
		status int
		code   string
	}{
		{"restricted", func() error { return &extension.Denial{Code: extension.Restricted} }, 403, "restricted"},
		{"license", func() error { return &extension.Denial{Code: extension.LicenseRequired} }, 403, "license_required"},
		{"quota", func() error { return &extension.Denial{Code: extension.QuotaExceeded} }, 409, "quota_exceeded"},
		{"error", func() error { return errors.New("entitlement store unavailable") }, 403, "restricted"},
		{"panic", func() error { panic("restriction bug") }, 403, "restricted"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &recordingRestriction{answer: tc.answer}
			rig := newRestrictedRig(t, tc.name, []extension.Restriction{r})
			before := rowCounts(t, rig.db)
			for _, c := range []struct{ method, path, body string }{
				{http.MethodPost, "/api/v1/api-resources", createBody},
				{http.MethodPut, "/api/v1/api-resources/" + rig.resA, `{"name":"renamed","active":false}`},
				{http.MethodDelete, "/api/v1/api-resources/" + rig.resA, ""},
			} {
				status, code := rig.call(t, c.method, c.path, rig.adminA, c.body)
				if status != tc.status || code != tc.code {
					t.Errorf("%s %s: answered %d %q; want %d %q", c.method, c.path, status, code, tc.status, tc.code)
				}
			}
			if n := len(r.calls()); n != 3 {
				t.Errorf("the restriction was asked %d time(s); want 3", n)
			}
			if after := rowCounts(t, rig.db); !reflect.DeepEqual(before, after) {
				for n := range after {
					if before[n] != after[n] {
						t.Errorf("table %s changed although every write was denied", n)
					}
				}
			}
		})
	}
}
