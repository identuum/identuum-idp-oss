package handlers

// WIRE-CONTRACT-HEALTH-1 — the GET /api/v1/health/details JSON key set is
// pinned EXACTLY (THE-HEALTH-DETAILS). The owner ruling makes Runtime info an
// OSS feature: OSS serves the fields it truly has, and fields OSS cannot know
// (Redis, an audit queue depth) are ABSENT (pointer + omitempty), never
// zero-faked. The UI-side twin pins that getSystemInfo reads only these keys
// and renders absence as "unknown". This pin also asserts NOLEAK: the body
// carries no DSN, key material, or session material.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

var (
	// Top-level systemHealthResponse.
	wireHealthKeysAlways    = []string{"status", "version"}
	wireHealthKeysOmitEmpty = []string{"audit_system", "database", "redis"}
)

func healthMarshaledKeys(t *testing.T, raw []byte) []string {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// RULE: WIRE-CONTRACT-HEALTH-1
func TestWireContractHealth_JSONKeySetIsPinned(t *testing.T) {
	// 1. STRUCT pin by reflection: the top-level tag names + omitempty flags
	//    equal the contract exactly. status/version always; database,
	//    audit_system, redis omitempty.
	var gotAlways, gotOmit []string
	rt := reflect.TypeOf(systemHealthResponse{})
	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		name, opts, _ := strings.Cut(f.Tag.Get("json"), ",")
		if name == "" || name == "-" {
			t.Fatalf("field %s: every systemHealthResponse field must carry an explicit json name", f.Name)
		}
		if strings.Contains(opts, "omitempty") {
			gotOmit = append(gotOmit, name)
		} else {
			gotAlways = append(gotAlways, name)
		}
	}
	sort.Strings(gotAlways)
	sort.Strings(gotOmit)
	if !reflect.DeepEqual(gotAlways, wireHealthKeysAlways) {
		t.Fatalf("always-emitted key set drifted:\n got  %v\n want %v", gotAlways, wireHealthKeysAlways)
	}
	if !reflect.DeepEqual(gotOmit, wireHealthKeysOmitEmpty) {
		t.Fatalf("omitempty key set drifted:\n got  %v\n want %v", gotOmit, wireHealthKeysOmitEmpty)
	}

	// audit_system: status always, queue_depth omitempty (OSS has no queue).
	var auditOmit []string
	rta := reflect.TypeOf(systemAuditHealth{})
	for i := 0; i < rta.NumField(); i++ {
		name, opts, _ := strings.Cut(rta.Field(i).Tag.Get("json"), ",")
		if strings.Contains(opts, "omitempty") {
			auditOmit = append(auditOmit, name)
		}
	}
	if !reflect.DeepEqual(auditOmit, []string{"queue_depth"}) {
		t.Fatalf("audit_system.queue_depth must be omitempty (OSS reports no queue); got omit=%v", auditOmit)
	}

	// 2. The FULL OSS shape from the handler: DB pinger wired, audit wired,
	//    no redis. Keys are EXACTLY status+version+database+audit_system;
	//    database carries only {status}; audit_system carries only {status}
	//    (NO queue_depth); redis is ABSENT.
	gin.SetMode(gin.TestMode)
	body := invokeHealth(t, SystemHealthDeps{
		Version:    "identuum-idp-oss test",
		DBPinger:   func(context.Context) error { return nil },
		AuditWired: true,
	})
	if got, want := healthMarshaledKeys(t, body), []string{"audit_system", "database", "status", "version"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("OSS-shape key set drifted:\n got  %v\n want %v", got, want)
	}
	var full struct {
		Database    map[string]any `json:"database"`
		AuditSystem map[string]any `json:"audit_system"`
	}
	if err := json.Unmarshal(body, &full); err != nil {
		t.Fatalf("unmarshal full: %v", err)
	}
	if got := sortedKeysOf(full.Database); !reflect.DeepEqual(got, []string{"status"}) {
		t.Fatalf("database keys drifted: got %v want [status]", got)
	}
	if got := sortedKeysOf(full.AuditSystem); !reflect.DeepEqual(got, []string{"status"}) {
		t.Fatalf("audit_system must carry status only (queue_depth absent on OSS): got %v", got)
	}
	// PREMISE (non-emptiness): the absence checks below — no "redis", no
	// leaked material — pass vacuously against an empty body. Prove there
	// is a body to search first.
	if len(body) == 0 {
		t.Fatal("PREMISE broken: empty health body — absence checks below would be vacuous")
	}
	if strings.Contains(string(body), "redis") {
		t.Fatalf("redis must be ABSENT on OSS (no Redis dependency); body=%s", body)
	}

	// 3. The MINIMAL shape: no DB pinger, no audit. database + audit_system
	//    VANISH; only status+version remain. Absence is never zero-faked.
	minBody := invokeHealth(t, SystemHealthDeps{Version: "v"})
	if got := healthMarshaledKeys(t, minBody); !reflect.DeepEqual(got, wireHealthKeysAlways) {
		t.Fatalf("minimal key set drifted:\n got  %v\n want %v", got, wireHealthKeysAlways)
	}

	// 4. NOLEAK: no DSN, key material, or session material in any shape.
	for _, forbidden := range []string{"://", "password", "secret", "private_key", "token", "cookie", "session", "dsn"} {
		if strings.Contains(strings.ToLower(string(body)), forbidden) {
			t.Fatalf("health/details body leaked %q: %s", forbidden, body)
		}
	}
	t.Logf("EVIDENCE health wire contract: %d always + %d omitempty keys pinned; redis + queue_depth absent on OSS",
		len(wireHealthKeysAlways), len(wireHealthKeysOmitEmpty))
}

func sortedKeysOf(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// invokeHealth drives the handler function directly (bypassing the site_admin
// route guard, which is not the contract under test here) and returns the JSON
// body.
func invokeHealth(t *testing.T, deps SystemHealthDeps) []byte {
	t.Helper()
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/health/details", nil)
	handleSystemHealthDetails(deps)(c)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	return w.Body.Bytes()
}
