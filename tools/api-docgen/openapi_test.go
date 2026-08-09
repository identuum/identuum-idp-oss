package main

import (
	"bytes"
	"sort"
	"testing"

	"gopkg.in/yaml.v3"
)

// openAPIDocForTest is the minimal shape TestOpenAPI_StructurallyValid
// decodes into. It intentionally models only the top-level fields the
// test asserts on — not a full OpenAPI 3 schema — since this test
// checks structural validity of the emitter's OWN output, not
// third-party spec conformance.
type openAPIDocForTest struct {
	OpenAPI string                                 `yaml:"openapi"`
	Info    map[string]any                         `yaml:"info"`
	Paths   map[string]map[string]openAPIOpForTest `yaml:"paths"`
}

type openAPIOpForTest struct {
	OperationID string `yaml:"operationId"`
	Summary     string `yaml:"summary"`
}

// TestOpenAPI_StructurallyValid pins that --format=openapi produces a
// document that parses as YAML and carries the required OpenAPI 3
// top-level shape: a non-empty `openapi` version string, a non-empty
// `info` object, and a `paths` object where every operation under
// every path has both an HTTP method key and a non-empty
// operationId — the two fields every OpenAPI 3 consumer needs to
// resolve an operation unambiguously.
func TestOpenAPI_StructurallyValid(t *testing.T) {
	endpoints := liveEndpoints(t)
	var buf bytes.Buffer
	if err := generateOpenAPI(&buf, endpoints); err != nil {
		t.Fatalf("generateOpenAPI: %v", err)
	}

	var doc openAPIDocForTest
	if err := yaml.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("emitted openapi output does not parse as YAML: %v", err)
	}
	if doc.OpenAPI == "" {
		t.Fatal("missing top-level `openapi` version field")
	}
	if len(doc.Info) == 0 {
		t.Fatal("missing or empty top-level `info` object")
	}
	if len(doc.Paths) == 0 {
		t.Fatal("`paths` object is empty")
	}
	validMethods := map[string]bool{"get": true, "put": true, "post": true, "delete": true, "patch": true, "options": true, "head": true, "trace": true}
	for path, ops := range doc.Paths {
		if len(ops) == 0 {
			t.Errorf("path %q has no operations", path)
			continue
		}
		for method, op := range ops {
			if !validMethods[method] {
				t.Errorf("path %q has unrecognized method key %q", path, method)
			}
			if op.OperationID == "" {
				t.Errorf("path %q method %q missing operationId", path, method)
			}
		}
	}
}

// TestOpenAPI_RouteParityWithGolden pins that the openapi emitter
// covers the SAME total route count as the YAML golden fixture (131
// endpoints) — every (path, method) pair the YAML emitter records
// also appears as exactly one operation in the OpenAPI document, and
// vice versa. This catches an emitter bug that silently drops or
// double-counts a route during the gin ":name" -> "{name}" path
// translation or the per-path operation grouping.
func TestOpenAPI_RouteParityWithGolden(t *testing.T) {
	endpoints := liveEndpoints(t)

	var yamlBuf bytes.Buffer
	if err := generate(&yamlBuf, endpoints); err != nil {
		t.Fatalf("generate (yaml): %v", err)
	}
	wantCount := len(endpoints)

	var oaBuf bytes.Buffer
	if err := generateOpenAPI(&oaBuf, endpoints); err != nil {
		t.Fatalf("generateOpenAPI: %v", err)
	}
	var doc openAPIDocForTest
	if err := yaml.Unmarshal(oaBuf.Bytes(), &doc); err != nil {
		t.Fatalf("unmarshal openapi output: %v", err)
	}
	gotCount := 0
	for _, ops := range doc.Paths {
		gotCount += len(ops)
	}
	if gotCount != wantCount {
		t.Fatalf("openapi operation count = %d, want %d (== len(endpoints), the same set the YAML golden covers)", gotCount, wantCount)
	}

	// Every operationId present in the YAML endpoint set must appear
	// exactly once as an operation.operationId in the OpenAPI doc —
	// operationId is the record's stable ID (endpoint.go), so this
	// also confirms no route was silently re-keyed onto a different
	// path/method during translation.
	wantIDs := make(map[string]bool, len(endpoints))
	for _, e := range endpoints {
		wantIDs[e.ID] = true
	}
	gotIDs := make(map[string]bool, gotCount)
	for _, ops := range doc.Paths {
		for _, op := range ops {
			gotIDs[op.OperationID] = true
		}
	}
	for id := range wantIDs {
		if !gotIDs[id] {
			t.Errorf("endpoint id %q missing from openapi output", id)
		}
	}
	for id := range gotIDs {
		if !wantIDs[id] {
			t.Errorf("openapi output has unexpected operationId %q not in the endpoint set", id)
		}
	}
}

// TestOpenAPI_Deterministic pins that two consecutive
// generateOpenAPI calls on the same input produce byte-identical
// output — the same determinism invariant TestGenerateIsDeterministic
// pins for the YAML emitter.
func TestOpenAPI_Deterministic(t *testing.T) {
	endpoints := liveEndpoints(t)
	var a, b bytes.Buffer
	if err := generateOpenAPI(&a, endpoints); err != nil {
		t.Fatalf("generateOpenAPI #1: %v", err)
	}
	if err := generateOpenAPI(&b, endpoints); err != nil {
		t.Fatalf("generateOpenAPI #2: %v", err)
	}
	if !bytes.Equal(a.Bytes(), b.Bytes()) {
		t.Fatalf("generateOpenAPI not deterministic: first %d bytes, second %d bytes", a.Len(), b.Len())
	}
}

// TestOpenAPI_NoFabricatedRequestBodySchemas pins the "do not invent
// field schemas" constraint: every components.schemas entry emitted
// is a bare `type: object` placeholder (no `properties` key), proving
// the emitter never synthesizes field-level shape data the Endpoint
// record does not carry.
func TestOpenAPI_NoFabricatedRequestBodySchemas(t *testing.T) {
	endpoints := liveEndpoints(t)
	var buf bytes.Buffer
	if err := generateOpenAPI(&buf, endpoints); err != nil {
		t.Fatalf("generateOpenAPI: %v", err)
	}
	var doc struct {
		Components struct {
			Schemas map[string]map[string]any `yaml:"schemas"`
		} `yaml:"components"`
	}
	if err := yaml.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(doc.Components.Schemas) == 0 {
		t.Fatal("expected at least one components.schemas entry (endpoints carry response_schema records)")
	}
	for name, schema := range doc.Components.Schemas {
		if _, ok := schema["properties"]; ok {
			t.Errorf("component %q has fabricated `properties` — the emitter must not invent field-level schemas", name)
		}
		if schema["type"] != "object" {
			t.Errorf("component %q type = %v, want a bare \"object\" placeholder", name, schema["type"])
		}
	}
}

// oaResponsesDoc decodes just enough of the emitted spec to inspect,
// per operation, the success-response status KEYS and whether each
// carries a content block — the two facts the P2-7 status tests assert.
type oaResponsesDoc struct {
	Paths      map[string]map[string]oaOpResponses `yaml:"paths"`
	Components struct {
		SecuritySchemes map[string]map[string]any `yaml:"securitySchemes"`
	} `yaml:"components"`
}

type oaOpResponses struct {
	OperationID string                    `yaml:"operationId"`
	Responses   map[string]map[string]any `yaml:"responses"`
}

func emitOpenAPIDoc(t *testing.T) oaResponsesDoc {
	t.Helper()
	endpoints := liveEndpoints(t)
	var buf bytes.Buffer
	if err := generateOpenAPI(&buf, endpoints); err != nil {
		t.Fatalf("generateOpenAPI: %v", err)
	}
	var doc oaResponsesDoc
	if err := yaml.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("unmarshal openapi output: %v", err)
	}
	return doc
}

// TestOpenAPI_CreateEmits201 pins the core P2-7 fix: a resource-create
// route (POST /api/v1/api-resources → HandleCreateAPIResource, whose
// terminal success write is c.JSON(http.StatusCreated, …)) surfaces its
// success response under the "201" key — NOT the formerly-hardcoded
// "200" — and that 201 response carries a JSON content block.
//
// TEETH: delete the `// docgen:status=201` annotation above the
// api-resources POST registration (or the SuccessStatus threading in
// openapi.go) and the operation falls back to "200"; this test then
// fails on the missing "201" key.
func TestOpenAPI_CreateEmits201(t *testing.T) {
	doc := emitOpenAPIDoc(t)
	op, ok := doc.Paths["/api/v1/api-resources"]["post"]
	if !ok {
		t.Fatal("POST /api/v1/api-resources missing from openapi output")
	}
	if _, has201 := op.Responses["201"]; !has201 {
		t.Fatalf("POST /api/v1/api-resources success response keys = %v, want a \"201\" (create returns 201, not a hardcoded 200)", responseKeys(op.Responses))
	}
	if _, has200 := op.Responses["200"]; has200 {
		t.Errorf("POST /api/v1/api-resources must not also carry a \"200\" success key (the hardcoded-200 bug)")
	}
	if _, hasContent := op.Responses["201"]["content"]; !hasContent {
		t.Errorf("the \"201\" response should carry a content block (the create returns a JSON body)")
	}
}

// TestOpenAPI_NoContentEmits204WithoutBody pins that a no-content route
// (POST /api/v1/auth/logout → HandleLogout, whose terminal success write
// is c.Status(http.StatusNoContent)) surfaces its success under "204"
// and — because a 204 carries no body — emits NO content block for it.
//
// TEETH: delete the `// docgen:status=204` annotation above the logout
// registration and the operation falls back to "200"; this test then
// fails on the missing "204" key.
func TestOpenAPI_NoContentEmits204WithoutBody(t *testing.T) {
	doc := emitOpenAPIDoc(t)
	op, ok := doc.Paths["/api/v1/auth/logout"]["post"]
	if !ok {
		t.Fatal("POST /api/v1/auth/logout missing from openapi output")
	}
	resp204, has204 := op.Responses["204"]
	if !has204 {
		t.Fatalf("POST /api/v1/auth/logout success response keys = %v, want a \"204\" (no-content success)", responseKeys(op.Responses))
	}
	if _, hasContent := resp204["content"]; hasContent {
		t.Errorf("a \"204\" response must NOT carry a content block (204 has no body)")
	}
	if _, has200 := op.Responses["200"]; has200 {
		t.Errorf("POST /api/v1/auth/logout must not also carry a \"200\" success key")
	}
}

// TestOpenAPI_CookieAuthUsesRealCookieName pins that the cookieAuth
// security scheme advertises the ACTUAL runtime session-cookie name —
// `identuum_session` (internal/service/cookie_session_service.go:
// browserSessionCookieName) — not the placeholder `session` a consumer
// would otherwise wire into an SDK and never authenticate with.
//
// TEETH: revert the cookieAuth `name` back to "session" in openapi.go
// and this test fails.
func TestOpenAPI_CookieAuthUsesRealCookieName(t *testing.T) {
	doc := emitOpenAPIDoc(t)
	cookie, ok := doc.Components.SecuritySchemes["cookieAuth"]
	if !ok {
		t.Fatal("components.securitySchemes.cookieAuth missing from openapi output")
	}
	if got := cookie["name"]; got != "identuum_session" {
		t.Fatalf("cookieAuth.name = %v, want \"identuum_session\" (the real runtime cookie, not the \"session\" placeholder)", got)
	}
}

// responseKeys returns the sorted status keys of a responses map for
// readable failure messages.
func responseKeys(resp map[string]map[string]any) []string {
	out := make([]string, 0, len(resp))
	for k := range resp {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// TestOpenAPI_RejectsFormatButRunAcceptsOpenAPI is a narrow CLI-level
// pin: --format=openapi must be ACCEPTED (unlike --format=json, which
// TestRun_RejectsUnsupportedFormat in docgen_test.go pins as still
// rejected).
func TestOpenAPI_RunAcceptsOpenAPIFormat(t *testing.T) {
	var out, errBuf bytes.Buffer
	if code := run([]string{"--dry-run", "--format=openapi"}, &out, &errBuf); code != 0 {
		t.Fatalf("--format=openapi should succeed; exit=%d stderr=%s", code, errBuf.String())
	}
	if !bytes.Contains(out.Bytes(), []byte("openapi:")) {
		t.Fatalf("--format=openapi output missing `openapi:` field; got %d bytes", out.Len())
	}
}
