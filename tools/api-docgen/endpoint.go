// Package main implements the IDP OSS API docs-as-data generator
// (Phase P1 — endpoints only).
//
// The generator is deterministic, dependency-light, and operates ONLY
// on a Go-source registry of endpoint metadata. It does NOT read the
// Go AST at runtime in this phase; AST-based inference is deferred to
// P2 (schemas) and P3 (CE extractor) per
// identuum-idp/docs/open-core/IDP_API_DOCGEN_BASELINE_ALL_SURFACES.md.
//
// The generator must NOT depend on Hugo or any MCP/gograph service at
// runtime. It writes plain YAML (zero new module dependencies).
package main

// Endpoint is a single canonical record describing one HTTP route
// exposed by identuum-idp-oss. Fields are intentionally narrow for
// P1; later phases extend the schema (request/response struct links,
// errors, filters, etc.) per the baseline.
type Endpoint struct {
	// ID is a stable identifier of the form "<module>.<surface>.<verb>".
	// Two generator runs MUST produce the same ID for the same route.
	ID string

	// Module is the Go module that owns the route. For P1 this is
	// always "identuum-idp-oss".
	Module string

	// Surface is a coarse grouping name (e.g. "keys", "users",
	// "oauth", "oidc", "auth", "top-level"). Used for sort order and
	// docs navigation. Free-form short string; lowercase.
	Surface string

	// Method is the HTTP method (uppercase: GET, POST, PUT, DELETE,
	// PATCH). Top-level routes use the same convention.
	Method string

	// Path is the canonical full URL path including the group prefix
	// (e.g. "/api/v1/keys/generate"). Path params use gin's ":name"
	// form for OSS records — translation to the docs site's preferred
	// "{name}" form happens at docs-render time, not here.
	Path string

	// Handler is the Go symbol name (without package) that serves the
	// request — e.g. "HandleGenerateSigningKey".
	Handler string

	// Registrar is the Register*Routes function that wires this route
	// (e.g. "RegisterKeysRoutes"). Empty for top-level routes
	// registered directly on the router in internal/api/router.go.
	Registrar string

	// Summary is a one-line factual description of the endpoint.
	// Sourced from the handler's Go doc comment where safely
	// available; otherwise concise metadata text. Future phases will
	// extract this automatically via doc comments + docgen tags.
	Summary string

	// Tier is the deployment tier classification:
	//   "oss"                                    — OSS core
	//   "oss-feature-gated:<feature>"            — code lives in OSS,
	//                                              route mounts only when
	//                                              the named feature is on
	//   "unknown"                                — not classified yet
	Tier string

	// Auth is the authentication method required to call the route:
	//   "public"        — no authentication
	//   "session"       — browser session cookie
	//   "bearer"        — Authorization: Bearer <JWT>
	//   "site_admin"    — site-admin principal
	//   "org_admin"     — org-admin principal scoped to the relevant org
	//   "oauth_client"  — OAuth 2.1 client authentication
	//   "unknown"       — not classified yet
	Auth string

	// RequestSchema is the ID of the request-body schema record in
	// api/schemas.yaml. Empty in P1 (schemas not yet extracted).
	RequestSchema string

	// ResponseSchema is the ID of the response-body schema record in
	// api/schemas.yaml. Empty in P1.
	ResponseSchema string

	// SuccessStatus is the HTTP status code the handler writes on its
	// terminal SUCCESS path, as a 3-digit string ("200", "201", "204",
	// …). Sourced from the source-local `// docgen:status=<NNN>`
	// annotation; DEFAULTS to "200" when the annotation is absent (the
	// overwhelming common case). The OpenAPI emitter uses this as the
	// success-response status key so generated SDKs read the real code
	// (a create returns 201, a no-content delete 204, …) instead of a
	// hardcoded 200. Handlers with more than one success code are left
	// unannotated (default 200) and carry a `// docgen:notes` line
	// explaining why — the generator never guesses a status from the
	// HTTP method.
	SuccessStatus string

	// SourcePackage is the Go import path of the handler's package.
	// Used for traceability without leaking absolute filesystem paths.
	SourcePackage string

	// SourceSymbol is the fully-qualified handler symbol identifier
	// for IDE / cross-reference navigation. Currently equals Handler
	// in P1; later phases may include receiver/type info for methods.
	SourceSymbol string

	// Deferred is true when the route is registered as a "deferred"
	// placeholder in OSS (e.g. delegated to a commercial service that
	// has not been relocated). Deferred routes typically return 501
	// or a structured "not implemented" envelope.
	Deferred bool

	// FeatureGate is the feature-flag key the docs site should
	// associate with the route. Sourced from the source-local
	// `// docgen:feature_gate=<key>` annotation. Empty when the
	// annotation is absent.
	//
	// In OSS the key is documentation metadata only — the OSS route
	// is reachable regardless of the gate (the OSS
	// StarterFeatureGate does not enforce keys it does not own). In
	// CE the same key is the runtime entitlement check enforced via
	// mw.RequireFeature. See internal/features/constants.go for the
	// authoritative meaning of each key.
	FeatureGate string
}

// moduleName is the constant module identifier used in every record.
const moduleName = "identuum-idp-oss"

// handlersPackage is the canonical Go import path for the OSS
// HTTP handler package. Most OSS endpoints resolve to this package.
const handlersPackage = "github.com/identuum/identuum-idp-oss/internal/handlers"

// apiPackage is the canonical Go import path for top-level routes
// registered directly in internal/api/router.go.
const apiPackage = "github.com/identuum/identuum-idp-oss/internal/api"
