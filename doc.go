// Package identuumidposs is the Starter-tier identity provider module.
//
// This module carries the Starter-tier OAuth 2.1 / OIDC authorization server
// extracted from the identuum-idp monolith. Phase 2 physical relocation is
// complete: the OSS core (auth, internal/{api,audit,auth,crypto,
// domain,features,handlers,infra,licenseprovider,mappers,metrics,mw,postgres,
// repository,server,service,startup,tlscert,utils}, logger, migrations, mw,
// ratelimit, tools, types) ships here as a standalone Go module. Phase 3
// offline OpenID structural conformance passed 2026-06-01.
//
// The production runtime remains the monolith at github.com/identuum/identuum-idp;
// identuum-idp will be retired once identuum-idp-oss and identuum-idp-ce are
// both stable.
//
// Boundary invariants:
//
//   - identuum-idp-oss MUST NOT import identuum-idp-ce (invariant I3).
//   - identuum-idp-oss MUST NOT import identuum-idp/internal (monolith private tree).
//   - identuum-idp-oss MUST NOT import identuum-ag, identuum-ui, or auth-service.
//   - No go.work at the workspace root.
//   - No replace directives in go.mod.
package identuumidposs
