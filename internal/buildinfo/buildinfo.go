// Package buildinfo carries link-time build provenance.
//
// THE-THREE-THAT-MUST-NOT-REPEAT (2026-08-26), item 1: a dev image built
// at 13:43 served an evening of clicks against a fix that landed at
// 15:33, and nothing said so. The running process must ANNOUNCE the
// commit it was built from (GET /system/info, the version subcommand),
// and the dev smoke REFUSES when that differs from the working tree.
package buildinfo

// Commit is the git commit the binary was built from, stamped at build
// time via
//
//	-ldflags "-X github.com/identuum/identuum-idp-oss/internal/buildinfo.Commit=<sha>[-dirty]"
//
// (make build and deployment/Dockerfile.local both stamp it; the
// Makefile appends "-dirty" when the tree had uncommitted changes).
// "unknown" means an UNSTAMPED build — the dev smoke refuses that too,
// because an unprovenanced binary is exactly the stale-binary hazard.
var Commit = "unknown"
