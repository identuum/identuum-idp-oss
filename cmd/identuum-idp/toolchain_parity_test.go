package main

// GO-TOOLCHAIN-SKEW-1 / TOOLCHAIN-PARITY-1. The image builder and go.mod must
// name the SAME Go version, digest-pinned.
//
// Why this exists: the v0.3.4 image was built by golang:1.26.5-bookworm while
// the owner host built and scanned with go1.26.6. Every host-side gate
// (govulncheck, grype on the host binary) was green, but the IMAGE carried the
// 1.26.5 stdlib — 8 HIGH CVEs — and the publish workflow's Trivy gate stopped
// it (run 32392773901; nothing was published). Host/image toolchain skew is
// invisible to every host-side scan by construction, so the parity is pinned
// here, where both sides can be read.

import (
	"os"
	"regexp"
	"testing"
)

// builderGoVersionRe extracts the version from the digest-pinned builder line:
//
//	FROM golang:<version>-bookworm@sha256:<digest> AS builder
//
// The digest pin is part of the match on purpose: an unpinned builder tag is
// its own regression (reproducibility), not just a skew risk.
var builderGoVersionRe = regexp.MustCompile(`(?m)^FROM golang:(\d+\.\d+\.\d+)-bookworm@sha256:[0-9a-f]{64} AS builder$`)

// goModGoDirectiveRe extracts go.mod's `go` directive.
var goModGoDirectiveRe = regexp.MustCompile(`(?m)^go (\d+\.\d+\.\d+)$`)

// RULE: TOOLCHAIN-PARITY-1
func TestToolchainParity_DockerfileBuilderEqualsGoModDirective(t *testing.T) {
	dockerfile := readDockerfile(t) // ../../deployment/Dockerfile.local

	m := builderGoVersionRe.FindStringSubmatch(directivesOnly(dockerfile))
	if m == nil {
		t.Fatal("Dockerfile.local must contain a digest-pinned `FROM golang:<x.y.z>-bookworm@sha256:<64 hex> AS builder` line " +
			"(unpinned or renamed builder — fix the Dockerfile or update this pin)")
	}
	builderVersion := m[1]

	rawGoMod, err := os.ReadFile("../../go.mod")
	if err != nil {
		t.Fatalf("read go.mod: %v", err)
	}
	gm := goModGoDirectiveRe.FindStringSubmatch(string(rawGoMod))
	if gm == nil {
		t.Fatal("go.mod must carry a full `go <x.y.z>` directive")
	}
	goModVersion := gm[1]

	if builderVersion != goModVersion {
		t.Fatalf("HOST/IMAGE TOOLCHAIN SKEW: Dockerfile builder pins golang %s while go.mod says go %s. "+
			"They MUST be equal — the side that lags ships a stale stdlib that no host-side scan can see "+
			"(GO-TOOLCHAIN-SKEW-1: 8 HIGH stdlib CVEs reached the v0.3.4 image this way). "+
			"Bump BOTH: the Dockerfile FROM line (new digest via `docker buildx imagetools inspect`) and go.mod.",
			builderVersion, goModVersion)
	}
}
