package main

// main.go — I/O for toolchain-parity: reads the workflow env and go.mod,
// runs each tool for its own version string, hashes the two vendored files
// CI digest-checks, and prints ONE line. It fixes nothing; it only refuses.

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func main() {
	repo := flag.String("repo", ".", "repository root")
	workflow := flag.String("workflow", ".github/workflows/ci.yml", "workflow whose env declares the pins")
	flag.Parse()

	pins, err := collect(*repo, *workflow)
	if err != nil {
		fmt.Fprintln(os.Stderr, "toolchain-parity: FAIL —", err)
		os.Exit(1)
	}
	_, summary, ok := Decide(pins)
	if !ok {
		fmt.Fprintln(os.Stderr, summary)
		os.Exit(1)
	}
	fmt.Println(summary)
}

// toolSpec is one version comparison: the env key that declares it and the
// command that reports what is installed.
type toolSpec struct {
	tool   string
	envKey string
	kind   string
	cmd    []string
}

// The commands mirror `make tool-versions` — the same invocations whose
// output the record already carries, so the two can never disagree about
// what "installed" means.
var toolSpecs = []toolSpec{
	{"rulefloor", "RULEFLOOR_VERSION", "rulefloor", []string{"rulefloor", "version", "--json"}},
	{"staticcheck", "STATICCHECK_VERSION", "staticcheck", []string{"staticcheck", "--version"}},
	{"grype", "GRYPE_VERSION", "grype", []string{"grype", "--version"}},
	{"govulncheck", "GOVULNCHECK_VERSION", "govulncheck", []string{"govulncheck", "-version"}},
}

// digestSpec is one file CI verifies by digest. A stale pin here means CI
// checks a file this repository no longer contains.
type digestSpec struct {
	tool   string
	envKey string
	path   string
}

var digestSpecs = []digestSpec{
	{"gate-witness.sh", "GATE_WITNESS_SHA256", "scripts/gate-witness.sh"},
	{"rulefloor-install-gate.sh", "RULEFLOOR_GATE_SHA256", "scripts/rulefloor-install-gate.sh"},
}

func collect(repo, workflow string) ([]Pin, error) {
	raw, err := os.ReadFile(filepath.Join(repo, workflow))
	if err != nil {
		return nil, fmt.Errorf("workflow %s: %w", workflow, err)
	}
	env := ParseWorkflowEnv(raw)

	var pins []Pin
	for _, s := range toolSpecs {
		pins = append(pins, Pin{
			Tool:     s.tool,
			Source:   "workflow env " + s.envKey,
			Declared: Normalize(KindPin, env[s.envKey]),
			Observed: Normalize(s.kind, run(s.cmd)),
		})
	}

	// Go is not re-declared in the workflow: go.mod's directive is the single
	// source, and CI's setup-go derives from it. So the comparison is go.mod
	// against the toolchain actually running here.
	gomod, err := os.ReadFile(filepath.Join(repo, "go.mod"))
	if err != nil {
		return nil, fmt.Errorf("go.mod: %w", err)
	}
	pins = append(pins, Pin{
		Tool:     "go",
		Source:   "go.mod go directive",
		Declared: Normalize(KindPin, goDirective(string(gomod))),
		Observed: Normalize("go", run([]string{"go", "version"})),
	})

	for _, d := range digestSpecs {
		sum, err := fileSHA256(filepath.Join(repo, d.path))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", d.path, err)
		}
		pins = append(pins, Pin{
			Tool:     d.tool,
			Source:   "workflow env " + d.envKey,
			Declared: Normalize("sha256", env[d.envKey]),
			Observed: sum,
		})
	}
	return pins, nil
}

// goDirective returns the `go` line's version from go.mod.
func goDirective(s string) string {
	for _, line := range strings.Split(s, "\n") {
		if strings.HasPrefix(line, "go ") {
			return strings.TrimSpace(line)
		}
	}
	return ""
}

// run returns a command's combined output, or "" if it cannot run — an
// absent tool reports nothing and Decide fails it.
func run(argv []string) string {
	out, err := exec.Command(argv[0], argv[1:]...).CombinedOutput()
	if err != nil && len(out) == 0 {
		return ""
	}
	return string(out)
}

func fileSHA256(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}
