package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// version is the build identifier for the docs-as-data generator.
// Bumped manually as the data model evolves; P3 switched the runtime
// source of truth from the curated registry to the AST-style
// annotation extractor (see extract.go), with the registry retained
// as a test-only parity fixture (see the deprecation header in
// registry.go).
const version = "identuum-idp-oss-api-docgen 0.2.0-p3"

// run is the testable entrypoint. main() delegates here so tests can
// capture stdout/stderr without touching the real os.Stdout.
func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("api-docgen", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var (
		showVersion bool
		dryRun      bool
		outDir      string
		format      string
		sourceRoots string
	)
	fs.BoolVar(&showVersion, "version", false, "Print the docgen version and exit.")
	fs.BoolVar(&dryRun, "dry-run", false, "Write generated output to stdout instead of disk.")
	fs.StringVar(&outDir, "output", "output/api", "Output directory for generated data files. Endpoint records are written to <output>/endpoints.yaml (--format=yaml) or <output>/openapi.yaml (--format=openapi). The directory is created if it does not exist. Ignored when --dry-run is set.")
	fs.StringVar(&format, "format", "yaml", "Output format: yaml (endpoints.yaml) or openapi (OpenAPI 3.0.3 spec, openapi.yaml).")
	fs.StringVar(&sourceRoots, "source-root", "", "Comma-separated list of source roots to scan for // docgen: annotations. When empty, the extractor auto-detects the OSS module root (via go.mod) and uses internal/api + internal/handlers.")

	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(stderr, "api-docgen: unexpected positional arguments: %v\n", fs.Args())
		fs.Usage()
		return 2
	}

	if showVersion {
		fmt.Fprintln(stdout, version)
		return 0
	}
	var emit func(io.Writer, []Endpoint) error
	var outFile string
	switch format {
	case "yaml":
		emit = generate
		outFile = "endpoints.yaml"
	case "openapi":
		emit = generateOpenAPI
		outFile = "openapi.yaml"
	default:
		fmt.Fprintf(stderr, "api-docgen: --format=%q is not supported (yaml or openapi)\n", format)
		return 2
	}

	roots, err := resolveSourceRoots(sourceRoots)
	if err != nil {
		fmt.Fprintf(stderr, "api-docgen: resolve source roots: %v\n", err)
		return 1
	}

	endpoints, err := EndpointsFromAnnotations(roots)
	if err != nil {
		fmt.Fprintf(stderr, "api-docgen: extract endpoints from annotations: %v\n", err)
		return 1
	}

	if dryRun {
		if err := emit(stdout, endpoints); err != nil {
			fmt.Fprintf(stderr, "api-docgen: emit failed: %v\n", err)
			return 1
		}
		return 0
	}

	if outDir == "" {
		fmt.Fprintln(stderr, "api-docgen: --output must be non-empty when --dry-run is not set")
		return 2
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		fmt.Fprintf(stderr, "api-docgen: mkdir output dir: %v\n", err)
		return 1
	}
	outPath := filepath.Join(outDir, outFile)
	f, err := os.Create(outPath)
	if err != nil {
		fmt.Fprintf(stderr, "api-docgen: create output file: %v\n", err)
		return 1
	}
	if err := emit(f, endpoints); err != nil {
		_ = f.Close()
		fmt.Fprintf(stderr, "api-docgen: emit failed: %v\n", err)
		return 1
	}
	if err := f.Close(); err != nil {
		fmt.Fprintf(stderr, "api-docgen: close output file: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "api-docgen: wrote %d endpoints to %s\n", len(endpoints), outPath)
	return 0
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// resolveSourceRoots returns the source roots the extractor should
// walk. When the operator passes `--source-root` on the CLI, the
// value is split on commas and each path is used as-is (relative
// paths are resolved against the CWD by the OS). When `--source-root`
// is empty, the extractor auto-detects the OSS module root via
// `go.mod` and joins it with `internal/api` + `internal/handlers`.
func resolveSourceRoots(flag string) ([]string, error) {
	flag = strings.TrimSpace(flag)
	if flag == "" {
		return defaultSourceRoots()
	}
	parts := strings.Split(flag, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		out = append(out, p)
	}
	if len(out) == 0 {
		return defaultSourceRoots()
	}
	return out, nil
}
