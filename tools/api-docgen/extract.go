package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// extract.go is the Phase P3 annotation-driven Endpoint source. The
// generator reads `// docgen:endpoint` comment blocks from the OSS
// handler tree, parses the key=value lines, infers the handler symbol
// from the route-registration call that follows each block, and
// builds the same `Endpoint` records the curated `Registry()`
// fixture used to enumerate hand by hand.
//
// The extractor is the binding source of truth at the generator
// runtime after P3. `Registry()` in `registry.go` remains in the
// package as a *test-only fixture* — it is used by parity tests to
// detect drift between the extractor and the legacy hand-curated set.
// See `registry.go`'s header for the deprecation policy.
//
// The extractor is intentionally line-based (no Go AST parse) so the
// `// docgen:` format stays grep-friendly and the implementation
// stays dependency-light. The only non-stdlib import is the existing
// emit/registry/CLI surface (all in `package main`).

// annotationBlock is one decoded `// docgen:endpoint` block plus the
// source file + line range it occupies. Used by both the production
// extractor and the test-side checker.
type annotationBlock struct {
	file      string
	startLine int
	endLine   int
	values    map[string]string
}

// defaultRelativeSourceRoots lists the source roots the extractor
// walks by default — relative to the OSS module root located via
// `findModuleRoot`. The extractor still accepts caller-supplied
// roots so tests can target alternative trees if needed in future
// phases.
var defaultRelativeSourceRoots = []string{
	"internal/api",
	"internal/handlers",
}

// findModuleRoot walks up from the current working directory until
// it finds a `go.mod` file. The OSS module root is the canonical
// anchor for resolving the default source roots.
//
// This is the only piece of runtime state the extractor consults
// from the environment. It is deterministic across runs from the
// same checkout and produces no I/O outside the OSS tree.
func findModuleRoot() (string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("api-docgen: getwd: %w", err)
	}
	dir := cwd
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("api-docgen: could not find go.mod above %s", cwd)
		}
		dir = parent
	}
}

// defaultSourceRoots returns the source roots used when the operator
// does not pass `--source-root` on the CLI. The roots are resolved
// relative to the OSS module root.
func defaultSourceRoots() ([]string, error) {
	root, err := findModuleRoot()
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(defaultRelativeSourceRoots))
	for _, rel := range defaultRelativeSourceRoots {
		out = append(out, filepath.Join(root, rel))
	}
	return out, nil
}

// EndpointsFromAnnotations is the production replacement for
// `Registry()`. Walks every `*.go` file under the supplied source
// roots (excluding `_test.go`), decodes every `// docgen:endpoint`
// block, infers the handler symbol from the route-registration call
// that immediately follows each block, and emits one `Endpoint`
// record per block.
//
// The function is pure: same input source tree → same Endpoint slice.
// `Generate(...)` in emit.go re-sorts the output deterministically,
// so callers do not need to pre-sort.
func EndpointsFromAnnotations(roots []string) ([]Endpoint, error) {
	blocks, err := scanDocgenAnnotationsAt(roots)
	if err != nil {
		return nil, err
	}
	endpoints, err := convertBlocksToEndpoints(blocks)
	if err != nil {
		return nil, err
	}
	return endpoints, nil
}

// scanDocgenAnnotationsAt walks the supplied source roots and
// returns every decoded `// docgen:endpoint` block. The scanner is
// line-based and does NOT parse Go AST.
func scanDocgenAnnotationsAt(roots []string) ([]annotationBlock, error) {
	var blocks []annotationBlock
	for _, root := range roots {
		err := filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if info.IsDir() {
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			fileBlocks, err := scanDocgenAnnotationsInFile(path)
			if err != nil {
				return err
			}
			blocks = append(blocks, fileBlocks...)
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return blocks, nil
}

// scanDocgenAnnotationsInFile is the per-file scanner.
//
// It recognises three line shapes:
//
//   - `// docgen:endpoint`     — anchor line, starts a new block
//   - `// docgen:KEY=VALUE`    — extends the current block
//   - any other line            — closes any open block
//
// The scanner also records each block's `(file, startLine, endLine)`
// so test failures and lint output can point at the offending source
// location.
func scanDocgenAnnotationsInFile(path string) ([]annotationBlock, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var blocks []annotationBlock
	var current *annotationBlock
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		raw := sc.Text()
		trim := strings.TrimSpace(raw)
		const prefix = "// docgen:"
		if !strings.HasPrefix(trim, prefix) {
			if current != nil {
				current.endLine = lineNo - 1
				blocks = append(blocks, *current)
				current = nil
			}
			continue
		}
		body := trim[len(prefix):]
		if body == "endpoint" {
			if current != nil {
				current.endLine = lineNo - 1
				blocks = append(blocks, *current)
			}
			current = &annotationBlock{
				file:      path,
				startLine: lineNo,
				values:    map[string]string{"endpoint": ""},
			}
			continue
		}
		eq := strings.IndexByte(body, '=')
		if eq < 0 {
			if current == nil {
				current = &annotationBlock{file: path, startLine: lineNo, values: map[string]string{}}
			}
			current.values[body] = ""
			continue
		}
		key := strings.TrimSpace(body[:eq])
		val := strings.TrimSpace(body[eq+1:])
		if current == nil {
			current = &annotationBlock{file: path, startLine: lineNo, values: map[string]string{}}
		}
		current.values[key] = val
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if current != nil {
		current.endLine = lineNo
		blocks = append(blocks, *current)
	}
	return blocks, nil
}

// handlerCallRE matches the second argument of a gin route call —
// the identifier before its opening paren in expressions of the
// shape `<group>.METHOD("<path>", HandlerSymbol(...))` or
// `router.METHOD("<path>", wrapper("...", "..."))`.
//
// The capture is intentionally narrow: a Go identifier followed by
// `(`. The regex is anchored to the comma so that `c.Query("page", ...)`
// inside a handler body never matches.
var handlerCallRE = regexp.MustCompile(`,\s*([A-Za-z_][A-Za-z0-9_]*)\(`)

// readHandlerFromCallSite reads up to a small window of lines past
// the annotation block's end and extracts the handler-symbol name
// from the route-registration call. Returns "" when no plausible
// handler can be inferred (the well-formed test will already have
// flagged a misplaced block).
func readHandlerFromCallSite(path string, afterLine int) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		if lineNo <= afterLine {
			continue
		}
		raw := sc.Text()
		trim := strings.TrimSpace(raw)
		if trim == "" || strings.HasPrefix(trim, "//") {
			// Blank or comment line — keep scanning (rare in
			// practice; the route-registration call almost
			// always immediately follows the annotation block).
			continue
		}
		if m := handlerCallRE.FindStringSubmatch(trim); len(m) == 2 {
			return m[1], nil
		}
		// Saw a non-comment line that isn't a route-registration
		// call. Stop — the block is mis-placed.
		return "", nil
	}
	if err := sc.Err(); err != nil {
		return "", err
	}
	return "", nil
}

// convertBlocksToEndpoints translates decoded annotation blocks into
// `Endpoint` records, infers the handler symbol from each block's
// call site, resolves the source-package import path from the file
// location, and derives IDs using the same `buildID/buildIDFromPath`
// scheme as the legacy `Registry()` fixture. ID disambiguation
// follows the same `mk/mkSub/mkDeferred` semantics so the extractor's
// emitted IDs match the registry's expectations exactly.
func convertBlocksToEndpoints(blocks []annotationBlock) ([]Endpoint, error) {
	type collisionKey struct {
		surface, handler string
	}

	// First pass: build Endpoint records without ID disambiguation
	// and tally (surface, handler) collisions.
	rawEndpoints := make([]Endpoint, 0, len(blocks))
	rawIdx := make(map[int]int, len(blocks)) // map raw index → block index
	collisionCounts := make(map[collisionKey]int)
	collisionFirstIdx := make(map[collisionKey]int)
	for i, b := range blocks {
		handler, err := readHandlerFromCallSite(b.file, b.endLine)
		if err != nil {
			return nil, fmt.Errorf("api-docgen: read handler at %s:%d: %w", b.file, b.endLine, err)
		}
		// SuccessStatus defaults to "200" when the block carries no
		// `status` annotation — the common case. A present-but-empty
		// value (a bare `// docgen:status` line) is treated the same as
		// absent, so it never yields a malformed status key.
		successStatus := strings.TrimSpace(b.values["status"])
		if successStatus == "" {
			successStatus = "200"
		}
		e := Endpoint{
			Module:         moduleName,
			Surface:        b.values["surface"],
			Method:         b.values["method"],
			Path:           b.values["path"],
			Handler:        handler,
			Registrar:      "",
			Summary:        b.values["summary"],
			Tier:           b.values["tier"],
			Auth:           b.values["auth"],
			RequestSchema:  b.values["request"],
			ResponseSchema: b.values["response"],
			SuccessStatus:  successStatus,
			SourcePackage:  importPathForFile(b.file),
			SourceSymbol:   handler,
			Deferred:       strings.EqualFold(b.values["deferred"], "true"),
			FeatureGate:    b.values["feature_gate"],
		}
		rawEndpoints = append(rawEndpoints, e)
		rawIdx[len(rawEndpoints)-1] = i

		if !e.Deferred && e.Handler != "" {
			ck := collisionKey{surface: e.Surface, handler: e.Handler}
			collisionCounts[ck]++
			if _, ok := collisionFirstIdx[ck]; !ok {
				collisionFirstIdx[ck] = len(rawEndpoints) - 1
			}
		}
	}

	// Second pass: derive IDs.
	//   - deferred=true  → buildIDFromPath (same as legacy `mkDeferred`)
	//   - collision >1   → buildID + "_" + sub-key (same as legacy `mkSub`)
	//   - otherwise       → buildID (same as legacy `mk`)
	//
	// Sub-key resolution mirrors the legacy registry: prefer the
	// trailing non-param path segment when paths differ, fall back
	// to lowercased method when paths are identical.
	for i := range rawEndpoints {
		e := &rawEndpoints[i]
		if e.Deferred {
			e.ID = buildIDFromPath(e.Surface, e.Method, e.Path)
			continue
		}
		if e.Handler == "" {
			// No handler resolvable; fall back to path-based ID
			// so the entry still gets a unique identifier.
			e.ID = buildIDFromPath(e.Surface, e.Method, e.Path)
			continue
		}
		ck := collisionKey{surface: e.Surface, handler: e.Handler}
		if collisionCounts[ck] <= 1 {
			e.ID = buildID(e.Surface, e.Handler)
			continue
		}
		// Collision — derive sub-key.
		members := collectCollisionMembers(rawEndpoints, ck)
		sub := pickSubKeyFor(*e, members)
		e.ID = buildID(e.Surface, e.Handler) + "_" + sanitizeIDSeg(sub)
	}

	return rawEndpoints, nil
}

func collectCollisionMembers(all []Endpoint, ck collisionMatch) []Endpoint {
	out := make([]Endpoint, 0, 4)
	for _, e := range all {
		if e.Surface == ck.surface && e.Handler == ck.handler && !e.Deferred {
			out = append(out, e)
		}
	}
	return out
}

// collisionMatch is an alias around the un-exported collisionKey
// type used by collectCollisionMembers — declared separately so
// the helper signature stays readable.
type collisionMatch = struct {
	surface, handler string
}

// pickSubKeyFor returns the disambiguator suffix for a collision
// member. Prefers the trailing non-param path segment when at least
// one member has a different trailing segment than this one; falls
// back to lowercased method when paths share the same trailing
// segment (the userinfo GET/POST case).
func pickSubKeyFor(e Endpoint, members []Endpoint) string {
	myTail := lastNonParamSegment(e.Path)
	tailDiffers := false
	for _, m := range members {
		if lastNonParamSegment(m.Path) != myTail {
			tailDiffers = true
			break
		}
	}
	if tailDiffers {
		return myTail
	}
	return strings.ToLower(e.Method)
}

// importPathForFile maps a filesystem path inside the OSS module
// to the canonical Go import path used in Endpoint.SourcePackage.
// The mapping is anchored on the trailing `internal/api/...` or
// `internal/handlers/...` segment so the result never contains a
// personal absolute filesystem path.
func importPathForFile(absPath string) string {
	normalised := filepath.ToSlash(absPath)
	switch {
	case strings.Contains(normalised, "/internal/handlers/"):
		return handlersPackage
	case strings.Contains(normalised, "/internal/api/"):
		return apiPackage
	default:
		// Unknown layout — return the empty string so the emitted
		// YAML carries an explicit empty `source_package` rather
		// than leaking the absolute path.
		return ""
	}
}
