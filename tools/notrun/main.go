// Command notrun counts the test functions a Docker-free aggregate does not run.
//
// WHY THIS IS A PARSER AND NOT A GREP (COUNT-THE-SKIPPER, 2026-08-02). This count
// began as an awk one-liner that tracked the last `func Test` it had seen and
// blamed any DSN skip on it, so a shared helper gating three tests counted as
// one. "Which test ends up skipping" is a CALL-GRAPH question and no line matcher
// can answer it.
//
// AND WHY THE FIRST PARSER WAS STILL WRONG (PROVED-ON-A-SHAPE-YOU-INVENTED,
// 2026-08-02). It was red-proved against a helper written for the proof and never
// against the shapes already on disk, so it inherited three assumptions that the
// tree does not honour:
//
//   - IT REQUIRED THE SKIP AND THE DSN MENTION IN THE SAME FUNCTION BODY. In
//     identuum-idp-ce/conformance the two are four calls apart:
//     TestConformance_* -> allEngines -> bootCE -> requireEnv(t, envCEDatabaseURL)
//     -> skipOrFail -> t.Skipf. No single function both skips and names the DSN,
//     so the whole chain was invisible. Both facts are now collected over the
//     TRANSITIVE CLOSURE of a test, which is where they actually live.
//   - IT COULD ONLY SEE A DSN SPELLED AS A LITERAL INSIDE THE BODY. This workspace
//     names DSNs with a package-level const (`envCEDatabaseURL`), so the literal
//     sits at package scope and never appeared in any body. Package-scope string
//     consts and vars are now resolved first.
//   - IT WAS A TWO-WAY CLASSIFIER OVER A THREE-WAY TREE: integration-tagged, or
//     "no build tag". identuum-idp-ce holds three //go:build conformance files,
//     which are neither — they were being counted in the untagged population,
//     under a sentence claiming this aggregate compiles and runs them. It does
//     not. Every constraint is now classified and reported under its own tag.
//
// POPULATION C REPORTS DSN REACHABILITY TOO, and that number is the proof the
// const fix works on code nobody wrote for the proof: all five conformance tests
// reach a skip whose DSN is named four calls away by a package-level const.
//
// The through-line: the previous version's 57 was exact only because all seven
// skippers happened to spell the variable inline — the same by-current-shape
// accident the parser was written to eliminate.
//
// IT FAILS LOUDLY AND NEVER REPORTS A ZERO IT IS NOT SURE OF. Every read or parse
// error is fatal with a non-zero exit and no output, so a broken run cannot be
// mistaken for a clean one.
//
// STATED LIMITS, because a counter that hides its blind spots is the thing this
// file exists to stop being:
//   - METHODS ARE NOT TRACKED. A skip helper hung off a receiver is missed.
//   - THE CLOSURE TEST IS "REACHES A SKIP AND REACHES A DSN NAME", not a dataflow
//     proof that the one causes the other. A test that reaches an unrelated
//     platform skip AND separately names a DSN would be counted. Measured on both
//     repos at introduction: no such case exists.
//   - Files in one directory are analysed together even when their build tags are
//     mutually exclusive. That is what makes the conformance chain visible, and it
//     can in principle join two functions that never compile together.
//
// Usage:
//
//	notrun          prints key=value lines for a caller to read
//	notrun -v       also lists every counted function with its population
package main

import (
	"errors"
	"flag"
	"fmt"
	"go/ast"
	"go/build"
	"go/build/constraint"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// dsnMarker is the substring that makes a skip a DATABASE skip rather than a
// platform skip. Both repos name their DSN variable *TEST_DATABASE_URL, so this
// one substring covers IDENTUUM_IDP_TEST_DATABASE_URL and
// IDENTUUM_CE_TEST_DATABASE_URL without hardcoding either.
const dsnMarker = "TEST_DATABASE_URL"

// buildTag is a file's classification: the empty string for a file with no
// //go:build line, "integration" for the integration suite, or the raw constraint
// text for anything else.
type buildTag string

const (
	// tagDefault marks a file the DEFAULT build selects — derived from the
	// toolchain, not from the absence of a //go:build line. A file constrained
	// `//go:build !race` has a constraint AND is selected by default; the old
	// two-way split had no way to say that.
	tagDefault     buildTag = "\x00default"
	tagIntegration buildTag = "\x00integration"
)

// pkgInfo is one directory's worth of test files. Files are collected across ALL
// build tags because they form one Go package and call each other — that is what
// makes a chain spanning harness_test.go and conformance_test.go visible.
type pkgInfo struct {
	funcs  map[string]*ast.FuncDecl // plain (non-method) funcs, any tag
	consts map[string]string        // package-scope string consts and vars
	tests  []testFunc
}

type testFunc struct {
	name string
	tag  buildTag
	file string
}

// absDir resolves a path's directory the way `go list` reports it, so the two
// universes are compared on the same spelling rather than on relative luck.
func absDir(path string) (string, error) {
	return filepath.Abs(filepath.Dir(path))
}

func main() {
	verbose := flag.Bool("v", false, "list every counted function")
	flag.Parse()

	fset := token.NewFileSet()
	ctxDefault, ctxIntegration := buildContexts()
	pkgs := map[string]*pkgInfo{}
	filesByTag := map[buildTag]int{}
	var otherPaths []string
	classified := 0
	fileTag := map[string]buildTag{}
	fileAtoms := map[string][]string{}

	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("walk %s: %w", path, err)
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "vendor", "node_modules":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}
		file, err := parser.ParseFile(fset, path, src, parser.ParseComments)
		if err != nil {
			return fmt.Errorf("parse %s: %w", path, err)
		}
		dir := filepath.Dir(path)
		p := pkgs[dir]
		if p == nil {
			p = &pkgInfo{funcs: map[string]*ast.FuncDecl{}, consts: map[string]string{}}
			pkgs[dir] = p
		}
		collectConsts(file, p.consts)

		// EVERY .go FILE IS CLASSIFIED, NOT ONLY TESTS (AG-MEASURE-FIRST,
		// 2026-08-02). This used to `return nil` here for non-test files, so
		// `othertag_names` — the population `tagged-vet` derives its `go vet -tags`
		// plan from — held TEST FILES ONLY. A tagged PRODUCTION file yielded no
		// derived tag and was therefore vetted by nothing, and the Makefile teeth
		// compared two numbers that were BOTH truncated the same way, so they could
		// not fire. identuum-ag-oss/internal/e2e/mock_oidc.go carries
		// `//go:build integration` and is exactly that file.
		//
		// Test FUNCTION counts still come from _test.go alone — production files
		// declare none — but tag classification, reachability and the vet plan now
		// cover the whole tree.
		inDefault, err := selects(ctxDefault, path)
		if err != nil {
			return err
		}
		inIntegration, err := selects(ctxIntegration, path)
		if err != nil {
			return err
		}
		var tag buildTag
		switch {
		case inDefault:
			tag = tagDefault
		case inIntegration:
			tag = tagIntegration
		default:
			tag = buildTag(constraintText(src))
			if tag == "" {
				tag = "(no //go:build line, yet selected by neither build)"
			}
		}
		fileTag[path] = tag
		fileAtoms[path] = constraintAtoms(src)
		classified++
		if !strings.HasSuffix(path, "_test.go") {
			return nil // classified for tags and coverage; declares no test functions
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || fn.Name == nil {
				continue
			}
			p.funcs[fn.Name.Name] = fn
		}
		for _, fn := range testFuncs(file) {
			p.tests = append(p.tests, testFunc{name: fn.Name.Name, tag: tag, file: path})
		}
		return nil
	})
	if err != nil {
		fatal(err)
	}

	// REACHABILITY IS ASKED FOR EVERY FILE, NOT JUST POPULATION C
	// (FIXED-IN-ONE-POPULATION, 2026-08-02). The previous version asked it only
	// where the defect had been FOUND — the other-tag population — while A and B
	// were printed under sentences asserting that some build selects them. An
	// integration-tagged _test.go under testdata with a real test function was
	// counted in integration_tests, described as selected by `-tags integration`,
	// and `go vet -tags integration ./...` can never reach it. A FILE NO PATTERN
	// CAN REACH IS NOT "NOT RUN HERE": it is compiled by nothing, and it belongs in
	// the invisible notice rather than in a count that claims a build selects it.
	lister := newDirLister()
	unreachable := map[string]bool{}
	var invisible []string
	paths := make([]string, 0, len(fileTag))
	for path := range fileTag {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		ok, err := lister.reachable(path, fileAtoms[path])
		if err != nil {
			fatal(err)
		}
		if !ok {
			unreachable[path] = true
			invisible = append(invisible, path)
			continue
		}
		filesByTag[fileTag[path]]++
		if fileTag[path] != tagDefault && fileTag[path] != tagIntegration {
			otherPaths = append(otherPaths, path)
		}
	}

	var integrationTests, untaggedDSN, otherDSN int
	otherByTag := map[buildTag]int{}
	var listed []string
	for dir, p := range pkgs {
		for _, t := range p.tests {
			if unreachable[t.file] {
				continue
			}
			switch {
			case t.tag == tagIntegration:
				integrationTests++
				listed = append(listed, "A integration "+dir+" "+t.name)
			case t.tag == tagDefault:
				if reachesDSNSkip(p, t.name) {
					untaggedDSN++
					listed = append(listed, "B default-build-dsn "+dir+" "+t.name)
				}
			default:
				otherByTag[t.tag]++
				mark := ""
				if reachesDSNSkip(p, t.name) {
					otherDSN++
					mark = " [reaches a DSN skip]"
				}
				listed = append(listed, "C "+string(t.tag)+" "+dir+" "+t.name+mark)
			}
		}
	}
	sort.Strings(listed)
	if *verbose {
		for _, l := range listed {
			fmt.Println(l)
		}
	}

	otherTests, otherFiles := 0, 0
	for _, n := range otherByTag {
		otherTests += n
	}
	// THE TAG NAMES COME FROM FILES, NOT FROM TEST BUCKETS (AG-MEASURE-FIRST,
	// 2026-08-02). They used to be collected from otherByTag, which is keyed by
	// the tag of a TEST FUNCTION — so a tagged PRODUCTION file, which declares
	// none, contributed a file to the count and no name to the list. The
	// inventory then printed "in 1 file(s) selected by NEITHER build
	// (constraints: )" with the constraint blank. Files are the population the
	// vet plan covers, so files are what names the tags.
	var otherNames []string
	for tag, n := range filesByTag {
		if tag != tagDefault && tag != tagIntegration {
			otherFiles += n
			otherNames = append(otherNames, string(tag))
		}
	}
	sort.Strings(otherNames)

	fmt.Printf("classified_files=%d\n", classified)
	fmt.Printf("integration_files=%d\n", filesByTag[tagIntegration])
	fmt.Printf("integration_tests=%d\n", integrationTests)
	fmt.Printf("othertag_files=%d\n", otherFiles)
	fmt.Printf("othertag_tests=%d\n", otherTests)
	fmt.Printf("othertag_names=%s\n", strings.Join(otherNames, ","))
	fmt.Printf("othertag_dsn_tests=%d\n", otherDSN)
	fmt.Printf("default_dsn_tests=%d\n", untaggedDSN)

	plans, uncovered, refused, err := vetPlan(ctxDefault, otherPaths)
	if err != nil {
		fatal(err)
	}
	fmt.Printf("vetplan_count=%d\n", len(plans))
	for _, p := range plans {
		fmt.Printf("vetplan=%s\n", p)
	}
	fmt.Printf("uncovered_count=%d\n", len(uncovered))
	for _, u := range uncovered {
		fmt.Printf("uncovered=%s\n", u)
	}
	fmt.Printf("refused_count=%d\n", len(refused))
	for _, r := range refused {
		fmt.Printf("refused=%s\n", r)
	}
	fmt.Printf("invisible_count=%d\n", len(invisible))
	for _, i := range invisible {
		fmt.Printf("invisible=%s\n", i)
	}
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "notrun: %v\n", err)
	os.Exit(1)
}

// buildContexts returns the two contexts whose answers the printed sentences are
// made of: the DEFAULT build (what `go build ./...` and `go test ./...` select)
// and the same build with -tags integration.
func buildContexts() (def, integ build.Context) {
	def = build.Default
	integ = build.Default
	integ.BuildTags = append(append([]string{}, build.Default.BuildTags...), "integration")
	return def, integ
}

// selects asks the TOOLCHAIN whether ctx would include this file. It replaces a
// hand-rolled evaluator that decided by substring — `strings.Contains(expr,
// "integration")` and then returned the raw text as a tag name (ASK-THE-TOOLCHAIN,
// 2026-08-02). That rule filed EVERY other constraint under "never compiles",
// which is false for `//go:build linux`, `cgo`, `!race` or `go1.26` — all
// satisfied by the default build. Measured before the change: a file tagged
// `!race` was reported as never compiled while `go test` compiled and ran it.
//
// go/build.Context.MatchFile is stdlib and evaluates the real constraint
// expression, including GOOS/GOARCH, filename suffixes and release tags. There is
// no third parser here on purpose: the previous two were both wrong in ways the
// toolchain is not.
func selects(ctx build.Context, path string) (bool, error) {
	ok, err := ctx.MatchFile(filepath.Dir(path), filepath.Base(path))
	if err != nil {
		return false, fmt.Errorf("match %s: %w", path, err)
	}
	return ok, nil
}

// constraintText returns the //go:build expression verbatim, or "" when there is
// none. It is REPORTING ONLY — it names what a reader will find in the file and
// decides nothing. Every compiles / does-not-compile claim comes from selects().
func constraintText(src []byte) string {
	for _, line := range strings.Split(string(src), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "//go:build") {
			return strings.TrimSpace(strings.TrimPrefix(line, "//go:build"))
		}
		if line != "" && !strings.HasPrefix(line, "//") && !strings.HasPrefix(line, "/*") {
			return ""
		}
	}
	return ""
}

// collectConsts records package-scope string consts and vars so a DSN named by
// identifier — the shape this workspace actually uses — is resolvable.
func collectConsts(file *ast.File, into map[string]string) {
	for _, decl := range file.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || (gd.Tok != token.CONST && gd.Tok != token.VAR) {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, name := range vs.Names {
				if i >= len(vs.Values) {
					continue
				}
				lit, ok := vs.Values[i].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				if v, err := strconv.Unquote(lit.Value); err == nil {
					into[name.Name] = v
				}
			}
		}
	}
}

// testFuncs returns the Go test functions declared in file. TestMain is NOT a
// test: it takes *testing.M and is the package entry point, so requiring the sole
// parameter to be *testing.T excludes it without special-casing the name.
func testFuncs(file *ast.File) []*ast.FuncDecl {
	var out []*ast.FuncDecl
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv != nil || fn.Name == nil || fn.Body == nil {
			continue
		}
		if !strings.HasPrefix(fn.Name.Name, "Test") || len(fn.Type.Params.List) != 1 {
			continue
		}
		star, ok := fn.Type.Params.List[0].Type.(*ast.StarExpr)
		if !ok {
			continue
		}
		sel, ok := star.X.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "T" {
			continue
		}
		out = append(out, fn)
	}
	return out
}

// reachesDSNSkip reports whether the transitive closure of name contains BOTH a
// t.Skip call and a reference to a DSN variable. The two live in different
// functions in real code, so neither half can be required of one body.
func reachesDSNSkip(p *pkgInfo, name string) bool {
	sawSkip, sawDSN := false, false
	seen := map[string]bool{}
	var walk func(string)
	walk = func(n string) {
		if seen[n] {
			return
		}
		seen[n] = true
		fn := p.funcs[n]
		if fn == nil || fn.Body == nil {
			return
		}
		ast.Inspect(fn.Body, func(node ast.Node) bool {
			switch v := node.(type) {
			case *ast.SelectorExpr:
				switch v.Sel.Name {
				case "Skip", "Skipf", "SkipNow":
					sawSkip = true
				}
			case *ast.BasicLit:
				if v.Kind == token.STRING && strings.Contains(v.Value, dsnMarker) {
					sawDSN = true
				}
			case *ast.Ident:
				if val, ok := p.consts[v.Name]; ok && strings.Contains(val, dsnMarker) {
					sawDSN = true
				}
			case *ast.CallExpr:
				if id, ok := v.Fun.(*ast.Ident); ok {
					walk(id.Name)
				}
			}
			return true
		})
	}
	walk(name)
	return sawSkip && sawDSN
}

// vetPlan derives the -tags arguments that would type-check every file the
// default and integration builds do not select, and VERIFIES the result instead
// of assuming it.
//
// THE DEFECT THIS EXISTS FOR (VET-THE-TAGS-YOU-DERIVED, 2026-08-02), iteration
// FOUR of the same mistake: the Makefile took `othertag_names` — which was the
// raw //go:build expression, documented as "reporting only" — and fed it to
// `go vet -tags`. A file constrained `//go:build slow && postgres` produced three
// fragments, `slow`, `&&` and `postgres`; three vets ran, all passed, and THE FILE
// WAS TYPE-CHECKED BY NOTHING. The teeth only fired when the name list was empty
// while files existed, which is a different question entirely. It was correct only
// because every constraint on disk was a single bare atom.
//
// TWO RULES, and the second is what makes the first safe:
//   - THE EXPRESSION IS PARSED BY go/build/constraint, NOT BY ME. Candidate tags
//     are the TagExpr atoms of the parsed tree, read off the stdlib AST.
//   - NOTHING IS TRUSTED UNTIL MatchFile AGREES. A candidate tag set counts only
//     when the toolchain, asked with exactly that set, SELECTS the file. Any file
//     no planned set selects is returned as uncovered and the caller must fail:
//     silence would be the same hole one level up again.
func vetPlan(base build.Context, files []string) (plans, uncovered, refused []string, err error) {
	seen := map[string]bool{}
	var chosen [][]string
	for _, path := range files {
		set, ok, err := coveringTags(base, path)
		if errors.Is(err, errRefused) {
			refused = append(refused, path)
			continue
		}
		if err != nil {
			return nil, nil, nil, err
		}
		if !ok {
			uncovered = append(uncovered, path)
			continue
		}
		// STRUCTURED KEY: "<goos>/<goarch>/<tags,csv>". A flat comma list could
		// not say whether "linux" meant GOOS=linux or -tags linux, and the
		// Makefile guessed wrong — see knownGOOS. Empty segments are normal.
		g, a, tg := splitAtoms(set)
		key := g + "/" + a + "/" + strings.Join(tg, ",")
		if !seen[key] {
			seen[key] = true
			chosen = append(chosen, set)
			plans = append(plans, key)
		}
	}
	// VERIFY THE WHOLE POPULATION against the plan actually emitted, not against
	// the per-file search that produced it. A file can be covered incidentally by
	// another file's tag set, and a file whose own set was found can still be
	// dropped by a bug here; only re-asking the toolchain settles both.
	for _, path := range files {
		covered := false
		if contains(refused, path) {
			continue
		}
		for _, set := range chosen {
			ok, err := selectsWithTags(base, path, set)
			if err != nil {
				return nil, nil, nil, err
			}
			if ok {
				covered = true
				break
			}
		}
		if !covered && !contains(uncovered, path) {
			uncovered = append(uncovered, path)
		}
	}
	sort.Strings(plans)
	sort.Strings(uncovered)
	sort.Strings(refused)
	return plans, uncovered, refused, nil
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

// maxConstraintAtoms bounds the subset search. Above it the search is refused
// rather than truncated: a partial search that reported "uncovered" would be
// indistinguishable from a genuinely uncoverable constraint.
const maxConstraintAtoms = 10

// errRefused marks a constraint whose atom count exceeds maxConstraintAtoms, so
// no search was attempted. It is NOT "uncoverable": nobody looked.
var errRefused = errors.New("constraint has more atoms than the search bound")

// coveringTags finds the smallest tag set for which the toolchain selects path.
// It searches subsets of the atoms in increasing size, so `!x && y` resolves to
// {y} rather than {x,y}, and an unsatisfiable constraint resolves to nothing.
func coveringTags(base build.Context, path string) ([]string, bool, error) {
	src, err := os.ReadFile(path)
	if err != nil {
		return nil, false, fmt.Errorf("read %s: %w", path, err)
	}
	atoms := constraintAtoms(src)
	if len(atoms) > maxConstraintAtoms {
		// REFUSED, NOT UNCOVERABLE (THE-WALKER-AND-THE-PATTERN, 2026-08-02). This
		// used to return the same (nil, false, nil) triple as a constraint no tag
		// set can satisfy, and the caller then printed "no tag set makes the
		// toolchain select them" — false for a search that was never run. The
		// comment on maxConstraintAtoms named exactly this confusion while the code
		// three lines below committed it.
		return nil, false, errRefused
	}
	// A NEGATED PLATFORM NEEDS AN ATOM THE FILE DOES NOT CONTAIN
	// (THE-RUNNER-SHELL, 2026-08-07). `//go:build !linux` yields the single atom
	// "linux", and no subset of {linux} can select the file on a Linux host: the
	// empty set is the host context (linux — excluded) and {linux} pins GOOS to
	// the very platform the constraint negates. The file IS type-checkable —
	// under any other GOOS — but the search universe could not say so, and
	// tagged-vet failed CI's first Linux contact over
	// internal/appliance/privdrop_other.go while passing on the Mac forever,
	// where the DEFAULT context selects the file and no candidate is needed.
	// For every GOOS atom, add ONE canonical alternate platform to the search
	// universe (darwin, or linux when the atom is darwin). MatchFile remains the
	// only arbiter: an alternate that does not select is discarded like any
	// other candidate. The refusal bound above is checked BEFORE this widening,
	// because constraint complexity is the file's own.
	for _, a := range atoms {
		if knownGOOS[a] {
			alt := "darwin"
			if a == "darwin" {
				alt = "linux"
			}
			if !contains(atoms, alt) {
				atoms = append(atoms, alt)
			}
		}
	}
	for size := 0; size <= len(atoms); size++ {
		var found []string
		var pick func(start int, cur []string) bool
		pick = func(start int, cur []string) bool {
			if len(cur) == size {
				ok, e := selectsWithTags(base, path, cur)
				if e != nil {
					err = e
					return true
				}
				if ok {
					found = append([]string{}, cur...)
					return true
				}
				return false
			}
			for i := start; i < len(atoms); i++ {
				if pick(i+1, append(cur, atoms[i])) {
					return true
				}
			}
			return false
		}
		pick(0, nil)
		if err != nil {
			return nil, false, err
		}
		if found != nil {
			sort.Strings(found)
			return found, true, nil
		}
	}
	return nil, false, nil
}

// selectsWithTags asks the toolchain whether base plus tags selects path.
// knownGOOS / knownGOARCH are the platform atoms the toolchain resolves from
// GOOS/GOARCH, NOT from -tags.
//
// THE DEFECT THIS CLOSES. `//go:build linux` has an atom "linux", and
// build.Context is happy to satisfy it via BuildTags — so the plan came out as
// `go vet -tags linux ./...`. That is not the same command, and on a non-Linux
// host it detonates inside the standard library, because EVERY zgoos_*.go
// selects at once:
//
//	internal/goos/zgoos_linux.go:7:7: GOOS redeclared in this block
//
// A platform atom has to move GOOS, not the tag list. Nothing in this repo was
// GOOS-constrained until the appliance privilege drop needed a Linux-only
// syscall path, so the gap had never been reachable.
var knownGOOS = map[string]bool{
	"aix": true, "android": true, "darwin": true, "dragonfly": true,
	"freebsd": true, "hurd": true, "illumos": true, "ios": true, "js": true,
	"linux": true, "nacl": true, "netbsd": true, "openbsd": true, "plan9": true,
	"solaris": true, "wasip1": true, "windows": true, "zos": true,
}

var knownGOARCH = map[string]bool{
	"386": true, "amd64": true, "arm": true, "arm64": true, "loong64": true,
	"mips": true, "mips64": true, "mips64le": true, "mipsle": true,
	"ppc64": true, "ppc64le": true, "riscv64": true, "s390x": true,
	"wasm": true,
}

// splitAtoms separates a candidate set into the platform it implies and the
// build tags it really is.
func splitAtoms(atoms []string) (goos, goarch string, tags []string) {
	for _, a := range atoms {
		switch {
		case knownGOOS[a]:
			goos = a
		case knownGOARCH[a]:
			goarch = a
		default:
			tags = append(tags, a)
		}
	}
	return goos, goarch, tags
}

func selectsWithTags(base build.Context, path string, atoms []string) (bool, error) {
	goos, goarch, tags := splitAtoms(atoms)
	ctx := base
	if goos != "" {
		ctx.GOOS = goos
	}
	if goarch != "" {
		ctx.GOARCH = goarch
	}
	ctx.BuildTags = append(append([]string{}, base.BuildTags...), tags...)
	return selects(ctx, path)
}

// constraintAtoms returns the tag identifiers in the file's //go:build line,
// parsed by go/build/constraint. A file with no parsable constraint yields none,
// which makes it uncoverable by tags — correct, and reported rather than hidden.
func constraintAtoms(src []byte) []string {
	line := ""
	for _, l := range strings.Split(string(src), "\n") {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "//go:build") {
			line = l
			break
		}
		if l != "" && !strings.HasPrefix(l, "//") && !strings.HasPrefix(l, "/*") {
			break
		}
	}
	if line == "" {
		return nil
	}
	expr, err := constraint.Parse(line)
	if err != nil {
		// AUDITED AND DELIBERATELY NOT BRANCHED (FIXED-IN-ONE-POPULATION, 2026-08-02).
		// Returning nil here looks like the "no //go:build line" case, and I built a
		// separate unparsable population for it — then measured, and it is DEAD CODE.
		// MatchFile parses the same line earlier in the walk and FAILS FIRST, so this
		// program aborts with `match <path>: parsing //go:build line: <reason>` before
		// any file with a malformed constraint is ever classified. The toolchain
		// already separates the two causes and names this one precisely. Adding a
		// branch that cannot fire would be machinery justified by symmetry alone.
		return nil
	}
	seen := map[string]bool{}
	var out []string
	var walk func(constraint.Expr)
	walk = func(e constraint.Expr) {
		switch v := e.(type) {
		case *constraint.TagExpr:
			if !seen[v.Tag] {
				seen[v.Tag] = true
				out = append(out, v.Tag)
			}
		case *constraint.NotExpr:
			walk(v.X)
		case *constraint.AndExpr:
			walk(v.X)
			walk(v.Y)
		case *constraint.OrExpr:
			walk(v.X)
			walk(v.Y)
		}
	}
	walk(expr)
	sort.Strings(out)
	return out
}

// dirLister answers "can `./...` reach this directory" by asking the go tool,
// caching one query per tag set.
//
// THE DEFECT THIS CLOSES (THE-WALKER-AND-THE-PATTERN, 2026-08-02): this program
// walks the filesystem and every gate consumes `./...`, and nobody reconciled the
// two universes. WalkDir skipped .git, vendor and node_modules — the go tool ALSO
// ignores every `testdata` directory and every directory whose name begins with
// `_` or `.`. identuum-idp-ce/internal/licenseprovider/testdata/seamfixture holds
// a _test.go file whose own header says the go tool never compiles it, and this
// program read and classified it. It cost nothing only because that file declared
// no test function.
//
// THE SKIP RULE IS NOT RETYPED HERE, and it is not inferred from a single listing
// either. A DIRECTORY MISSING FROM ONE LISTING IS AMBIGUOUS: it may be skipped by
// the tool, or it may simply hold no file matching the tags that listing used. The
// first version of this fix conflated the two and reported an 11-atom file in a
// perfectly ordinary directory as "invisible by design" — the same
// two-things-one-answer error, one layer in. Each file is therefore checked
// against listings made with the DEFAULT build, with -tags integration, AND with
// that file's own constraint atoms; a directory absent from all three cannot be
// reached by any pattern this repo runs.
//
// Naming a testdata directory EXPLICITLY bypasses the skip, so per-directory
// queries cannot answer this. Only the `./...` pattern can.
type dirLister struct {
	cache map[string]map[string]bool
}

func newDirLister() *dirLister { return &dirLister{cache: map[string]map[string]bool{}} }

func (l *dirLister) dirs(tags []string) (map[string]bool, error) {
	key := strings.Join(tags, ",")
	if got, ok := l.cache[key]; ok {
		return got, nil
	}
	args := []string{"list", "-e", "-f", "{{.Dir}}"}
	if len(tags) > 0 {
		args = append(args, "-tags", key)
	}
	args = append(args, "./...")
	blob, err := exec.Command("go", args...).Output()
	if err != nil {
		return nil, fmt.Errorf("go %s: %w", strings.Join(args, " "), err)
	}
	set := map[string]bool{}
	for _, line := range strings.Split(string(blob), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			set[line] = true
		}
	}
	l.cache[key] = set
	return set, nil
}

// reachable reports whether any pattern this repo runs can reach path's directory.
func (l *dirLister) reachable(path string, atoms []string) (bool, error) {
	dir, err := absDir(path)
	if err != nil {
		return false, err
	}
	for _, tags := range [][]string{nil, {"integration"}, atoms} {
		set, err := l.dirs(tags)
		if err != nil {
			return false, err
		}
		if set[dir] {
			return true, nil
		}
	}
	return false, nil
}
