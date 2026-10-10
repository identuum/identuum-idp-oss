package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/google/licensecheck"
)

func main() {
	repo := flag.String("repo", ".", "the identuum-idp-oss checkout")
	ui := flag.String("ui", "../identuum-ui", "an identuum-ui checkout at the vendored commit (-write only)")
	out := flag.String("out", "THIRD_PARTY_NOTICES", "the notices file, relative to -repo")
	write := flag.Bool("write", false, "regenerate the notices file")
	check := flag.Bool("check", false, "refuse a notices file whose inputs moved")
	flag.Parse()
	if *write == *check {
		fail("give exactly one of -write and -check")
	}
	in, dirs, err := inputs(*repo)
	if err != nil {
		fail(err.Error())
	}
	path := filepath.Join(*repo, *out)
	if *check {
		line, ok := checkFile(path, in, dirs)
		fmt.Println(line)
		if !ok {
			os.Exit(1)
		}
		return
	}
	comps, err := goComponents(in.BuildList, dirs)
	if err != nil {
		fail(err.Error())
	}
	npm, err := npmComponents(*ui, in.UICommit)
	if err != nil {
		fail(err.Error())
	}
	text := Render(in, append(comps, npm...))
	if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
		fail(err.Error())
	}
	fmt.Printf("notices: wrote %s — %d Go modules, %d npm packages\n", *out, len(comps), len(npm))
}

// checkFile is -check: the notices file at path against the inputs now. The
// fingerprints say whether the build list or the vendored ui moved; the Go
// licence texts are then REGENERATED from the module cache and compared, so a
// licence file that a compiled package adds, changes or drops inside a module
// already listed is caught too (OSS-MINT-GUARD-2, review OSS-FIXES-3 F3). The
// npm texts need an identuum-ui checkout at the vendored commit, which -check
// does not have; they stay bound by that commit.
func checkFile(path string, in Inputs, dirs map[string]goModule) (string, bool) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "check FAILED: notices — " + err.Error(), false
	}
	line, ok := Check(string(raw), in)
	if !ok {
		return line, false
	}
	comps, err := goComponents(in.BuildList, dirs)
	if err != nil {
		return "check FAILED: notices — regenerating the Go licence texts: " + err.Error(), false
	}
	if goSection(string(raw)) != goSection(Render(in, comps)) {
		return "check FAILED: notices — the Go licence texts differ from a regeneration although the build list did not move (a compiled package's licence file was added, changed or removed); regenerate THIRD_PARTY_NOTICES with `go run ./tools/notices -write`", false
	}
	return line + "; its Go licence texts match a regeneration", true
}

func fail(msg string) {
	fmt.Fprintln(os.Stderr, "notices: "+msg)
	os.Exit(2)
}

// releaseTargets are the platforms the binary and the image ship for; the
// build list is theirs, never the host's.
var releaseTargets = []string{"linux/amd64", "linux/arm64"}

// inputs returns the build list (path@version) of every release target,
// united, each module's directory and the vendored identuum-ui commit.
// goModule keeps the compiled directories as well as the module root. A
// module can contain separately licensed subpackages and unshipped assets.
type goModule struct {
	Dir      string
	Packages map[string]bool
}

func inputs(repo string) (Inputs, map[string]goModule, error) {
	dirs := map[string]goModule{}
	for _, target := range releaseTargets {
		goos, goarch, _ := strings.Cut(target, "/")
		cmd := exec.Command("go", "list", "-deps", "-f",
			"{{if .Module}}{{if not .Standard}}{{if .Module.Version}}{{.Module.Path}}@{{.Module.Version}} {{.Module.Dir}} {{.Dir}}{{end}}{{end}}{{end}}",
			"./cmd/identuum-idp")
		cmd.Dir = repo
		cmd.Env = append(os.Environ(), "GOOS="+goos, "GOARCH="+goarch, "CGO_ENABLED=0")
		raw, err := cmd.Output()
		if err != nil {
			return Inputs{}, nil, fmt.Errorf("go list (%s): %w", target, err)
		}
		for _, l := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
			if f := strings.Fields(l); len(f) == 3 {
				m := dirs[f[0]]
				if m.Packages == nil {
					m = goModule{Dir: f[1], Packages: map[string]bool{}}
				}
				m.Packages[f[2]] = true
				dirs[f[0]] = m
			} else if len(f) != 0 {
				return Inputs{}, nil, fmt.Errorf("go list (%s): malformed module directory row", target)
			}
		}
	}
	list := make([]string, 0, len(dirs))
	for m := range dirs {
		list = append(list, m)
	}
	sort.Strings(list)
	var manifest struct {
		UICommit string `json:"ui_commit"`
	}
	mraw, err := os.ReadFile(filepath.Join(repo, "internal/uiexport/manifest.json"))
	if err != nil {
		return Inputs{}, nil, err
	}
	if err := json.Unmarshal(mraw, &manifest); err != nil || manifest.UICommit == "" {
		return Inputs{}, nil, fmt.Errorf("internal/uiexport/manifest.json names no ui_commit")
	}
	return Inputs{BuildList: list, UICommit: manifest.UICommit}, dirs, nil
}

var licenseFile = regexp.MustCompile(`(?i)^(licen[cs]e|copying|notice|patents)([.-].*)?$`)

// licenseFiles reads the licence-like files at the root of dir, sorted.
func licenseFiles(dir string) ([]LicenseText, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []LicenseText
	for _, e := range entries {
		if e.IsDir() || !licenseFile.MatchString(e.Name()) {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		out = append(out, LicenseText{File: e.Name(), Text: string(raw)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].File < out[j].File })
	return out, nil
}

// classify names the SPDX licences a text matches; "UNKNOWN" below 75% cover.
func classify(texts []LicenseText) string {
	var body strings.Builder
	for _, t := range texts {
		if n := strings.ToUpper(filepath.Base(t.File)); strings.HasPrefix(n, "NOTICE") || strings.HasPrefix(n, "PATENTS") {
			continue
		}
		body.WriteString(t.Text + "\n")
	}
	cov := licensecheck.Scan([]byte(body.String()))
	if cov.Percent < 75 || len(cov.Match) == 0 {
		return "UNKNOWN"
	}
	seen := map[string]bool{}
	var ids []string
	for _, m := range cov.Match {
		if !seen[m.ID] {
			seen[m.ID] = true
			ids = append(ids, m.ID)
		}
	}
	sort.Strings(ids)
	return strings.Join(ids, " AND ")
}

// goLicenseFiles collects root and ancestor notices for compiled packages.
// It deliberately excludes unrelated directories such as quic-go/assets.
func goLicenseFiles(m goModule) ([]LicenseText, error) {
	root := filepath.Clean(m.Dir)
	seen := map[string]bool{}
	var out []LicenseText
	collect := func(dir string) error {
		if seen[dir] {
			return nil
		}
		seen[dir] = true
		texts, err := licenseFiles(dir)
		if err != nil {
			return err
		}
		for _, text := range texts {
			rel, err := filepath.Rel(root, filepath.Join(dir, text.File))
			if err != nil {
				return err
			}
			text.File = filepath.ToSlash(rel)
			out = append(out, text)
		}
		return nil
	}
	if err := collect(root); err != nil {
		return nil, err
	}
	for pkg := range m.Packages {
		rel, err := filepath.Rel(root, pkg)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
			return nil, fmt.Errorf("compiled package directory %s is outside module %s", pkg, root)
		}
		for dir := filepath.Clean(pkg); dir != root; dir = filepath.Dir(dir) {
			if err := collect(dir); err != nil {
				return nil, err
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].File < out[j].File })
	return out, nil
}

func goComponents(list []string, dirs map[string]goModule) ([]Component, error) {
	var out []Component
	for _, m := range list {
		path, version, _ := strings.Cut(m, "@")
		texts, err := goLicenseFiles(dirs[m])
		if err != nil {
			return nil, fmt.Errorf("%s: %w", m, err)
		}
		out = append(out, Component{Ecosystem: "go", Name: path, Version: version, SPDX: classify(texts), Texts: texts})
	}
	return out, nil
}

// npmComponents installs identuum-ui's production closure from its lockfile
// at the vendored commit (offline, no scripts — as its `make export-sbom`
// does) into a scratch directory and reads every package installed.
func npmComponents(ui, commit string) ([]Component, error) {
	head, err := exec.Command("git", "-C", ui, "rev-parse", "HEAD").Output()
	if err != nil {
		return nil, fmt.Errorf("identuum-ui checkout %s: %w", ui, err)
	}
	if strings.TrimSpace(string(head)) != commit {
		return nil, fmt.Errorf("identuum-ui is at %s, not the vendored %s", strings.TrimSpace(string(head)), commit)
	}
	if dirty, _ := exec.Command("git", "-C", ui, "status", "--porcelain", "--", "package.json", "pnpm-lock.yaml", "pnpm-workspace.yaml").Output(); len(dirty) > 0 {
		return nil, fmt.Errorf("identuum-ui's package files are modified")
	}
	tmp, err := os.MkdirTemp("", "notices-npm-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
	for _, f := range []string{"package.json", "pnpm-lock.yaml", "pnpm-workspace.yaml"} {
		raw, err := os.ReadFile(filepath.Join(ui, f))
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(filepath.Join(tmp, f), raw, 0o644); err != nil {
			return nil, err
		}
	}
	install := exec.Command("pnpm", "install", "--prod", "--frozen-lockfile", "--offline", "--ignore-scripts")
	install.Dir = tmp
	if log, err := install.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("pnpm install --prod: %w\n%s", err, log)
	}
	store := filepath.Join(tmp, "node_modules", ".pnpm")
	entries, err := os.ReadDir(store)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []Component
	for _, e := range entries {
		if !e.IsDir() || e.Name() == "node_modules" {
			continue
		}
		pkgs, err := realPackages(filepath.Join(store, e.Name(), "node_modules"))
		if err != nil {
			return nil, err
		}
		for _, dir := range pkgs {
			c, platform, err := npmComponent(dir)
			if err != nil {
				return nil, err
			}
			// A package that names an os or cpu is a native build helper
			// pnpm picks per host (sharp, swc); a static export carries none,
			// and listing it would make the file differ between hosts.
			if platform {
				continue
			}
			vendored, err := vendoredComponents(dir, c.Name)
			if err != nil {
				return nil, err
			}
			for _, v := range append([]Component{c}, vendored...) {
				if key := v.Name + "@" + v.Version; !seen[key] {
					seen[key] = true
					out = append(out, v)
				}
			}
		}
	}
	return supplementNPM(out)
}

// supplementNPM keeps obligations in the generated file. Packages that omit a
// licence file inherit the exact upstream project licence from the same
// production closure; no generic MIT text or copyright is manufactured.
func supplementNPM(comps []Component) ([]Component, error) {
	upstream := func(name string) (Component, LicenseText, bool) {
		for _, c := range comps {
			if c.Name != name || c.SPDX != "MIT" {
				continue
			}
			for _, text := range c.Texts {
				if licenseFile.MatchString(filepath.Base(text.File)) && classify([]LicenseText{text}) == "MIT" {
					return c, text, true
				}
			}
		}
		return Component{}, LicenseText{}, false
	}
	for i := range comps {
		c := &comps[i]
		switch c.Name {
		case "@vercel/og":
			if c.Version != "0.11.1" || c.SPDX != "MPL-2.0" {
				return nil, fmt.Errorf("review @vercel/og source availability for %s (%s)", c.Version, c.SPDX)
			}
			c.Notice = "MPL-2.0 source availability: Identuum has not modified @vercel/og. The\n" +
				"unmodified upstream source of @vercel/og 0.11.1 is available at\n" +
				"https://registry.npmjs.org/@vercel/og/-/og-0.11.1.tgz\n" +
				"The archive includes dist/index.edge.js.map and dist/index.node.js.map,\n" +
				"with original source files in sourcesContent. Covered source remains under MPL-2.0."
		case "caniuse-lite":
			if c.SPDX != "CC-BY-4.0" {
				return nil, fmt.Errorf("review caniuse-lite attribution for %s", c.SPDX)
			}
			c.Notice = "Attribution: Can I use browser support data, by Alexis Deveria and\n" +
				"contributors (https://caniuse.com/), repackaged as caniuse-lite by Ben Briggs\n" +
				"and contributors (https://github.com/browserslist/caniuse-lite).\n" +
				"Licensed under CC-BY-4.0: https://creativecommons.org/licenses/by/4.0/\n" +
				"Changes: caniuse-lite compacts and repackages the original data."
		case "@next/env", "client-only":
			if len(c.Texts) != 0 {
				continue
			}
			parent := "next"
			if c.Name == "client-only" {
				parent = "react"
			}
			p, text, ok := upstream(parent)
			if !ok || c.SPDX != "MIT" || (c.Name == "@next/env" && c.Version != p.Version) ||
				(c.Name == "client-only" && c.Version != "0.0.1") {
				return nil, fmt.Errorf("%s %s: no reviewed upstream MIT licence", c.Name, c.Version)
			}
			c.Notice = "This package omits its licence file; the upstream project's MIT text follows."
			text.File = p.Name + "@" + p.Version + "/" + text.File + " (upstream project licence)"
			c.Texts = []LicenseText{text}
		}
	}
	return comps, nil
}

// vendoredComponents finds third-party packages copied inside a package (for
// example next/dist/compiled/*): a nested package.json with a name and a
// version, its own licence file, and a name that is not a sub-path of the
// enclosing package.
func vendoredComponents(dir, parent string) ([]Component, error) {
	var out []Component
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type()&os.ModeSymlink != 0 {
			return filepath.SkipDir
		}
		if d.IsDir() || d.Name() != "package.json" || filepath.Dir(p) == dir {
			return nil
		}
		c, platform, err := npmComponent(filepath.Dir(p))
		if err != nil || platform || c.Name == "" || c.Version == "" || len(c.Texts) == 0 ||
			c.Name == parent || strings.HasPrefix(c.Name, parent+"/") {
			return nil
		}
		out = append(out, c)
		return nil
	})
	return out, err
}

// realPackages returns the package directories under a store entry's
// node_modules that are not symlinks (the entry's own package; its
// dependencies are linked in).
func realPackages(nm string) ([]string, error) {
	var out []string
	entries, err := os.ReadDir(nm)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		p := filepath.Join(nm, e.Name())
		if e.Type()&os.ModeSymlink != 0 || !e.IsDir() {
			continue
		}
		if strings.HasPrefix(e.Name(), "@") {
			sub, err := os.ReadDir(p)
			if err != nil {
				return nil, err
			}
			for _, s := range sub {
				if s.Type()&os.ModeSymlink == 0 && s.IsDir() {
					out = append(out, filepath.Join(p, s.Name()))
				}
			}
			continue
		}
		out = append(out, p)
	}
	return out, nil
}

// npmComponent reads one package directory; platform reports a package that
// names an os or cpu.
func npmComponent(dir string) (Component, bool, error) {
	raw, err := os.ReadFile(filepath.Join(dir, "package.json"))
	if err != nil {
		return Component{}, false, err
	}
	var pkg struct {
		Name     string          `json:"name"`
		Version  string          `json:"version"`
		License  json.RawMessage `json:"license"`
		Licenses []struct {
			Type string `json:"type"`
		} `json:"licenses"`
		OS  []string `json:"os"`
		CPU []string `json:"cpu"`
	}
	if err := json.Unmarshal(raw, &pkg); err != nil {
		return Component{}, false, fmt.Errorf("%s: %w", dir, err)
	}
	texts, err := licenseFiles(dir)
	if err != nil {
		return Component{}, false, err
	}
	spdx := declared(pkg.License)
	if spdx == "" && len(pkg.Licenses) > 0 {
		var types []string
		for _, l := range pkg.Licenses {
			types = append(types, l.Type)
		}
		spdx = strings.Join(types, " OR ")
	}
	if spdx == "" {
		spdx = classify(texts)
	}
	return Component{Ecosystem: "npm", Name: pkg.Name, Version: pkg.Version, SPDX: spdx, Texts: texts}, len(pkg.OS) > 0 || len(pkg.CPU) > 0, nil
}

// declared reads package.json's license field: a string, or {"type": ...}.
func declared(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var o struct {
		Type string `json:"type"`
	}
	if json.Unmarshal(raw, &o) == nil {
		return o.Type
	}
	return ""
}
