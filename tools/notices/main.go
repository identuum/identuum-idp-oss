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
		raw, err := os.ReadFile(path)
		if err != nil {
			fmt.Println("check FAILED: notices — " + err.Error())
			os.Exit(1)
		}
		line, ok := Check(string(raw), in)
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

func fail(msg string) {
	fmt.Fprintln(os.Stderr, "notices: "+msg)
	os.Exit(2)
}

// inputs returns the build list (path@version), each module's directory and
// the vendored identuum-ui commit.
func inputs(repo string) (Inputs, map[string]string, error) {
	cmd := exec.Command("go", "list", "-deps", "-f",
		"{{if .Module}}{{if not .Standard}}{{if .Module.Version}}{{.Module.Path}}@{{.Module.Version}} {{.Module.Dir}}{{end}}{{end}}{{end}}",
		"./cmd/identuum-idp")
	cmd.Dir = repo
	raw, err := cmd.Output()
	if err != nil {
		return Inputs{}, nil, fmt.Errorf("go list: %w", err)
	}
	dirs := map[string]string{}
	for _, l := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if f := strings.Fields(l); len(f) >= 1 {
			dir := ""
			if len(f) == 2 {
				dir = f[1]
			}
			dirs[f[0]] = dir
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
		out = append(out, LicenseText{File: e.Name(), Text: strings.ReplaceAll(string(raw), "\r\n", "\n")})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].File < out[j].File })
	return out, nil
}

// classify names the SPDX licences a text matches; "UNKNOWN" below 75% cover.
func classify(texts []LicenseText) string {
	var body strings.Builder
	for _, t := range texts {
		if n := strings.ToUpper(t.File); strings.HasPrefix(n, "NOTICE") || strings.HasPrefix(n, "PATENTS") {
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

func goComponents(list []string, dirs map[string]string) ([]Component, error) {
	var out []Component
	for _, m := range list {
		path, version, _ := strings.Cut(m, "@")
		texts, err := licenseFiles(dirs[m])
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
	return out, nil
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
