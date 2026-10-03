package main

import (
	"strings"
	"testing"
)

func sampleInputs() Inputs {
	return Inputs{
		BuildList: []string{"example.com/a@v1.0.0", "example.com/b@v2.1.0"},
		UICommit:  "9cfd09b1007f8f7905b688dc20104f1a603f13c9",
	}
}

func sampleComponents() []Component {
	return []Component{
		{Ecosystem: "npm", Name: "left-pad", Version: "1.3.0", SPDX: "WTFPL", Texts: []LicenseText{{File: "LICENSE", Text: "do what you want\n"}}},
		{Ecosystem: "go", Name: "example.com/b", Version: "v2.1.0", SPDX: "MIT", Texts: []LicenseText{{File: "LICENSE", Text: "MIT text\r\n"}}},
		{Ecosystem: "go", Name: "example.com/a", Version: "v1.0.0", SPDX: "BSD-3-Clause"},
	}
}

// OSS-NOTICES-TIDY: the gate refuses a notices file whose build list or
// vendored identuum-ui commit moved without the file being regenerated.
func TestCheckRefusesMovedInputs(t *testing.T) {
	file := Render(sampleInputs(), sampleComponents())
	if line, ok := Check(file, sampleInputs()); !ok || !strings.HasPrefix(line, "check OK: notices") {
		t.Fatalf("the inputs it was generated from must pass: %s", line)
	}

	fake := sampleInputs()
	fake.BuildList = append(fake.BuildList, "example.com/fake@v0.0.1")
	line, ok := Check(file, fake)
	if ok || !strings.Contains(line, "the build list changed") || !strings.Contains(line, "over 3 modules") {
		t.Fatalf("a fake module in the build list must refuse the file: %s", line)
	}

	moved := sampleInputs()
	moved.UICommit = "81e4ad0fb54ff980542aaf53845c3d1650c1f58c"
	line, ok = Check(file, moved)
	if ok || !strings.Contains(line, "the vendored identuum-ui commit changed") {
		t.Fatalf("a moved identuum-ui commit must refuse the file: %s", line)
	}

	if line, ok := Check("hand-written notices\n", sampleInputs()); ok || !strings.Contains(line, "records no build-list digest") {
		t.Fatalf("a file without its inputs must refuse: %s", line)
	}
}

// The build list is the shipped targets' (linux/amd64 and linux/arm64), so the
// file and its check come out the same whatever host runs them.
func TestBuildListIsHostIndependent(t *testing.T) {
	var want []string
	for i, host := range [][2]string{{"darwin", "arm64"}, {"linux", "amd64"}, {"linux", "arm64"}, {"freebsd", "amd64"}} {
		t.Setenv("GOOS", host[0])
		t.Setenv("GOARCH", host[1])
		in, _, err := inputs("../..")
		if err != nil {
			t.Fatalf("%s/%s: %v", host[0], host[1], err)
		}
		if i == 0 {
			want = in.BuildList
			continue
		}
		if BuildListDigest(in.BuildList) != BuildListDigest(want) {
			t.Fatalf("the build list on a %s/%s host (%d modules) differs from a darwin/arm64 host's (%d)", host[0], host[1], len(in.BuildList), len(want))
		}
	}
}

// The file is deterministic: component order does not depend on the order
// the generator found them in.
func TestRenderIsDeterministic(t *testing.T) {
	a := Render(sampleInputs(), sampleComponents())
	rev := sampleComponents()
	rev[0], rev[2] = rev[2], rev[0]
	if b := Render(sampleInputs(), rev); a != b {
		t.Fatal("Render depends on input order")
	}
	if !(strings.Index(a, "go example.com/a") < strings.Index(a, "go example.com/b") &&
		strings.Index(a, "go example.com/b") < strings.Index(a, "npm left-pad")) {
		t.Fatalf("components are not sorted by ecosystem, name and version:\n%s", a)
	}
	if !strings.Contains(a, "(no licence file is shipped with this component)") {
		t.Fatal("a component without a licence file is not said to have none")
	}
}
