package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// OSS-LICTOR-VERIFY: `make verify` drives `lictor witness run --all`, so these
// tests pin lictor's behaviour on a throwaway repository that declares the
// same LICTOR_VERSION this repository's workflow does. lictor runs argv, not
// shell, so a failing target is the fixture's own exit-with program.

func verifyAllCommand(t *testing.T, dir, command string, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command(command, args...)
	cmd.Dir = dir
	for _, variable := range os.Environ() {
		if !strings.HasPrefix(variable, "GATE_WITNESS_") {
			cmd.Env = append(cmd.Env, variable)
		}
	}
	out, err := cmd.CombinedOutput()
	if err == nil {
		return string(out), 0
	}
	if exit, ok := err.(*exec.ExitError); ok {
		return string(out), exit.ExitCode()
	}
	t.Fatalf("could not execute fixture command: %v", err)
	return "", -1
}

func verifyAllFixture(t *testing.T) (string, string) {
	t.Helper()
	lictor, err := exec.LookPath("lictor")
	if err != nil {
		t.Fatalf("lictor is the verify recorder and is not on PATH: %v", err)
	}
	workflow := readGateContractFile(t, "../../.github/workflows/ci.yml")
	pin := regexp.MustCompile(`(?m)^  LICTOR_VERSION: v[0-9.]+$`).FindString(workflow)
	if pin == "" {
		t.Fatal("the workflow declares no LICTOR_VERSION")
	}
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"work.txt":                 "clean\n",
		"exit-with":                "#!/usr/bin/env bash\nexit \"${1:-0}\"\n",
		".github/workflows/ci.yml": "env:\n" + pin + "\n",
	} {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, args := range [][]string{{"init", "-q"}, {"add", "work.txt", "exit-with", ".github"}, {"-c", "user.name=fixture", "-c", "user.email=fixture@example.invalid", "-c", "commit.gpgsign=false", "commit", "-qm", "fixture"}} {
		if out, code := verifyAllCommand(t, dir, "git", args...); code != 0 {
			t.Fatalf("fixture git failed: %s", out)
		}
	}
	return dir, lictor
}

func verifyAllRun(t *testing.T, dir, lictor string, args ...string) (string, int) {
	t.Helper()
	argv := append([]string{"witness", "run", "--all", "--repo", dir, "--record", "GATE-RUN.txt", "--label", "fixture"}, args...)
	return verifyAllCommand(t, dir, lictor, argv...)
}

func TestVerifyAllRecordsEveryOutcome(t *testing.T) {
	for _, tc := range []struct {
		name    string
		args    []string
		lines   []string
		console []string
		code    int
		result  string
	}{
		{"green", []string{"--", "first=true", "middle=true", "last=true"}, []string{"target: first exit=0", "target: middle exit=0", "target: last exit=0"}, nil, 0, "green"},
		{"ordinary_failure", []string{"--", "first=true", "middle=./exit-with 7", "last=true"}, []string{"target: first exit=0", "target: middle exit=7", "target: last exit=0"}, nil, 1, "red"},
		{"failed_dependency", []string{"--requires", "dependent:build", "--", "build=./exit-with 9", "dependent=touch must-not-run", "last=true"}, []string{"target: build exit=9", "target: dependent exit=125", "target: last exit=0", "evidence: [dependent] check FAILED: NOT-RUN dependent: dependency build recorded exit=9"},
			[]string{"==> gate-witness: dependent", "check FAILED: NOT-RUN dependent: dependency build recorded exit=9"}, 1, "red"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, lictor := verifyAllFixture(t)
			out, code := verifyAllRun(t, dir, lictor, tc.args...)
			if code != tc.code {
				t.Fatalf("lictor exit=%d, want %d: %s", code, tc.code, out)
			}
			// A clean tree mints: the in-tree record is written, red or green.
			record := readGateContractFile(t, filepath.Join(dir, "GATE-RUN.txt"))
			for _, line := range append(tc.lines, "result: "+tc.result) {
				if !strings.Contains(record, "\n"+line+"\n") {
					t.Fatalf("missing %q in record:\n%s", line, record)
				}
			}
			if strings.Count(record, "\ntarget: ") != 3 || strings.Count(record, "\nresult: ") != 1 {
				t.Fatalf("record must contain three outcomes and one verdict:\n%s", record)
			}
			// The console names a blocked dependent as the source driver did
			// (owner ruling a, 2026-10-02; lictor v0.4.4).
			for _, line := range tc.console {
				if !strings.Contains(out, line+"\n") {
					t.Fatalf("console lacks %q:\n%s", line, out)
				}
			}
			if _, err := os.Stat(filepath.Join(dir, "must-not-run")); !os.IsNotExist(err) {
				t.Fatalf("blocked command ran, or its absence could not be established: %v", err)
			}
			witness, err := filepath.Abs("../../scripts/gate-witness.sh")
			if err != nil {
				t.Fatal(err)
			}
			if out, code := verifyAllCommand(t, dir, "bash", witness, "check", ".", "GATE-RUN.txt"); (code == 0) != (tc.result == "green") {
				t.Fatalf("shared reader disagrees with %s verdict: %s", tc.result, out)
			}
		})
	}
}

func TestVerifyAllDirtyWorkPreservesRecord(t *testing.T) {
	dir, lictor := verifyAllFixture(t)
	if out, code := verifyAllRun(t, dir, lictor, "--", "first=true"); code != 0 {
		t.Fatalf("initial mint: %s", out)
	}
	before := readGateContractFile(t, filepath.Join(dir, "GATE-RUN.txt"))
	if err := os.WriteFile(filepath.Join(dir, "work.txt"), []byte("dirty\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, middle := range []string{"true", "./exit-with 7"} {
		out, code := verifyAllRun(t, dir, lictor, "--", "first=true", "middle="+middle, "last=true")
		if (code == 0) != (middle == "true") {
			t.Fatalf("dirty evaluation softened or lost its verdict: exit=%d, %s", code, out)
		}
		if !strings.Contains(out, "GATE-WITNESS NOT MINTING: dirty work; GATE-RUN.txt remains untouched") ||
			!strings.Contains(out, "GATE-WITNESS NOT MINTED: dirty work; GATE-RUN.txt is untouched") ||
			strings.Count(out, "\ntarget: ") != 3 || !strings.Contains(out, "target: last exit=0") {
			t.Fatalf("dirty evaluation must print every outcome and refuse minting: %s", out)
		}
		if after := readGateContractFile(t, filepath.Join(dir, "GATE-RUN.txt")); after != before {
			t.Fatal("dirty evaluation replaced the committed-head record")
		}
	}
}

func TestVerifyAllPlanKeepsFreshnessLast(t *testing.T) {
	makefile := readGateContractFile(t, "../../Makefile")
	start, end := strings.Index(makefile, "\nverify:\n"), strings.Index(makefile, "\nci-verify:\n")
	if start < 0 || end <= start {
		t.Fatal("missing verify plan")
	}
	plan := makefile[start:end]
	for _, want := range []string{
		`"$(LICTOR)" witness run --all --repo "$(CURDIR)"`,
		"--record GATE-RUN.txt",
		"--requires gograph-boundaries:gograph-build --",
	} {
		if !strings.Contains(plan, want) {
			t.Fatalf("verify must drive lictor's complete-run recorder and declare the graph prerequisite; missing %q", want)
		}
	}
	if strings.Contains(plan, "scripts/verify-all.sh GATE-RUN.txt") {
		t.Fatal("verify still drives scripts/verify-all.sh")
	}
	names := regexp.MustCompile(`(?m)^\t\t'([a-zA-Z0-9_-]+)=`).FindAllStringSubmatch(plan, -1)
	if len(names) < 2 || names[len(names)-2][1] != "grype-scan" || names[len(names)-1][1] != "wiki-fresh" {
		t.Fatal("the vulnerability gate must precede fatal freshness, with no target below freshness")
	}
}
