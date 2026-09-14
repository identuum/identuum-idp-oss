package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

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
	driver, err := filepath.Abs("../../scripts/verify-all.sh")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "work.txt"), []byte("clean\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"init", "-q"}, {"add", "work.txt"}, {"-c", "user.name=fixture", "-c", "user.email=fixture@example.invalid", "-c", "commit.gpgsign=false", "commit", "-qm", "fixture"}} {
		if out, code := verifyAllCommand(t, dir, "git", args...); code != 0 {
			t.Fatalf("fixture git failed: %s", out)
		}
	}
	return dir, driver
}

func TestVerifyAllRecordsEveryOutcome(t *testing.T) {
	for _, tc := range []struct {
		name   string
		args   []string
		lines  []string
		code   int
		result string
	}{
		{"green", []string{"--", "first=true", "middle=true", "last=true"}, []string{"target: first exit=0", "target: middle exit=0", "target: last exit=0"}, 0, "green"},
		{"ordinary_failure", []string{"--", "first=true", "middle=exit 7", "last=true"}, []string{"target: first exit=0", "target: middle exit=7", "target: last exit=0"}, 1, "red"},
		{"failed_dependency", []string{"--requires", "dependent:build", "--", "build=exit 9", "dependent=touch must-not-run", "last=true"}, []string{"target: build exit=9", "target: dependent exit=125", "target: last exit=0", "evidence: [dependent] check FAILED: NOT-RUN dependent: dependency build recorded exit=9"}, 1, "red"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, driver := verifyAllFixture(t)
			args := append([]string{driver, "GATE-RUN.txt", "fixture"}, tc.args...)
			if out, code := verifyAllCommand(t, dir, "bash", args...); code != tc.code {
				t.Fatalf("driver exit=%d, want %d: %s", code, tc.code, out)
			}
			record := readGateContractFile(t, filepath.Join(dir, "GATE-RUN.txt"))
			for _, line := range append(tc.lines, "result: "+tc.result) {
				if !strings.Contains(record, "\n"+line+"\n") {
					t.Fatalf("missing %q in record:\n%s", line, record)
				}
			}
			if strings.Count(record, "\ntarget: ") != 3 || strings.Count(record, "\nresult: ") != 1 {
				t.Fatalf("record must contain three outcomes and one verdict:\n%s", record)
			}
			if _, err := os.Stat(filepath.Join(dir, "must-not-run")); !os.IsNotExist(err) {
				t.Fatalf("blocked command ran, or its absence could not be established: %v", err)
			}
			witness := filepath.Join(filepath.Dir(driver), "gate-witness.sh")
			if out, code := verifyAllCommand(t, dir, "bash", witness, "check", ".", "GATE-RUN.txt"); (code == 0) != (tc.result == "green") {
				t.Fatalf("shared reader disagrees with %s verdict: %s", tc.result, out)
			}
		})
	}
}

func TestVerifyAllDirtyWorkPreservesRecord(t *testing.T) {
	dir, driver := verifyAllFixture(t)
	if out, code := verifyAllCommand(t, dir, "bash", driver, "GATE-RUN.txt", "fixture", "--", "first=true"); code != 0 {
		t.Fatalf("initial mint: %s", out)
	}
	before := readGateContractFile(t, filepath.Join(dir, "GATE-RUN.txt"))
	if err := os.WriteFile(filepath.Join(dir, "work.txt"), []byte("dirty\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, middle := range []string{"true", "exit 7"} {
		out, code := verifyAllCommand(t, dir, "bash", driver, "GATE-RUN.txt", "fixture", "--", "first=true", "middle="+middle, "last=true")
		if (code == 0) != (middle == "true") {
			t.Fatalf("dirty evaluation softened or lost its verdict: exit=%d, %s", code, out)
		}
		if !strings.Contains(out, "GATE-WITNESS NOT MINTED") || strings.Count(out, "\ntarget: ") != 3 || !strings.Contains(out, "target: last exit=0") {
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
	if !strings.Contains(plan, "bash scripts/verify-all.sh GATE-RUN.txt") || !strings.Contains(plan, "--requires gograph-boundaries:gograph-build --") {
		t.Fatal("verify must use the complete-run driver and declare the graph prerequisite")
	}
	names := regexp.MustCompile(`(?m)^\t\t'([a-zA-Z0-9_-]+)=`).FindAllStringSubmatch(plan, -1)
	if len(names) < 2 || names[len(names)-2][1] != "grype-scan" || names[len(names)-1][1] != "wiki-fresh" {
		t.Fatal("the vulnerability gate must precede fatal freshness, with no target below freshness")
	}
}
