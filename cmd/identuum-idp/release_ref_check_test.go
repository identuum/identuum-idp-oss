package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// OSS-RELEASE-REF: GitHub records the DISPATCH ref in a workflow's
// provenance, not the tag it checks out, so v0.9.2's binaries (and its
// image's provenance) named refs/heads/main. Each release publish workflow
// therefore refuses, before any build, a release run not dispatched on its
// tag. This test runs the workflows' own "Check the dispatch ref" step, the
// shell GitHub runs, with the dispatch environment it sees.

// releaseRefStep returns the run script of the step named "Check the
// dispatch ref" in a workflow file, dedented.
func releaseRefStep(t *testing.T, workflow string) string {
	t.Helper()
	lines := strings.Split(readGateContractFile(t, "../../.github/workflows/"+workflow), "\n")
	start := -1
	for i, l := range lines {
		if strings.TrimSpace(l) == "- name: Check the dispatch ref" {
			start = i
			break
		}
	}
	if start < 0 {
		t.Fatalf("%s has no step named \"Check the dispatch ref\"", workflow)
	}
	run := -1
	for i := start + 1; i < len(lines) && i < start+6; i++ {
		if strings.TrimSpace(lines[i]) == "run: |" {
			run = i
			break
		}
	}
	if run < 0 {
		t.Fatalf("%s: the dispatch-ref step has no `run: |` block", workflow)
	}
	indent := len(lines[run]) - len(strings.TrimLeft(lines[run], " ")) + 2
	var body []string
	for _, l := range lines[run+1:] {
		if strings.TrimSpace(l) != "" && len(l)-len(strings.TrimLeft(l, " ")) < indent {
			break
		}
		if len(l) >= indent {
			l = l[indent:]
		}
		body = append(body, l)
	}
	return strings.Join(body, "\n")
}

func runReleaseRefStep(t *testing.T, script string, env map[string]string) (string, int) {
	t.Helper()
	cmd := exec.Command("bash", "-c", script)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	out, err := cmd.CombinedOutput()
	if err == nil {
		return string(out), 0
	}
	if exit, ok := err.(*exec.ExitError); ok {
		return string(out), exit.ExitCode()
	}
	t.Fatalf("could not run the step: %v", err)
	return "", -1
}

func TestReleaseWorkflowsRefuseANonTagDispatch(t *testing.T) {
	for _, tc := range []struct {
		workflow, name string
		env            map[string]string
		pass           bool
		says           []string
	}{
		{"publish-binaries.yml", "release on main is refused", map[string]string{"DRY_RUN": "false", "VERSION_TAG": "v0.9.2", "GITHUB_REF": "refs/heads/main"}, false, []string{"expected refs/tags/v0.9.2", "got refs/heads/main"}},
		{"publish-binaries.yml", "release on another tag is refused", map[string]string{"DRY_RUN": "false", "VERSION_TAG": "v0.9.2", "GITHUB_REF": "refs/tags/v0.9.1"}, false, []string{"expected refs/tags/v0.9.2", "got refs/tags/v0.9.1"}},
		{"publish-binaries.yml", "release on its tag runs", map[string]string{"DRY_RUN": "false", "VERSION_TAG": "v0.9.2", "GITHUB_REF": "refs/tags/v0.9.2"}, true, nil},
		{"publish-binaries.yml", "release without a tag is refused", map[string]string{"DRY_RUN": "false", "VERSION_TAG": "", "GITHUB_REF": "refs/heads/main"}, false, []string{"version_tag is required"}},
		{"publish-binaries.yml", "dry run on main runs", map[string]string{"DRY_RUN": "true", "VERSION_TAG": "", "GITHUB_REF": "refs/heads/main"}, true, nil},
		{"publish-binaries.yml", "dry run elsewhere is refused", map[string]string{"DRY_RUN": "true", "VERSION_TAG": "", "GITHUB_REF": "refs/tags/v0.9.2"}, false, []string{"a dry run builds main"}},
		{"publish-image.yml", "publish on main is refused", map[string]string{"VERSION_TAG": "v0.9.2", "GITHUB_REF": "refs/heads/main"}, false, []string{"expected refs/tags/v0.9.2", "got refs/heads/main"}},
		{"publish-image.yml", "publish on another tag is refused", map[string]string{"VERSION_TAG": "v0.9.2", "GITHUB_REF": "refs/tags/v0.9.1"}, false, []string{"expected refs/tags/v0.9.2", "got refs/tags/v0.9.1"}},
		{"publish-image.yml", "publish on its tag runs", map[string]string{"VERSION_TAG": "v0.9.2", "GITHUB_REF": "refs/tags/v0.9.2"}, true, nil},
	} {
		t.Run(tc.workflow+"/"+tc.name, func(t *testing.T) {
			out, code := runReleaseRefStep(t, releaseRefStep(t, tc.workflow), tc.env)
			if (code == 0) != tc.pass {
				t.Fatalf("exit %d, want pass=%v:\n%s", code, tc.pass, out)
			}
			for _, s := range tc.says {
				if !strings.Contains(out, s) {
					t.Fatalf("the refusal does not name %q:\n%s", s, out)
				}
			}
		})
	}
}
