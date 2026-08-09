package main

import (
	"os"
	"strings"
	"testing"
)

// The image and the binary have to agree, and nothing else checks that.
//
// P2-19b moved the runtime to distroless, which works only because the
// entrypoint's shell work now lives in the binary (P2-19c). Three facts hold
// that together, and each of them is invisible from the other side of the
// file boundary:
//
//   - The Dockerfile creates uid/gid 10001; the binary drops to a compiled-in
//     constant. If either moves, the server runs as a user that does not own
//     its data directory — and the symptom is a permission error deep in
//     first-run setup, on a FRESH database only.
//   - The ENTRYPOINT must invoke the `appliance` subcommand. Left as the bare
//     binary it would serve WITHOUT preparing the data dir or the at-rest key.
//   - The runtime base must have no shell. If someone reverts it to a
//     slim/full base "just to debug something", the reasoning in the header
//     stops being true and nothing would say so.
//
// Reading the Dockerfile from a test is the only place these can be compared.

func readDockerfile(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile("../../deployment/Dockerfile.local")
	if err != nil {
		t.Fatalf("read Dockerfile: %v", err)
	}
	return string(raw)
}

// directivesOnly strips comment lines.
//
// The first version of these tests matched the WHOLE file and failed on its
// own documentation: the header explains that the image is "Alpine-free" and
// the ENTRYPOINT comment explains why there is "No tini". Both are the file
// saying it does NOT do the thing, and matching them made the gate assert the
// opposite of what it means. A gate that fires on prose describing the correct
// state is worse than no gate — it trains you to weaken it.
func directivesOnly(s string) string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}

func TestApplianceImage_UIDMatchesTheBinarysDropTarget(t *testing.T) {
	df := readDockerfile(t)
	uid, gid := applianceUIDGIDForTest()

	if !strings.Contains(df, "-u "+uid) {
		t.Errorf("the Dockerfile does not create uid %s, but the binary drops to it — the server "+
			"would run as a user that does not own /app/data", uid)
	}
	if !strings.Contains(df, "-g "+gid+" idp") {
		t.Errorf("the Dockerfile does not create gid %s, but the binary drops to it", gid)
	}
	if !strings.Contains(df, "--chown="+uid+":"+gid) {
		t.Errorf("the data directory is not COPYed with --chown=%s:%s; distroless has no chown "+
			"to fix it afterwards", uid, gid)
	}
	if uid == "0" || gid == "0" {
		t.Fatalf("the drop target is root (uid=%s gid=%s) — that is not a drop", uid, gid)
	}
}

func TestApplianceImage_EntrypointInvokesTheApplianceSubcommand(t *testing.T) {
	df := readDockerfile(t)
	const want = `ENTRYPOINT ["/app/identuum-idp", "appliance"]`
	if !strings.Contains(df, want) {
		t.Errorf("ENTRYPOINT is not %s — the bare binary serves WITHOUT preparing the data "+
			"directory or the at-rest encryption key, and first-run setup fails writing its token", want)
	}
}

func TestApplianceImage_RuntimeIsDistrolessAndCarriesNoShellTooling(t *testing.T) {
	df := directivesOnly(readDockerfile(t))

	// Slice from the START of the FROM line, not from "AS runtime" — the image
	// name sits BEFORE that marker on the same line, so slicing at the marker
	// cut off the very thing being asserted and the test reported a
	// non-distroless base while looking at a distroless one.
	i := strings.LastIndex(df, "AS runtime")
	if i < 0 {
		t.Fatalf("no runtime stage found in the Dockerfile")
	}
	start := strings.LastIndex(df[:i], "FROM ")
	if start < 0 {
		t.Fatalf("the runtime stage has no FROM line")
	}
	runtime := df[start:]
	if !strings.Contains(runtime, "gcr.io/distroless/") {
		t.Errorf("the runtime stage is not distroless (P2-19b); the file's own reasoning about "+
			"having no shell stops being true:\n%s", firstLines(runtime, 3))
	}

	// The tooling the old entrypoint needed. Its ABSENCE is the whole point,
	// and an apt install would silently reintroduce the attack surface.
	for _, gone := range []string{"apt-get install", "gosu", "tini", "entrypoint.sh"} {
		if strings.Contains(runtime, gone) {
			t.Errorf("the runtime stage still references %q — P2-19c removed the need for it, "+
				"so its return means the shell entrypoint is creeping back", gone)
		}
	}

	// CONTROL: the four assertions above would all pass on an empty string, so
	// prove the slice really is the runtime stage.
	if !strings.Contains(runtime, "ENTRYPOINT") {
		t.Fatalf("the extracted runtime stage has no ENTRYPOINT; the assertions above were vacuous")
	}
}

func TestApplianceImage_AlpineIsAbsentEverywhere(t *testing.T) {
	// Standing owner policy, re-checked here because a distroless move is
	// exactly the kind of edit where someone reaches for a small base.
	if df := directivesOnly(readDockerfile(t)); strings.Contains(strings.ToLower(df), "alpine") {
		t.Errorf("the Dockerfile mentions alpine; owner policy forbids it in any image we build")
	}
}

func firstLines(s string, n int) string {
	lines := strings.SplitN(s, "\n", n+1)
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, "\n")
}
