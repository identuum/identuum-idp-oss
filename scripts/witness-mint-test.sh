#!/usr/bin/env bash
# State-based proofs with the real classifier, recorder and witness recipe.
# Synthetic repositories only; never copy a checkout or its ignored files.
set -eu
root=$(cd "$(dirname "$0")/.." && pwd -P)
scratch=$(mktemp -d /tmp/witness-mint-test.XXXXXX)
trap 'rm -rf "$scratch"' EXIT
oss="$scratch/identuum-idp-oss"
ui="$scratch/identuum-ui"
mkdir -p "$oss/tools/mint-reachability" "$oss/scripts" "$ui" "$scratch/wiki/tools"
cp "$root"/tools/mint-reachability/*.go "$oss/tools/mint-reachability/"
cp "$root/scripts/gate-witness.sh" "$root/scripts/verify-all.sh" "$oss/scripts/"
go_version=$(awk '$1 == "go" { print $2 }' "$root/go.mod")
printf 'module fixture\n\ngo %s\n' "$go_version" > "$oss/go.mod"
# Only the unrelated parts-policy boundary is a fixture. The mint judge and
# witness body are unchanged; this permits a synthetic witness commit.
printf '#!/usr/bin/env bash\nexit 0\n' > "$scratch/wiki/tools/parts-commit-gate.sh"
python3 - "$root/Makefile" "$oss/Makefile" <<'PY'
from pathlib import Path
import re
import sys
source = Path(sys.argv[1]).read_text()
names = {'mint-decide', 'mint-report', 'witness', 'witness-mint-check'}
lines = source.splitlines(keepends=True)
out = ['SHELL := /bin/bash\n']
for index, line in enumerate(lines):
    if line.startswith('.PHONY:'):
        out.append(line)
    match = re.match(r'^([a-z-]+):', line)
    if match and match[1] in names:
        out.append(line)
        for body in lines[index+1:]:
            if body.startswith('\t') or not body.strip():
                out.append(body)
            else:
                break
Path(sys.argv[2]).write_text(''.join(out))
PY
commit() {
	git -C "$1" -c user.name=Fixture -c user.email=fixture@example.invalid -c commit.gpgsign=false commit -qm "$2"
}
for repo in "$oss" "$ui"; do
	git -C "$repo" -c init.defaultBranch=main init -q
	printf 'synthetic baseline\n' > "$repo/README.md"
done
git -C "$oss" add -- Makefile go.mod README.md scripts tools
commit "$oss" baseline
git -C "$ui" add -- README.md
commit "$ui" baseline
oss_base=$(git -C "$oss" rev-parse HEAD)
ui_base=$(git -C "$ui" rev-parse HEAD)
printf 'gate: e2e-full\nrepo-head: %s\nxrepo: identuum-idp-oss head=%s\nfinished: fixture\nresult: green\n' "$ui_base" "$oss_base" > "$ui/GATE-RUN.e2e-full.txt"
git -C "$ui" add -- GATE-RUN.e2e-full.txt
commit "$ui" 'synthetic mint baseline'
cd "$oss"
assert() {
	local label=$1; shift
	if "$@"; then echo "PASS $label"; else echo "FAIL $label"; exit 1; fi
}
# No change reaches the appliance: only the sibling's record was committed.
bash scripts/verify-all.sh GATE-RUN.txt fixture -- 'mint-decide=make --no-print-directory mint-report' > "$scratch/not-owed.log" 2>&1
assert 'not owed: reported mint satisfied' grep -q 'MINT SATISFIED' GATE-RUN.txt
assert 'not owed: verify green' grep -qx 'result: green' GATE-RUN.txt
make --no-print-directory witness > "$scratch/witness.log" 2>&1
assert 'not owed: shared witness committed' test "$(git log -1 --format=%s)" = "Witness: make verify green at ${oss_base:0:7}"
assert 'not owed: commit contains only the record' test "$(git diff-tree --no-commit-id --name-only -r HEAD)" = GATE-RUN.txt
cat "$scratch/witness.log"
# Makefile is explicitly reaching in the real classifier. Commit a change
# after the synthetic mint baseline, then generate a clean-head gate record.
printf '\n# synthetic change after mint\n' >> Makefile
git add -- Makefile
commit "$oss" 'reaching change'
head_before=$(git rev-parse HEAD)
bash scripts/verify-all.sh GATE-RUN.txt fixture -- 'mint-decide=make --no-print-directory mint-report' > "$scratch/owed.log" 2>&1
assert 'owed: verdict recorded' grep -q 'MINT REQUIRED' GATE-RUN.txt
assert 'owed: report target passes' grep -qx 'target: mint-decide exit=0' GATE-RUN.txt
assert 'owed: verify green' grep -qx 'result: green' GATE-RUN.txt
cat GATE-RUN.txt
for attempt in 1 2; do
	# A file named after the prerequisite must not cache approval or refusal.
	if [ "$attempt" = 2 ]; then touch witness-mint-check; fi
	result=0
	make --no-print-directory witness > "$scratch/refused.log" 2>&1 || result=$?
	assert "owed: witness attempt $attempt refuses" test "$result" -ne 0
	assert "owed: witness attempt $attempt explains debt" grep -q 'witness: REFUSED — the e2e mint is owed' "$scratch/refused.log"
	assert "owed: witness attempt $attempt commits nothing" test "$(git rev-parse HEAD)" = "$head_before"
done
cat "$scratch/refused.log"
rm witness-mint-check
result=0
bash scripts/verify-all.sh GATE-RUN.txt fixture -- 'failure=exit 23' 'mint-decide=make --no-print-directory mint-report' > "$scratch/red.log" 2>&1 || result=$?
assert 'red target: run fails' test "$result" -ne 0
assert 'red target: exact target exit recorded' grep -qx 'target: failure exit=23' GATE-RUN.txt
assert 'red target: later report still runs' grep -qx 'target: mint-decide exit=0' GATE-RUN.txt
assert 'red target: record remains red' grep -qx 'result: red' GATE-RUN.txt
cat GATE-RUN.txt
echo 'SELFTEST OK: mint debt is recorded without failing verify and refuses every witness attempt'
