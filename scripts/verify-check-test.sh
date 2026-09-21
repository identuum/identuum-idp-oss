#!/usr/bin/env bash
# Standalone transport proofs. Synthetic commands below are not a repository plan.
set -eu
root=$(cd "$(dirname "$0")/.." && pwd -P)
scratch=$(mktemp -d /tmp/verify-check-test.XXXXXX)
trap 'rm -rf "$scratch"' EXIT
mkdir "$scratch/repo"
cd "$scratch/repo"
git init -q
printf 'fixture\n' > work.txt
printf 'prior record\n' > GATE-RUN.txt
printf '.gograph/\n' > .gitignore
# THE-RUN-HALF: a plan entry is an argv, never a shell line, so the two
# synthetic steps below are programs the fixture ships and commits — one that
# exits with a chosen code, one that writes the ignored cache the non-minting
# proofs read. Neither is a repository plan.
printf '#!/usr/bin/env bash\nexit "${1:-0}"\n' > exit-with
printf '#!/usr/bin/env bash\nmkdir -p .gograph\nprintf %%s "$1" > .gograph/cache\n' > gen
chmod +x exit-with gen
git add work.txt GATE-RUN.txt .gitignore exit-with gen
git -c user.name=fixture -c user.email=fixture@example.invalid -c commit.gpgsign=false commit -qm fixture
printf 'prior record\n' > "$scratch/prior"

for declaration in VERIFY_PLAN:34 CI_VERIFY_PLAN:25 VERIFY_INTEGRATION_PLAN:4; do
	variable=${declaration%:*}; count=${declaration#*:}
	measured=$(awk -v variable="$variable" '
		$0 == "define " variable { definitions++; inside=1; next }
		inside && $0 == "endef" { inside=0 }
		inside && /^\t\t\047[^=]+=/ { targets++ }
		END { print definitions, targets }
	' "$root/Makefile")
	[ "$measured" = "1 $count" ] || { echo "FAIL: $variable definition/count: $measured"; exit 1; }
	[ "$(grep -Fc "\$($variable)" "$root/Makefile")" = 1 ] || { echo "FAIL: $variable must have one recipe consumer"; exit 1; }
done

# Both recorder forms the wrapper accepts are proved here, because both are
# driven by a recipe: `verify` still drives the Bash complete-run recorder,
# and ci-verify and verify-integration drive the pinned judge. The fixture
# carries no workflow, so the judge's version pin is ABSENT here and never
# mismatched: --unpinned permits exactly that. Consumer recipes stay pinned.
for mode in all fail-fast; do
	if [ "$mode" = all ]; then
		driver=(bash "$root/scripts/verify-all.sh" GATE-RUN.txt fixture --)
	else
		driver=("${LICTOR:-lictor}" witness run --record GATE-RUN.txt --label fixture --unpinned --)
	fi
	for outcome in green red; do
		command=./exit-with; expected=0; attempted=2
		if [ "$outcome" = red ]; then
			command='./exit-with 7'; expected=1
			[ "$mode" = all ] || attempted=1
		fi
		args=("first=$command" 'last=./gen generated')
		normal=0
		"${driver[@]}" "${args[@]}" > "$scratch/normal.log" 2>&1 || normal=$?
		[ "$normal" = "$expected" ] || { cat "$scratch/normal.log"; exit 1; }
		[ "$(grep -c '^target:' GATE-RUN.txt)" = "$attempted" ] || exit 1
		cp "$scratch/prior" GATE-RUN.txt
		mkdir -p .gograph; printf prior > .gograph/cache
		before=$(git status --porcelain)
		checked=0
		bash "$root/scripts/verify-check.sh" "${driver[@]}" "${args[@]}" > "$scratch/check.log" 2>&1 || checked=$?
		[ "$checked" = "$normal" ] || { cat "$scratch/check.log"; exit 1; }
		[ "$(grep -c '^target:' "$scratch/check.log")" = "$attempted" ] || exit 1
		grep -qx "result: $outcome" "$scratch/check.log"
		[ "$(git status --porcelain)" = "$before" ] || exit 1
		cmp -s "$scratch/prior" GATE-RUN.txt
		cache=generated; [ "$attempted" = 2 ] || cache=prior
		[ "$(cat .gograph/cache)" = "$cache" ] || exit 1
		printf 'PASS: %s %s — same verdict, %s outcomes, record and status unchanged\n' "$mode" "$outcome" "$attempted"
	done
done
git worktree add -q --detach "$scratch/linked" HEAD
cd "$scratch/linked"
bash "$root/scripts/verify-check.sh" bash "$root/scripts/verify-all.sh" GATE-RUN.txt fixture -- first=true > "$scratch/linked.log" 2>&1
grep -qx 'result: green' "$scratch/linked.log"
cmp -s "$scratch/prior" GATE-RUN.txt
[ -z "$(git status --porcelain)" ] || exit 1
echo 'PASS: linked worktree — green, record and status unchanged'
echo 'SELFTEST OK: one definition per plan (34/25/4); external records preserve all-target and fail-fast verdicts'
