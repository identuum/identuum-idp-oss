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

counts=
for declaration in VERIFY_PLAN:37 CI_VERIFY_PLAN:28 VERIFY_INTEGRATION_PLAN:4; do
	variable=${declaration%:*}; count=${declaration#*:}
	counts=$counts${counts:+/}$count
	measured=$(awk -v variable="$variable" '
		$0 == "define " variable { definitions++; inside=1; next }
		inside && $0 == "endef" { inside=0 }
		inside && /^\t\t\047[^=]+=/ { targets++ }
		END { print definitions, targets }
	' "$root/Makefile")
	[ "$measured" = "1 $count" ] || { echo "FAIL: $variable definition/count: $measured"; exit 1; }
	[ "$(grep -Fc "\$($variable)" "$root/Makefile")" = 1 ] || { echo "FAIL: $variable must have one recipe consumer"; exit 1; }
done

# OSS-TIDY-3: what ci-verify subtracts from verify, and adds, is declared once
# (CI_VERIFY_SUBTRACTS, CI_VERIFY_ADDS); the two plans may differ by nothing else.
plan_names() {
	awk -v variable="$1" '
		$0 == "define " variable { inside=1; next }
		inside && $0 == "endef" { inside=0 }
		inside && /^\t\t\047[^=]+=/ { name=$0; sub(/^\t\t\047/, "", name); sub(/=.*/, "", name); print name }
	' "$root/Makefile" | sort
}
declared() { sed -n "s/^$1 := //p" "$root/Makefile" | tr ' ' '\n' | sed '/^$/d' | sort; }
plan_names VERIFY_PLAN > "$scratch/verify.names"
plan_names CI_VERIFY_PLAN > "$scratch/ci.names"
for pair in CI_VERIFY_SUBTRACTS:-23 CI_VERIFY_ADDS:-13; do
	variable=${pair%:*}; flag=${pair#*:}
	comm "$flag" "$scratch/verify.names" "$scratch/ci.names" > "$scratch/measured"
	declared "$variable" > "$scratch/declared"
	cmp -s "$scratch/measured" "$scratch/declared" || {
		echo "FAIL: $variable does not match the plans — measured: $(tr '\n' ' ' < "$scratch/measured")— declared: $(tr '\n' ' ' < "$scratch/declared")"
		exit 1
	}
	echo "PASS: $variable matches the plans ($(wc -l < "$scratch/declared" | tr -d ' ') names)"
done

# OSS-CI-ENV, LICTOR-ADOPT-0.4.5: lictor runs every plan entry with its
# environment allowlist, so ci-verify declares the job's DB settings with
# `--env NAME` (never as make variables, which would put a value on a command
# line), the CI job sets the same names, and go-test-race refuses when one is
# absent. Without them its 17 DB-backed tests skip under a green record.
recipe=$(awk '$0 == "ci-verify:" { inside=1; next } inside && /^[^\t#]/ { inside=0 } inside' "$root/Makefile")
entry=$(awk '$0 == "define CI_VERIFY_PLAN" { inside=1; next } inside && $0 == "endef" { inside=0 } inside && /^\t\t\047go-test-race=/' "$root/Makefile")
for variable in IDENTUUM_IDP_TEST_DATABASE_URL IDENTUUM_IDP_REQUIRE_DB_TESTS IDENTUUM_IDP_ALLOW_MULTI_REPLICA; do
	case "$recipe" in *"--env $variable "*|*"--env $variable"$'\n'*) ;; *) echo "FAIL: ci-verify does not declare --env $variable"; exit 1;; esac
	case "$entry" in *"$variable="*) echo "FAIL: ci-verify's go-test-race passes $variable as a make variable: $entry"; exit 1;; esac
	grep -Eq "^      $variable: " "$root/.github/workflows/ci.yml" || { echo "FAIL: the CI verify job does not set $variable"; exit 1; }
	# the other two set to placeholders, this one absent: refused before any test
	set +e
	out=$(cd "$root" && env IDENTUUM_IDP_TEST_DATABASE_URL=placeholder IDENTUUM_IDP_REQUIRE_DB_TESTS=placeholder IDENTUUM_IDP_ALLOW_MULTI_REPLICA=placeholder \
		env -u "$variable" make --no-print-directory go-test-race 2>&1 </dev/null)
	status=$?
	set -e
	[ "$status" -ne 0 ] && case "$out" in *"REFUSED — $variable is not set"*) true;; *) false;; esac || { echo "FAIL: go-test-race does not refuse an absent $variable (exit $status)"; exit 1; }
done
echo 'PASS: ci-verify declares the job DB settings with --env, CI sets them, go-test-race refuses an absent one (3)'

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
echo "SELFTEST OK: one definition per plan ($counts); ci-verify differs from verify only by its declared subtractions and additions; external records preserve all-target and fail-fast verdicts"
