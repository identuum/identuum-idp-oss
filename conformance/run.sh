#!/usr/bin/env bash
# conformance/run.sh — THE-CONFORMANCE-HARNESS (2026-09-01).
#
# `make openid-conformance` — the MANUAL OpenID Foundation conformance run.
# Harness only: it stands up EVERYTHING (the pinned conformance suite AND a
# fresh disposable idp-oss appliance with a conformance organization), runs
# the config-certification plan and then the basic plan headless, reports the
# suite's verdicts VERBATIM, and tears ALL of it down — success, failure or
# interrupt. It fixes nothing.
#
# ISOLATION: one dedicated compose project (scratch-conformance) holds both
# stacks on one network, with host ports 127.0.0.1:28443/28444 (suite) and
# 127.0.0.1:27113 (OP, provisioning glue only). The dev stack, its ports and
# its data are never touched. Only the cached suite clone (and its python
# venv) and the images survive between runs.
#
# OWNERSHIP (OSS-CANDIDATE-LIFECYCLE-FIX, SPEC K1-K5, K8 — the rules
# devseed-live and identuum-ui's e2e-full follow):
#   claim     one fixed host claim, /tmp/identuum-harness.lock (never derived
#             from TMPDIR), shared with devseed-live and e2e-full — devseed-live
#             publishes 27113 too — then this host's own Docker engine through
#             a unix socket only, pinned for every later docker call, its ID
#             re-checked before each one, and the daemon mutex
#             identuum-harness-lock-engine on that engine (labelled with this
#             project and its ports). Busy is a refusal, never a wait.
#   refusal   anything of the project, or a volume or network holding a name
#             this run creates, already present is a REFUSAL — never a
#             pre-run `down`; the resolved config must be this harness's
#             services alone (no privileged or host-namespace service, no host
#             mount, no external network or volume, ports 28443, 28444 and
#             27113 on 127.0.0.1 only, the built image named for the project).
#   record    every service, volume and network carries this run's invocation
#             label, volumes and networks a name ending in the invocation id;
#             after `up --no-start` and after the start, the containers and
#             networks carrying the label are recorded by full ID and the
#             volumes by name and creation time, with a manifest.json
#             projection in the claim.
#   TLS       the per-run self-signed certificate and nginx config live in a
#             mode-700 work dir under TMPDIR and reach the recorded
#             conformance-op container by `docker cp`, by its ID, before it
#             starts — no host directory is mounted into any container.
#   teardown  removes exactly what the record names, each by full ID (a
#             volume by its invocation-unique name) after rechecking its
#             identity, and proves each gone; anything unrecorded, replaced
#             or attached refuses the WHOLE step before the first removal.
#             No `down`, no prune. A refused or failed teardown keeps the
#             claim, the mutex and the record for an operator, and is red.
#
# FLOOR SEMANTICS (CONFORMANCE-FLOOR-1): the suite's own run-test-plan.py
# exits nonzero on any UNEXPECTED failure/warning/skip AND on any expected
# failure that did not happen — an expected failure that starts passing must
# be removed from the expected file deliberately, exactly like a rulefloor
# raise. This script propagates that exit and never masks it.
#
# The suite clone is a TOOL REPO: run, never modified. Every deviation from
# its defaults lives in conformance/ (this repo).
#
# Test seams (used by the harness contract test, never in a real run):
#   CONFORMANCE_STUB_PLAN='cmd'  replaces the plan invocations
#   CONFORMANCE_STUB_STACK=1     skips clone/pull/build/up/wait/provision; the
#                                claim, the engine checks, the mutex and the
#                                recorded teardown still run
#   (a fake `docker` earlier on PATH answers and records the docker calls)
set -u

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO=$(dirname "$HERE")
# The clone lives OUTSIDE the repo tree: the image-base gate block is shared
# md5-verbatim across four repos (IMG-GATE-4), two of them out of this
# harness's reach, so the third-party clone must simply never be where any
# repo's scanners look. A sibling cache dir is uncommittable by construction.
CACHE="$(dirname "$REPO")/.conformance-suite-cache"
PIN_FILE="$HERE/PIN"
PROJECT="scratch-conformance"

# THE-JAR-REQUEST-OBJECT: MODULE mode — one basic-plan module, by name,
# resolved BEFORE anything is cloned or started so a wrong name fails in
# milliseconds. The suite's runner selects modules by 1-based index
# (--rerun <plan>:<module>); the index comes from the committed order file
# every FULL run regenerates (conformance/plan-basic.modules.txt). The
# config plan is skipped in this mode; the floor verdict is the FULL run's.
RERUN_ARGS=""
MODULES_FILE="$HERE/plan-basic.modules.txt"
if [ -n "${CONFORMANCE_MODULE:-}" ]; then
	MODULE_IDX=$(awk -v m="$CONFORMANCE_MODULE" '$1 ~ /^[0-9]+$/ && $2 == m {print $1}' "$MODULES_FILE" | head -1)
	if [ -z "$MODULE_IDX" ]; then
		echo "openid-conformance: MODULE '$CONFORMANCE_MODULE' is not in $MODULES_FILE (names come from the last full run; $(grep -cE '^[0-9]+ ' "$MODULES_FILE" 2>/dev/null || echo 0) entries)"
		exit 2
	fi
	RERUN_ARGS="--rerun 1:$MODULE_IDX"
	echo "openid-conformance: MODULE mode — oidcc-basic-certification-test-plan module $MODULE_IDX ($CONFORMANCE_MODULE) only; oidcc-config-certification-test-plan skipped"
fi

# The one pinned truth about the suite version.
PIN_TAG=$(sed -n 's/^tag: //p' "$PIN_FILE")
PIN_SHA=$(sed -n 's/^sha: //p' "$PIN_FILE")

COMPOSE_FILES=(-f "$CACHE/docker-compose-prebuilt.yml" -f "$HERE/compose.suite-override.yml" -f "$HERE/compose.appliance.yml" -f "$HERE/compose.tls.yml")

# One project authority: an inherited project name or orphan flag never
# reaches a Compose command (the e2e-full rule).
unset COMPOSE_PROJECT_NAME COMPOSE_REMOVE_ORPHANS
compose() {
	IMAGE_TAG="$PIN_TAG" CONFORMANCE_REPO="$REPO" docker compose -p "$PROJECT" "${COMPOSE_FILES[@]}" "$@"
}

fail() { echo "openid-conformance: $*" >&2; exit 2; }

# ── the claim, the engine and the daemon mutex (SPEC K2) ────────────────────
# One fixed path per machine, shared by every harness; a test rewrites this
# one line in its private copy only.
HARNESS_LOCK=/tmp/identuum-harness.lock
# N5 (OSS-TEARDOWN-MESSAGES): the claim, its record and the work dir are
# readable by this user only; the record carries the invocation id.
umask 077
if ! mkdir "$HARNESS_LOCK" 2>/dev/null; then
	# The holder line is another writer's text: first line only, filtered to
	# [A-Za-z0-9._ -], at most 80 characters.
	holder='no holder file'
	if [ -f "$HARNESS_LOCK/holder" ]; then
		IFS= read -r holder <"$HARNESS_LOCK/holder" || true
		holder=$(printf '%s' "$holder" | LC_ALL=C tr -cd 'A-Za-z0-9._ -' | cut -c1-80)
	fi
	{
		echo "openid-conformance: REFUSING — could not take the harness claim $HARNESS_LOCK (it already exists: another harness run on this machine may hold it — openid-conformance, idp-oss devseed-live, identuum-ui e2e-full/e2e-quick, final-conformance, testbook-fixtures or human-acceptance, whatever its TMPDIR — or a refused teardown kept it, with its record; nothing was started)"
		echo "openid-conformance: holder: $holder"
		echo "Read $HARNESS_LOCK/manifest.json when present. Removal is a manual owner decision."
	} >&2
	exit 1
fi
echo "$$" >"$HARNESS_LOCK/pid"
printf 'openid-conformance %s\n' "$PROJECT" >"$HARNESS_LOCK/holder"
LABEL=io.identuum.harness.invocation
INVOCATION=$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')
EXPECTED="$HARNESS_LOCK/expected"
INVENTORY="$HARNESS_LOCK/inventory"
OVERLAY="$HARNESS_LOCK/invocation.json"
CREATED="$HARNESS_LOCK/created"
MANIFEST="$HARNESS_LOCK/manifest.json"
ENGINE_FLAG="$HARNESS_LOCK/engine-changed"
MUTEX=identuum-harness-lock-engine
MUTEX_IMAGE=gcr.io/distroless/static-debian12@sha256:d75cdd72874d4790092fcb1b058493ecf6bb5bf2b2b897045b00ff01d91843f2
MUTEX_FORMAT='{{.Id}} {{index .Config.Labels "io.identuum.harness.mutex-owner"}} {{index .Config.Labels "io.identuum.harness.engine"}}'
MUTEX_ID=""
ENGINE_ID=""
ENDPOINT=""
PORTS="28443 28444 27113"
RETAIN=0
WORK=""
teardown_done=0

# OSS-TEARDOWN-MESSAGES: a refusal prints what was found and READ-ONLY
# commands to inspect it — never a deleting command; removal is the owner's
# manual decision. Advice is printed, never executed (an engine-change
# refusal permits no further docker call). The format shows identity and
# ownership labels only, never configuration or environment.
inspection_command() {
	local kind=$1 id=$2 format cmd
	case "$kind" in
	container) cmd='docker inspect'; format='{{.Id}} {{.Name}} {{index .Config.Labels "com.docker.compose.project"}} {{index .Config.Labels "io.identuum.harness.invocation"}}' ;;
	network) cmd='docker network inspect'; format='{{.Id}} {{.Name}} {{index .Labels "com.docker.compose.project"}} {{index .Labels "io.identuum.harness.invocation"}}' ;;
	volume) cmd='docker volume inspect'; format='{{.Name}} {{.CreatedAt}} {{index .Labels "com.docker.compose.project"}} {{index .Labels "io.identuum.harness.invocation"}}' ;;
	*) return 0 ;;
	esac
	printf '  found %s %s; inspect its ID, name and ownership labels:\n    %s --format %q %q\n' "$kind" "$id" "$cmd" "$format" "$id"
}

inspection_advice() {
	local kind id created
	echo "Removal is a manual owner decision. Inspect on the original engine $ENGINE_ID ($ENDPOINT); the commands below are read-only."
	echo "Recorded project $PROJECT, invocation label $LABEL=$INVOCATION (a record, not proof of current ownership). List the project's objects:"
	printf '    docker %s --filter %q\n' "ps -a" "label=com.docker.compose.project=$PROJECT" "volume ls" "label=com.docker.compose.project=$PROJECT" "network ls" "label=com.docker.compose.project=$PROJECT"
	if [ -f "$CREATED" ]; then
		while read -r kind id created; do
			[ -n "$id" ] || continue
			inspection_command "$kind" "$id"
			[ "$kind" != volume ] || echo "    (recorded creation time $created)"
		done <"$CREATED"
	fi
	[ -z "$MUTEX_ID" ] || inspection_command container "$MUTEX_ID"
}

release_claim() {
	if [ "$RETAIN" = 1 ]; then
		echo "openid-conformance: the harness claim $HARNESS_LOCK is KEPT with this run's record ($MANIFEST, $CREATED): what it created was not all proved gone. The claim and the daemon mutex stay until the owner decides." >&2
		inspection_advice >&2
		return 0
	fi
	rm -f "$HARNESS_LOCK/pid" "$HARNESS_LOCK/holder" "$EXPECTED" "$INVENTORY" "$OVERLAY" "$CREATED" "$CREATED.part" "$CREATED.complete" "$CREATED.complete.part" "$ENGINE_FLAG" "$MANIFEST" "$MANIFEST.part"
	rmdir "$HARNESS_LOCK" 2>/dev/null ||
		echo "openid-conformance: could not release the harness claim $HARNESS_LOCK — remove it once no harness run is active" >&2
}
release_mutex() {
	local m="$MUTEX_ID" got
	[ -n "$m" ] || return 0
	if [ "$RETAIN" = 1 ]; then
		echo "openid-conformance: the daemon mutex $MUTEX ($m) is KEPT with the claim: this run's resources were not all proved gone" >&2
		return 1
	fi
	if [ -e "$ENGINE_FLAG" ]; then
		RETAIN=1
		echo "openid-conformance: the daemon mutex $MUTEX was not released — the Docker daemon answering is not the engine checked at preflight (its ID changed, or it did not answer); no further docker command was run, and the mutex is left on the engine it was taken on. Removal is a manual owner decision. Inspect that engine with read-only commands: docker container inspect $MUTEX" >&2
		return 1
	fi
	got=$(docker container inspect --format "$MUTEX_FORMAT" "$m") || got=""
	if [ "$got" = "$m $INVOCATION $ENGINE_ID" ] && docker container rm "$m" >/dev/null; then
		MUTEX_ID=""
		return 0
	fi
	RETAIN=1
	echo "openid-conformance: the daemon mutex $MUTEX is no longer this run's, or could not be removed; it was left in place. Removal is a manual owner decision. Inspect it read-only: docker container inspect $MUTEX" >&2
	return 1
}
# write_manifest STATE: the public projection of this run's record (SPEC K6),
# written whole — names and IDs only, never an environment value.
write_manifest() {
	local kind id t first=1
	{
		printf '{"schema":"identuum.harness.run.v1","kind":"openid-conformance","state":"%s","project":"%s","invocation":"%s",' "$1" "$PROJECT" "$INVOCATION"
		printf '"daemon_id":"%s","endpoint":"%s","mutex_id":"%s","ports":[28443,28444,27113],"resources":[' "$ENGINE_ID" "$ENDPOINT" "$MUTEX_ID"
		if [ -e "$CREATED" ]; then
			while read -r kind id t; do
				[ -n "$kind" ] || continue
				[ "$first" = 1 ] || printf ','
				first=0
				case "$kind" in
				volume) printf '{"kind":"volume","name":"%s","created_at":"%s"}' "$id" "$t" ;;
				*) printf '{"kind":"%s","id":"%s"}' "$kind" "$id" ;;
				esac
			done <"$CREATED"
		fi
		printf ']}\n'
	} >"$MANIFEST.part" && mv "$MANIFEST.part" "$MANIFEST"
}
# Until the teardown is armed, an exit releases the mutex and the claim only:
# nothing of the project has been created yet.
release_on_exit() {
	local status=$?
	trap - EXIT
	release_mutex || [ "$status" -ne 0 ] || status=1
	release_claim
	exit "$status"
}
trap release_on_exit EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
refuse_topology() {
	echo "openid-conformance: REFUSING — $1. The harness supports exactly one topology: this host's own Docker engine, through a unix socket on this host (unix:///...). Unset DOCKER_HOST and DOCKER_CONTEXT, or select the local context (docker context use <name>)." >&2
	exit 1
}
[[ "$INVOCATION" =~ ^[0-9a-f]{32}$ ]] || fail "no invocation id could be drawn from /dev/urandom"
if [ -n "${DOCKER_HOST:-}" ] && ! [[ "$DOCKER_HOST" =~ ^unix:/// ]]; then
	refuse_topology "DOCKER_HOST selects an endpoint that is not this host's own Docker engine (not a unix socket); no docker command was run"
fi
ENDPOINT=$(docker context inspect --format '{{.Endpoints.docker.Host}}' 2>/dev/null) ||
	refuse_topology "the Docker context could not be resolved, so the engine this run would use is unknown"
[[ "$ENDPOINT" =~ ^unix:/// ]] || refuse_topology "the selected Docker context's endpoint is not this host's own Docker engine (not a unix socket)"
export DOCKER_HOST="$ENDPOINT"
unset DOCKER_CONTEXT
if ! ENGINE_ID=$(docker info --format '{{.ID}}' 2>/dev/null) || [ -z "$ENGINE_ID" ]; then
	refuse_topology "the Docker daemon did not report its ID, so this run cannot bind to the engine it checked"
fi
# Every later docker call of this runner first checks that the same engine
# answers; a changed or silent one stops every later call (sticky), keeps the
# mutex and the claim, and the run is red.
docker() {
	if [ ! -e "$ENGINE_FLAG" ] && [ "$(command docker info --format '{{.ID}}' 2>/dev/null)" = "$ENGINE_ID" ]; then
		command docker "$@"
		return "$?"
	fi
	: >"$ENGINE_FLAG"
	echo "openid-conformance: REFUSING docker $1 — the Docker daemon answering is not the engine checked at preflight (its ID changed, or it did not answer); no further docker command runs" >&2
	return 1
}
if ! mutex_volumes=$(docker image inspect --format '{{json .Config.Volumes}}' "$MUTEX_IMAGE" 2>/dev/null); then
	fail "REFUSING — the daemon mutex image $MUTEX_IMAGE is not on this engine; pull it once (docker pull $MUTEX_IMAGE) and re-run (nothing was started)"
fi
[ "$mutex_volumes" = null ] || fail "REFUSING — the daemon mutex image $MUTEX_IMAGE declares a VOLUME, so creating the mutex would create a volume (nothing was started)"
if ! MUTEX_ID=$(docker container create --name "$MUTEX" --pull=never --network=none --restart=no --read-only \
	--label io.identuum.harness.mutex=engine-v1 --label "io.identuum.harness.mutex-owner=$INVOCATION" \
	--label "io.identuum.harness.engine=$ENGINE_ID" --label io.identuum.harness.kind=openid-conformance \
	--label "io.identuum.harness.project=$PROJECT" --label "io.identuum.harness.ports=28443,28444,27113" \
	"$MUTEX_IMAGE" /identuum-harness-lock) || [ -z "$MUTEX_ID" ]; then
	MUTEX_ID=""
	fail "REFUSING — could not take the daemon mutex: container $MUTEX could not be created on this engine. Another harness run (openid-conformance, idp-oss devseed-live or identuum-ui e2e-full, from any filesystem namespace) holds it, or a killed run left it; it is never removed automatically. Removal is a manual owner decision. Inspect it read-only (docker container inspect $MUTEX; labels io.identuum.harness.*) (nothing was started)"
fi
[ "$(docker container inspect --format "$MUTEX_FORMAT" "$MUTEX_ID")" = "$MUTEX_ID $INVOCATION $ENGINE_ID" ] ||
	fail "REFUSING — the daemon mutex $MUTEX read back is not the one this run created (nothing was started)"
write_manifest reserved || fail "REFUSING — the run record $MANIFEST could not be written (nothing was started)"
echo "openid-conformance: took the harness claim $HARNESS_LOCK and the daemon mutex $MUTEX on the checked engine; held through the teardown"

# listed NAME LIST: NAME is a whole line of LIST.
listed() { grep -Fxq -- "$1" <<<"$2"; }
# record_created writes CREATED: the containers and networks carrying this
# run's invocation label, by full ID, and its volumes, by name and creation
# time. A failed listing writes nothing and fails.
record_created() {
	local rc rn rv c n v t
	if ! rc=$(docker ps -aq --no-trunc --filter "label=$LABEL=$INVOCATION") ||
		! rn=$(docker network ls -q --no-trunc --filter "label=$LABEL=$INVOCATION") ||
		! rv=$(docker volume ls -q --filter "label=$LABEL=$INVOCATION"); then
		return 1
	fi
	for c in $rc; do
		got=$(docker inspect --format "{{.Id}} {{index .Config.Labels \"$LABEL\"}} {{index .Config.Labels \"com.docker.compose.project\"}} {{index .Config.Labels \"com.docker.compose.service\"}}" "$c") || return 1
		read -r id marker project name <<<"$got"; name=${name#/}
		[ "$id $marker $project" = "$c $INVOCATION $PROJECT" ] || return 1
		case "$name" in conformance-idp|conformance-op|conformance-postgres|mongodb|nginx|server) ;; *) return 1;; esac
		users=$(docker inspect --format '{{range .Mounts}}{{if eq .Type "volume"}}{{println .Name}}{{end}}{{end}}' "$c") || return 1
		for v in $users; do
			grep -qxF "$v" <<<"$rv" || { echo "unrecorded volume $v attached to $c" >&2; return 1; }
		done
	done
	{
		for c in $rc; do echo "container $c"; done
		for n in $rn; do
			name=$(docker network inspect --format '{{.Name}}' "$n") || return 1
			grep -qxF "network"$'\t'"$name" "$INVENTORY" || return 1
			echo "network $n"
		done
		for v in $rv; do
			grep -qxF "volume"$'\t'"$v" "$INVENTORY" || return 1
			t=$(docker volume inspect --format '{{.CreatedAt}}' "$v") && [ -n "$t" ] || return 1
			echo "volume $v $t"
		done
	} >"$CREATED.part" || return 1
	seal_record
}
# seal_record publishes CREATED.part as the record, with the manifest and the
# cksum seal over both. N3 (OSS-TEARDOWN-MESSAGES): an EMPTY record is sealed
# before the first creating command, so a run that fails before it created
# anything tears down nothing, proves its project empty and releases the claim
# and the mutex; anything of the project found then is still unrecorded, and
# refuses.
seal_record() {
	mv "$CREATED.part" "$CREATED" && write_manifest created && cksum "$CREATED" "$MANIFEST" >"$CREATED.complete.part" && mv "$CREATED.complete.part" "$CREATED.complete"
}
recorded() { grep -qxF "$1 $2" "$CREATED" || grep -qF "$1 $2 " "$CREATED"; }
# remove_recorded: WHOLE STEP (SPEC K5). Phase 1 checks everything before the
# first removal — every listing, every object of the project or holding one of
# its names against the record, every recorded object's identity and label,
# and every container attached to a recorded network or using a recorded
# volume — and one finding refuses the whole step: nothing is removed. Phase 2
# removes each recorded object, its identity rechecked right before its
# removal; phase 3 proves each gone. Docker removes a volume by name with no
# identity precondition, so a volume is removed only under a name carrying
# this invocation's id; a writer that copies that exact name between the last
# inspection and the removal is the accepted residual (judge ruling Q3 (a),
# OSS-MINT-GUARD-6) — the claim and the mutex bind cooperating harness runs,
# not such a writer.
remove_recorded() {
	if [ ! -f "$CREATED.complete" ] || [ ! -f "$CREATED" ] || [ ! -f "$MANIFEST" ] || [ "$(cksum "$CREATED" "$MANIFEST")" != "$(cat "$CREATED.complete")" ]; then
		echo "  creation record missing or incomplete; nothing was removed"
		return 1
	fi
	local all_c proj_c all_n proj_n all_v proj_v strange="" failed="" left="" kind id t name got c n v users
	if ! all_c=$(docker ps -aq --no-trunc) ||
		! proj_c=$(docker ps -aq --no-trunc --filter "label=com.docker.compose.project=$PROJECT") ||
		! all_n=$(docker network ls --no-trunc --format '{{.ID}} {{.Name}}') ||
		! proj_n=$(docker network ls -q --no-trunc --filter "label=com.docker.compose.project=$PROJECT") ||
		! all_v=$(docker volume ls --format '{{.Name}}') ||
		! proj_v=$(docker volume ls -q --filter "label=com.docker.compose.project=$PROJECT"); then
		echo "  (the containers, networks and volumes could not be listed; nothing was removed)"
		return 1
	fi
	for c in $proj_c; do recorded container "$c" || strange+="  container $c (not recorded as created by this run)"$'\n'; done
	for n in $proj_n; do recorded network "$n" || strange+="  network $n (not recorded as created by this run)"$'\n'; done
	for v in $proj_v; do recorded volume "$v" || strange+="  volume $v (not recorded as created by this run)"$'\n'; done
	if [ -e "$INVENTORY" ]; then
		while IFS=$'\t' read -r kind name; do
			case "$kind" in
			network)
				for n in $(awk -v w="$name" '$2==w{print $1}' <<<"$all_n"); do
					recorded network "$n" || strange+="  network $name ($n: not recorded as created by this run)"$'\n'
				done
				;;
			volume) if listed "$name" "$all_v"; then recorded volume "$name" || strange+="  volume $name (not recorded as created by this run)"$'\n'; fi ;;
			esac
		done <"$INVENTORY"
	fi
	while read -r kind id t; do
		case "$kind" in
		container)
			listed "$id" "$all_c" || continue
			got=$(docker inspect --format "{{.Id}} {{index .Config.Labels \"$LABEL\"}}" "$id") || got=""
			[ "$got" = "$id $INVOCATION" ] || strange+="  container $id (its identity changed since it was recorded)"$'\n'
			if ! users=$(docker inspect --format '{{range .Mounts}}{{if eq .Type "volume"}}{{println .Name}}{{end}}{{end}}' "$id"); then
				strange+="  container $id (mounts could not be listed)"$'\n'
			else
				for v in $users; do recorded volume "$v" || strange+="  container $id (unrecorded volume $v is attached)"$'\n'; done
			fi
			;;
		network)
			awk '{print $1}' <<<"$all_n" | grep -qxF -- "$id" || continue
			got=$(docker network inspect --format "{{.Id}} {{index .Labels \"$LABEL\"}}" "$id") || got=""
			if [ "$got" != "$id $INVOCATION" ]; then
				strange+="  network $id (its identity changed since it was recorded)"$'\n'
				continue
			fi
			if ! users=$(docker ps -aq --no-trunc --filter "network=$id"); then
				strange+="  network $id (the containers attached to it could not be listed)"$'\n'
				continue
			fi
			for c in $users; do recorded container "$c" || strange+="  network $id (container $c, not recorded as created by this run, is attached to it)"$'\n'; done
			;;
		volume)
			listed "$id" "$all_v" || continue
			case "$id" in
			*"_$INVOCATION") ;;
			*)
				strange+="  volume $id (its name does not carry this invocation's id, so a removal by name could reach another writer's volume)"$'\n'
				continue
				;;
			esac
			got=$(docker volume inspect --format "{{.CreatedAt}} {{index .Labels \"$LABEL\"}}" "$id") || got=""
			if [ "$got" != "$t $INVOCATION" ]; then
				strange+="  volume $id (replaced since it was recorded: its creation time or invocation label changed)"$'\n'
				continue
			fi
			if ! users=$(docker ps -aq --no-trunc --filter "volume=$id"); then
				strange+="  volume $id (the containers using it could not be listed)"$'\n'
				continue
			fi
			for c in $users; do recorded container "$c" || strange+="  volume $id (container $c, not recorded as created by this run, uses it)"$'\n'; done
			;;
		esac
	done <"$CREATED"
	if [ -n "$strange" ]; then
		printf '%s' "$strange"
		echo "  (the whole step was refused before the first removal: nothing was removed, this run's own resources included)"
		return 1
	fi
	while read -r kind id t; do
		case "$kind" in
		container)
			listed "$id" "$all_c" || continue
			got=$(docker inspect --format "{{.Id}} {{index .Config.Labels \"$LABEL\"}}" "$id") || got=""
			if [ "$got" != "$id $INVOCATION" ]; then
				failed+="  container $id (its identity changed right before its removal; not removed)"$'\n'
				continue
			fi
			docker rm -f "$id" >/dev/null || failed+="  container $id (its removal failed)"$'\n'
			;;
		network)
			awk '{print $1}' <<<"$all_n" | grep -qxF -- "$id" || continue
			got=$(docker network inspect --format "{{.Id}} {{index .Labels \"$LABEL\"}}" "$id") || got=""
			if [ "$got" != "$id $INVOCATION" ]; then
				failed+="  network $id (its identity changed right before its removal; not removed)"$'\n'
				continue
			fi
			docker network rm "$id" >/dev/null || failed+="  network $id (its removal failed)"$'\n'
			;;
		volume)
			listed "$id" "$all_v" || continue
			got=$(docker volume inspect --format "{{.CreatedAt}} {{index .Labels \"$LABEL\"}}" "$id") || got=""
			if [ "$got" != "$t $INVOCATION" ]; then
				failed+="  volume $id (replaced right before its removal; not removed)"$'\n'
				continue
			fi
			docker volume rm "$id" >/dev/null || failed+="  volume $id (its removal failed)"$'\n'
			;;
		esac
	done <"$CREATED"
	if ! all_c=$(docker ps -aq --no-trunc) || ! all_n=$(docker network ls -q --no-trunc) || ! all_v=$(docker volume ls --format '{{.Name}}'); then
		failed+="  (the containers, networks and volumes could not be listed after the removals, so none was proved gone)"$'\n'
	else
		while read -r kind id t; do
			case "$kind" in
			container) ! listed "$id" "$all_c" || left+="  container $id (still present after its removal)"$'\n' ;;
			network) ! listed "$id" "$all_n" || left+="  network $id (still present after its removal)"$'\n' ;;
			volume) ! listed "$id" "$all_v" || left+="  volume $id (still present after its removal)"$'\n' ;;
			esac
		done <"$CREATED"
	fi
	printf '%s' "$failed$left"
	[ -z "$failed$left" ]
}

teardown() {
	local ec=$? refused
	trap - EXIT
	[ "$teardown_done" = 0 ] || exit "$ec"
	teardown_done=1
	# THE-HONEST-HARNESS (2026-09-07): the work dir is handled FIRST, before
	# the docker calls below. Two reasons. (1) EVIDENCE: on a red run the only
	# record of WHAT failed is the suite's exported module logs, and they live
	# in $WORK — the verdict used to be the only thing that survived the
	# teardown. (2) A docker that hangs or is missing must not strand the
	# work dir, which holds this run's private TLS key.
	if [ -n "$WORK" ] && [ "$ec" -ne 0 ] && [ -n "$(ls -A "$WORK/export" 2>/dev/null)" ]; then
		ev="$HERE/.evidence/$(date -u +%Y%m%dT%H%M%SZ)"
		if mkdir -p "$ev" && mv "$WORK/export" "$ev/export"; then
			echo "openid-conformance: EVIDENCE KEPT (exit $ec) — the suite's exported module logs are at $ev/export (gitignored; a green run keeps nothing)"
		else
			echo "openid-conformance: could NOT keep the exported module logs at $ev — they go with the work dir" >&2
		fi
	fi
	[ -n "$WORK" ] && rm -rf "$WORK"
	if [ ! -f "$CREATED.complete" ] || [ ! -f "$CREATED" ] || [ ! -f "$MANIFEST" ] || [ "$(cksum "$CREATED" "$MANIFEST")" != "$(cat "$CREATED.complete")" ]; then
		RETAIN=1
		echo "openid-conformance: TEARDOWN REFUSED for project $PROJECT — the creation record is missing or incomplete, so nothing was removed; labels cannot reconstruct creation evidence" >&2
		[ "$ec" -ne 0 ] || ec=1
	elif refused=$(remove_recorded); then
		echo "openid-conformance: teardown (project $PROJECT: removed only what this run recorded creating — both stacks — each by ID after rechecking its identity, and proved every one gone; no down; the cached clone and the images survive)"
	else
		RETAIN=1
		{
			echo "openid-conformance: TEARDOWN REFUSED for project $PROJECT — these were not created by this run, changed identity, are attached to what it created, or could not be removed or proved gone:"
			printf '%s' "$refused"
			echo "Nothing else was removed."
		} >&2
		[ "$ec" -ne 0 ] || ec=1
	fi
	if [ "$RETAIN" = 1 ]; then write_manifest refused || true; else write_manifest torn-down || true; fi
	release_mutex || [ "$ec" -ne 0 ] || ec=1
	release_claim
	exit "$ec"
}

# redact masks secret classes before anything reaches the log (FUNC-M10, §G):
# a JWT, and the value of a token, code, state, secret, session or password
# field, whether in a query string or a JSON body. It never redacts by
# remembered values.
redact() {
	sed -E \
		-e 's/eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/[jwt]/g' \
		-e 's/((access_token|id_token|refresh_token|token|code|state|client_secret|session_id|password|id_token_hint)=)[^&[:space:]"]+/\1[redacted]/g' \
		-e 's/("(access_token|id_token|refresh_token|token|code|state|client_secret|session_id|password|id_token_hint)"[[:space:]]*:[[:space:]]*")[^"]*"/\1[redacted]"/g'
}

# ── the pinned clone (cached; cloned on first run) ──────────────────────────
if [ -z "${CONFORMANCE_STUB_STACK:-}" ]; then
	if [ ! -d "$CACHE/.git" ]; then
		echo "openid-conformance: cloning conformance suite at $PIN_TAG (first run only)"
		git clone --depth 1 --branch "$PIN_TAG" https://gitlab.com/openid/conformance-suite.git "$CACHE" || fail "clone failed"
	fi
	ACTUAL_SHA=$(git -C "$CACHE" rev-parse HEAD)
	[ "$ACTUAL_SHA" = "$PIN_SHA" ] || fail "clone is at $ACTUAL_SHA, PIN says $PIN_SHA — remove $CACHE to re-clone the pinned tag"
	if ! git -C "$CACHE" diff --quiet || ! git -C "$CACHE" diff --cached --quiet; then
		fail "the suite clone has local modifications — it is a tool repo: run, never modify; remove $CACHE to restore it"
	fi
fi

# ── ownership before any creation (SPEC K1, K3) ─────────────────────────────
# Read-only listings and `config` only; nothing here creates or removes. Any
# existing object of the project, or one holding a name this run creates,
# whatever its labels, is a refusal: a previous run's leftovers are never
# deleted by assumption (this replaced a pre-run `down --volumes`).
if [ -z "${CONFORMANCE_STUB_STACK:-}" ]; then
	leftovers=""
	for q in "ps -aq" "volume ls -q" "network ls -q"; do
		# shellcheck disable=SC2086
		out=$(docker $q --filter "label=com.docker.compose.project=$PROJECT") || fail "REFUSING — docker $q failed, so leftovers of $PROJECT were not counted (nothing was started)"
		if [ -n "$out" ]; then
			leftovers+=" ${q%% *}"
			kind=${q%% *}; [ "$kind" != ps ] || kind=container
			for id in $out; do inspection_command "$kind" "$id" >&2; done
		fi
	done
	[ -z "$leftovers" ] || fail "REFUSING — project $PROJECT already has resources this run did not create ($leftovers ); the listing found their com.docker.compose.project=$PROJECT label, which proves no creation authority. Removal is a manual owner decision. Use the read-only inspection commands above (nothing was started)."
	# The resolved config, read before any resource action and never printed
	# (it carries environment values): node prints names only and writes the
	# names this run creates and the invocation overlay.
	if ! compose config --format json | PROJECT="$PROJECT" PORTS="$PORTS" LABEL="$LABEL" INVOCATION="$INVOCATION" EXPECTED="$EXPECTED" OVERLAY="$OVERLAY" node -e '
const project = process.env.PROJECT;
let cfg;
try {
	cfg = JSON.parse(require("node:fs").readFileSync(0, "utf8"));
} catch {
	console.error("openid-conformance: REFUSING — the resolved Compose config is not JSON");
	process.exit(1);
}
const bad = [];
const prot = (n) => typeof n === "string" && n.startsWith("identuum-idp-oss");
const allowed = ["conformance-idp", "conformance-op", "conformance-postgres", "mongodb", "nginx", "server"];
const ports = process.env.PORTS.split(" ");
const invocation = process.env.INVOCATION;
if (cfg.name !== project) bad.push(`project name ${cfg.name}`);
const svcs = Object.keys(cfg.services || {}).sort();
if (svcs.join(" ") !== allowed.join(" ")) bad.push(`services ${svcs.join(",")} are not exactly ${allowed.join(",")}`);
// N1/N2 (OSS-TEARDOWN-MESSAGES): ONE reviewed allowlist of service keys and
// values, the same rule in all three harnesses (devseed-live, e2e-full):
// a key not on it is refused (cap_add, privileged, userns_mode,
// volume_driver, devices, security_opt, deploy, env_file, a host namespace,
// ...); build takes context and dockerfile only; labels only the
// invocation label; logging only json-file with size options; a mount is a
// named volume of this project or a tmpfs; a network belongs to this project, with
// aliases only, none protected; a port is a reserved one on 127.0.0.1.
// OSS-ALLOWLIST-NULL-FIX: command and entrypoint are accepted only as null,
// which Compose 5.6.0 writes for every service that sets neither.
const KEYS = ["build", "container_name", "depends_on", "environment", "healthcheck", "image", "labels", "logging", "networks", "ports", "profiles", "restart", "volumes"];
const NULL_ONLY = ["command", "entrypoint"];
for (const [svc, def] of Object.entries(cfg.services || {})) {
	if (!def) continue;
	for (const key of Object.keys(def)) if (!KEYS.includes(key) && !(NULL_ONLY.includes(key) && def[key] === null)) bad.push(`service ${svc} sets unreviewed key ${key}`);
	if (def.container_name !== undefined) bad.push(`service ${svc} sets container_name ${def.container_name}`);
	for (const key of Object.keys(def.build || {})) if (key !== "context" && key !== "dockerfile") bad.push(`service ${svc} sets unreviewed build key ${key}`);
	for (const [k, v] of Object.entries(def.labels || {})) if (k !== process.env.LABEL || v !== invocation) bad.push(`service ${svc} sets label ${k}`);
	const log = def.logging;
	if (log && (log.driver !== "json-file" || Object.keys(log).some((k) => k !== "driver" && k !== "options") || Object.keys(log.options || {}).some((k) => k !== "max-size" && k !== "max-file"))) bad.push(`service ${svc} logs through an unreviewed driver or option`);
	if (def.restart !== undefined && !["no", "always", "on-failure", "unless-stopped"].includes(def.restart)) bad.push(`service ${svc} restart ${def.restart}`);
	for (const [key, n] of Object.entries(def.networks || {})) {
		if (!Object.hasOwn(cfg.networks || {}, key)) bad.push(`service ${svc} has an unowned network`);
		for (const k of Object.keys(n || {})) if (k !== "aliases") bad.push(`service ${svc} sets unreviewed network key ${k}`);
		for (const a of (n && n.aliases) || []) if (prot(a)) bad.push(`service ${svc} alias ${a}`);
	}
	for (const m of def.volumes || []) {
		if (!m || m.type !== "volume" && m.type !== "tmpfs") bad.push(`service ${svc} mounts a ${(m && m.type) || "host"} path`);
		else if (m.type === "volume" && (!m.source || !Object.hasOwn(cfg.volumes || {}, m.source))) bad.push(`service ${svc} has an unowned volume source`);
	}
	for (const p of def.ports || []) if (!p || p.host_ip !== "127.0.0.1" || !ports.includes(String(p.published))) bad.push(`service ${svc} publishes ${(p && p.host_ip) || "*"}:${(p && p.published) || "?"}`);
	if (def.build && !(typeof def.image === "string" && def.image.startsWith(`${project}-`))) bad.push(`service ${svc} builds image ${def.image || "-"}`);
}
const names = { networks: [], volumes: [] };
const unique = { networks: {}, volumes: {} };
for (const kind of ["networks", "volumes"]) {
	for (const [key, def] of Object.entries(cfg[kind] || {})) {
		const name = (def && def.name) || key;
		unique[kind][key] = `${name}_${invocation}`;
		names[kind].push(unique[kind][key]);
		if (def && def.external) bad.push(`${kind} ${key} is external (${name})`);
		if (def && def.driver_opts) bad.push(`${kind} ${key} sets driver options`);
		if (def && def.driver && def.driver !== (kind === "volumes" ? "local" : "bridge")) bad.push(`${kind} ${key} uses an unreviewed host/plugin driver`);
		if (!name.startsWith(`${project}_`) || prot(name)) bad.push(`${kind} ${key} resolves to ${name}`);
	}
}
if (bad.length) {
	console.error(`openid-conformance: REFUSING — the resolved Compose config is not this harness project alone: ${bad.join("; ")}`);
	process.exit(1);
}
const lines = [];
for (const [kind, list] of [["network", names.networks], ["volume", names.volumes]]) for (const n of list) lines.push(`${kind}\t${n}\n`);
require("node:fs").writeFileSync(process.env.EXPECTED, lines.join(""));
const label = { labels: { [process.env.LABEL]: invocation } };
const overlay = { services: {}, volumes: {}, networks: {} };
for (const svc of Object.keys(cfg.services || {})) overlay.services[svc] = label;
for (const kind of ["volumes", "networks"]) for (const key of Object.keys(cfg[kind] || {})) overlay[kind][key] = { name: unique[kind][key], ...label };
require("node:fs").writeFileSync(process.env.OVERLAY, JSON.stringify(overlay));
console.log(`openid-conformance: resolved config OK — project ${project}; networks ${names.networks.join(", ") || "-"}; volumes ${names.volumes.join(", ") || "-"}`);
'; then
		fail "REFUSING — the resolved Compose config for project $PROJECT could not be validated (nothing was started)"
	fi
	all_volumes=$(docker volume ls --format '{{.Name}}') && all_networks=$(docker network ls --format '{{.Name}}') ||
		fail "REFUSING — could not list Docker volumes and networks to prove the names this run creates are absent (nothing was started)"
	taken=""
	while IFS=$'\t' read -r kind name; do
		case "$kind" in volume) all=$all_volumes ;; network) all=$all_networks ;; *) continue ;; esac
		listed "$name" "$all" || continue
		taken+=" $kind:$name"
		inspection_command "$kind" "$name" >&2
	done <"$EXPECTED"
	[ -z "$taken" ] || fail "REFUSING —$taken already exist(s), whatever its labels; a same-name volume or network is not this run's, and Compose would reuse it. Removal is a manual owner decision. Use the read-only inspection commands above (nothing was started)."
	for port in $PORTS; do
		holder="$(docker ps --filter "publish=$port" --format '{{.Names}}' | tr '\n' ' ' || true)"
		[ -n "$holder" ] || holder="$(lsof -nP -iTCP:"$port" -sTCP:LISTEN 2>/dev/null | awk 'NR>1{print $1" pid "$2}' | sort -u | tr '\n' ' ' || true)"
		[ -z "$holder" ] || fail "REFUSING — host port $port is taken by: $holder(the harness needs it free; it never stops another stack)"
	done
	mv "$EXPECTED" "$INVENTORY"
	COMPOSE_FILES+=(-f "$OVERLAY")
	echo "openid-conformance: preflight OK — project $PROJECT unused, the names it creates absent, ports $PORTS free"
fi
# The teardown is armed now — after every refusal, before the first create,
# with an empty sealed record (N3).
: >"$CREATED.part" && seal_record || fail "REFUSING — the empty creation record could not be sealed (nothing was started)"
trap teardown EXIT

# ── stand everything up ─────────────────────────────────────────────────────
# https by default: the DO-3 measurement showed the suite RUNS against an
# http OP but fails every endpoint on scheme alone, drowning real findings.
CONFORMANCE_OP_ISSUER="${CONFORMANCE_OP_ISSUER:-https://conformance-op:8443}"
export CONFORMANCE_OP_ISSUER

# Per-run self-signed cert + nginx config for the TLS sidecar, in a mode-700
# work dir under TMPDIR (SPEC K8: private material stays out of the repo).
# They reach the conformance-op container by `docker cp`, by its recorded
# ID, before it starts; no host directory is mounted into any container.
# Removed by teardown; never committed, never reused. CONFORMANCE_TLS_DIR
# names the work dir for the harness contract test.
WORK=$(mktemp -d "${TMPDIR:-/tmp}/conformance-work.XXXXXX") || fail "no work dir could be created"
chmod 700 "$WORK"
export CONFORMANCE_TLS_DIR="$WORK"
if [ -z "${CONFORMANCE_STUB_STACK:-}" ]; then
	mkdir -p "$WORK/tls"
	(umask 077 && openssl req -x509 -newkey rsa:2048 -keyout "$WORK/tls/op.key" -out "$WORK/tls/op.crt" \
		-days 2 -nodes -subj "/CN=conformance-op" \
		-addext "subjectAltName=DNS:conformance-op" >/dev/null 2>&1) || fail "self-signed cert generation failed"
	cat >"$WORK/tls/default.conf" <<'NGINX'
server {
    listen 8443 ssl;
    server_name conformance-op;
    ssl_certificate /etc/nginx/conf.d/op.crt;
    ssl_certificate_key /etc/nginx/conf.d/op.key;
    location / {
        proxy_pass http://conformance-idp:7113;
        proxy_set_header Host $host:8443;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-For $remote_addr;
    }
}
NGINX
fi
IDENTUUM_IDP_BOOTSTRAP_PASSWORD="${IDENTUUM_IDP_BOOTSTRAP_PASSWORD:-Conf0rmance!$(openssl rand -hex 12)}"
export IDENTUUM_IDP_BOOTSTRAP_PASSWORD
CONFORMANCE_USER_PASSWORD="${CONFORMANCE_USER_PASSWORD:-Conf0rmanceUs3r!$(openssl rand -hex 8)}"
export CONFORMANCE_USER_PASSWORD

if [ -z "${CONFORMANCE_STUB_STACK:-}" ]; then
	echo "openid-conformance: pulling pinned suite images ($PIN_TAG) + building the appliance"
	compose pull mongodb nginx server || fail "image pull failed"
	compose build conformance-idp || fail "appliance build failed"
	# Created first, not started: the record names every object before any
	# runs, and the TLS files are copied into the recorded conformance-op
	# container by its ID.
	# N5 (OSS-TEARDOWN-MESSAGES): the pull and the build took time since the
	# preflight; right before the first creating command every name this run
	# creates is proved absent again, so a volume or network that appeared
	# meanwhile — whatever its labels, this invocation's included — is never
	# adopted (it is unrecorded, so the teardown refuses and keeps the claim).
	all_volumes=$(docker volume ls --format '{{.Name}}') && all_networks=$(docker network ls --format '{{.Name}}') ||
		fail "could not list Docker volumes and networks right before the first create"
	while IFS=$'\t' read -r kind name; do
		case "$kind" in volume) all=$all_volumes ;; network) all=$all_networks ;; *) continue ;; esac
		! listed "$name" "$all" || fail "REFUSING — $kind $name appeared after the preflight, before this run created anything; it is not adopted"
	done <"$INVENTORY"
	compose up --no-start --no-build || fail "compose up --no-start failed"
	record_created || fail "could not record what this run created"
	op=$(docker ps -aq --no-trunc --filter "label=$LABEL=$INVOCATION" --filter "label=com.docker.compose.service=conformance-op") || op=""
	[ "$(printf '%s\n' "$op" | grep -c .)" = 1 ] && recorded container "$op" || fail "the conformance-op container of this run is not exactly one recorded container"
	docker cp "$WORK/tls/." "$op:/etc/nginx/conf.d/" >/dev/null || fail "could not copy the TLS files into the recorded conformance-op container"
	compose up -d --no-build --no-recreate || fail "compose up failed"
	echo "openid-conformance: recorded $(grep -c . "$CREATED") resource(s) this run created, by ID"

	echo "openid-conformance: waiting for the OP appliance"
	for i in $(seq 1 60); do
		curl -fsS --max-time 2 http://127.0.0.1:27113/health >/dev/null 2>&1 && break
		[ "$i" = 60 ] && fail "the OP appliance never became healthy"
		sleep 2
	done
	compose exec -e IDENTUUM_IDP_BOOTSTRAP_PASSWORD -T conformance-idp /app/identuum-idp bootstrap || fail "bootstrap failed"

	echo "openid-conformance: waiting for the conformance suite"
	for i in $(seq 1 90); do
		curl -fsSk --max-time 2 https://127.0.0.1:28443/api/server >/dev/null 2>&1 && break
		[ "$i" = 90 ] && fail "the conformance suite never became ready"
		sleep 2
	done

	echo "openid-conformance: provisioning the conformance organization"
	PROV=$(CONFORMANCE_OP_BASE=http://127.0.0.1:27113 \
		CONFORMANCE_CALLBACK="https://localhost.emobix.co.uk:8443/test/a/identuum-oss/callback" \
		node "$HERE/provision.mjs") || fail "provisioning failed"
else
	record_created || fail "could not record the offline stack"
fi

# ── plan configs: substitute fixtures into the throwaway work dir ───────────
jqget() { node -e "process.stdout.write(JSON.parse(process.argv[1])[process.argv[2]] ?? '')" "$PROV" "$1"; }
if [ -z "${CONFORMANCE_STUB_STACK:-}" ]; then
	sed -e "s|__OP_ISSUER__|$CONFORMANCE_OP_ISSUER|g" "$HERE/plan-config.json" >"$WORK/plan-config.json"
	sed -e "s|__OP_ISSUER__|$CONFORMANCE_OP_ISSUER|g" \
		-e "s|__CLIENT1_ID__|$(jqget client1_id)|g" \
		-e "s|__CLIENT1_SECRET__|$(jqget client1_secret)|g" \
		-e "s|__CLIENT2_ID__|$(jqget client2_id)|g" \
		-e "s|__CLIENT2_SECRET__|$(jqget client2_secret)|g" \
		-e "s|__CLIENT3_ID__|$(jqget client3_id)|g" \
		-e "s|__CLIENT3_SECRET__|$(jqget client3_secret)|g" \
		-e "s|__USER_PASSWORD__|$CONFORMANCE_USER_PASSWORD|g" \
		"$HERE/plan-basic.json" >"$WORK/plan-basic.json"
fi

# ── login smoke: prove the provisioned ORG_USER can complete the OP-native
# ceremony (browser-login -> consent approve -> authorization code) BEFORE
# handing the OP to the suite. If the ceremony itself is broken, this names
# it directly instead of leaving the suite to time out module by module. ──
login_smoke() {
	local base=http://127.0.0.1:27113 jar="$WORK/smoke-cookies" page csrf code loc
	local c1 cb="https://localhost.emobix.co.uk:8443/test/a/identuum-oss/callback"
	c1=$(jqget client1_id)
	# PKCE pair (optional for this confidential client since
	# THE-PKCE-DECISION; the smoke keeps sending one — a supplied
	# challenge must still round-trip).
	local verifier challenge
	verifier=$(openssl rand -hex 32)
	challenge=$(printf '%s' "$verifier" | openssl dgst -sha256 -binary | openssl base64 -A | tr '+/' '-_' | tr -d '=')

	page=$(curl -fsS -c "$jar" "$base/api/v1/auth/browser-login") || { echo "login-smoke: login form unreachable"; return 1; }
	csrf=$(printf '%s' "$page" | sed -n 's/.*name="csrf_token" value="\([^"]*\)".*/\1/p')
	code=$(curl -s -o /dev/null -w '%{http_code}' -b "$jar" -c "$jar" -X POST "$base/api/v1/auth/browser-login" \
		--data-urlencode "email=conformance-user@conformance.test" \
		--data-urlencode "password=$CONFORMANCE_USER_PASSWORD" \
		--data-urlencode "csrf_token=$csrf" \
		--data-urlencode "return_to=")
	case "$code" in 2* | 3*) : ;; *) echo "login-smoke: org_user browser-login FAILED (HTTP $code)"; return 1 ;; esac

	page=$(curl -fsS -b "$jar" -c "$jar" "$base/api/v1/oauth/consent?client_id=$c1&redirect_uri=$cb&scope=openid") || { echo "login-smoke: consent form unreachable (is the session cookie missing?)"; return 1; }
	csrf=$(printf '%s' "$page" | sed -n 's/.*name="csrf_token" value="\([^"]*\)".*/\1/p')
	loc=$(curl -s -o /dev/null -w '%{redirect_url}' -b "$jar" -c "$jar" -X POST "$base/api/v1/oauth/consent" \
		--data-urlencode "action=approve" \
		--data-urlencode "csrf_token=$csrf" \
		--data-urlencode "client_id=$c1" \
		--data-urlencode "redirect_uri=$cb" \
		--data-urlencode "response_type=code" \
		--data-urlencode "scope=openid" \
		--data-urlencode "state=smoke-state" \
		--data-urlencode "nonce=smoke-nonce" \
		--data-urlencode "code_challenge=$challenge" \
		--data-urlencode "code_challenge_method=S256")
	case "$loc" in
	*code=*) echo "login-smoke: PASS — org_user completed browser-login + consent and received an authorization code" ;;
	*) echo "login-smoke: consent approve did not yield a code (redirect: $(printf '%s' "${loc:-none}" | redact))"; return 1 ;;
	esac

	# And with consent stored, a plain authorize on the SAME session mints a
	# code directly — the exact request the suite's browser makes.
	loc=$(curl -s -o /dev/null -w '%{redirect_url}' -b "$jar" \
		"$base/api/v1/oauth/authorize?client_id=$c1&redirect_uri=$(printf '%s' "$cb" | sed 's/:/%3A/g;s|/|%2F|g')&response_type=code&scope=openid&state=smoke2&nonce=smoke2&code_challenge=$challenge&code_challenge_method=S256")
	case "$loc" in
	*code=*) echo "login-smoke: PASS — authorize on the logged-in session mints a code" ;;
	*) echo "login-smoke: authorize on the logged-in session did not mint a code (redirect: $(printf '%s' "${loc:-none}" | redact))"; return 1 ;;
	esac
}
if [ -z "${CONFORMANCE_STUB_STACK:-}" ]; then
	echo "openid-conformance: login smoke (org_user in the conformance organization)"
	login_smoke || fail "the OP-native login/consent ceremony is broken for the provisioned org_user — fix the appliance or the provisioner before reading suite verdicts"
fi

# ── run the plans, floor semantics, verdicts verbatim ───────────────────────
run_plan() { # <plan[variants]> <config> <expected-failures> <expected-skips>
	if [ -n "${CONFORMANCE_STUB_PLAN:-}" ]; then
		# The stub receives the plan name as $1 so a contract test can give
		# each plan a different scripted verdict.
		bash -c "$CONFORMANCE_STUB_PLAN" _ "$1"
		return $?
	fi
	(
		mkdir -p "$WORK/export" # run-test-plan.py --export-dir needs it to exist
		cd "$CACHE" || exit 2
		if [ ! -d .venv ]; then
			python3 -m venv .venv && ./.venv/bin/pip -q install -r scripts/requirements.txt || exit 2
		fi
		CONFORMANCE_SERVER="https://localhost.emobix.co.uk:28443/" \
			CONFORMANCE_DEV_MODE=1 DISABLE_SSL_VERIFY=1 \
			./.venv/bin/python scripts/run-test-plan.py \
			--verbose \
			--export-dir "$WORK/export" \
			$RERUN_ARGS \
			--expected-failures-file "$3" \
			--expected-skips-file "$4" \
			"$1" "$2"
	)
}

overall=0
if [ -z "${CONFORMANCE_MODULE:-}" ]; then
	echo "openid-conformance: PLAN 1/2 — oidcc-config-certification-test-plan"
	run_plan "oidcc-config-certification-test-plan" "$WORK/plan-config.json" \
		"$HERE/expected-failures-config.json" "$HERE/expected-skips-config.json" || overall=1
fi

echo "openid-conformance: PLAN 2/2 — oidcc-basic-certification-test-plan"
# FLOOR FOR INCOMPLETE MODULES the suite's expected-failures format cannot
# express (see expected-basic-incomplete.txt): prompt=login / max_age=1 end
# stuck in WAITING (the re-auth finding), which run-test-plan counts as
# "did not run to completion" regardless of the expected-failures files.
# The plan is GREEN-AGAINST-FLOOR only when the incomplete-module set
# EQUALS the recorded list exactly AND no other failure marker fired; a
# plan that IMPROVES (the recorded modules complete) also fails, so the
# floor moves only by deliberately re-recording it.
BASIC_LOG="$WORK/plan-basic-output.log"
run_plan "oidcc-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client]" \
	"$WORK/plan-basic.json" \
	"$HERE/expected-failures-basic.json" "$HERE/expected-skips-basic.json" 2>&1 | tee "$BASIC_LOG"
basic_ec=${PIPESTATUS[0]}
# THE-JAR-REQUEST-OBJECT: when the basic plan is not green, surface the
# suite SERVER's own exception trail before teardown erases it — an
# INTERRUPTED module prints nothing useful in the runner output.
if [ "$basic_ec" -ne 0 ] && [ -z "${CONFORMANCE_STUB_STACK:-}" ]; then
	echo "openid-conformance: FAILURE / INTERRUPTED entries from the exported module logs ($WORK/export):"
	{ python3 - "$WORK/export" <<'PY' || true
import glob, json, os, sys
for path in sorted(glob.glob(os.path.join(sys.argv[1], "**", "*.json"), recursive=True)):
    try:
        doc = json.load(open(path))
    except Exception as e:  # noqa: BLE001
        print("  (unreadable export)", path, e); continue
    entries = doc.get("results") if isinstance(doc, dict) else doc
    if not isinstance(entries, list):
        continue
    for e in entries:
        if not isinstance(e, dict):
            continue
        res = str(e.get("result", ""))
        if res in ("FAILURE", "INTERRUPTED", "WARNING"):
            print("  [%s] %s :: %s" % (res, e.get("src", ""), str(e.get("msg", ""))[:300]))
            for k in ("expected", "actual", "error", "error_description", "stacktrace"):
                if k in e:
                    print("      %s: %s" % (k, str(e[k])[:300]))
PY
	} | redact
	echo "openid-conformance: suite server log (exceptions/errors, tail) for diagnosis:"
	compose logs --no-color --tail 600 server 2>/dev/null | grep -iE -A8 'exception|error|interrupt' | tail -120 | redact || true
fi
# THE-JAR-REQUEST-OBJECT: a FULL run regenerates the committed module-order
# file MODULE mode resolves indices from; a changed order shows up in git.
if [ -z "${CONFORMANCE_MODULE:-}" ]; then
	{
		echo "# oidcc-basic-certification-test-plan module order — 1-based run-test-plan --rerun index. Regenerated by conformance/run.sh from every FULL run; MODULE=<name> resolves its index here."
		grep -oE '\[1:[0-9]+\] oidcc-[a-z0-9-]+' "$BASIC_LOG" | sed -E 's/\[1:([0-9]+)\] /\1 /' | sort -n -k1 | uniq
	} >"$WORK/plan-basic.modules.txt"
	# Never overwrite the committed order with an empty or tiny listing (a
	# run that died before the module list printed must not erase it).
	if [ "$(grep -cE '^[0-9]+ ' "$WORK/plan-basic.modules.txt")" -ge 10 ] && ! cmp -s "$WORK/plan-basic.modules.txt" "$MODULES_FILE"; then
		cp "$WORK/plan-basic.modules.txt" "$MODULES_FILE"
		echo "openid-conformance: NOTE — conformance/plan-basic.modules.txt regenerated (module order changed); commit it with the run"
	fi
fi
EXPECTED_INCOMPLETE=$(grep -v '^#' "$HERE/expected-basic-incomplete.txt" | grep -v '^$' | sort)
if [ "$basic_ec" -eq 0 ]; then
	if [ -n "$EXPECTED_INCOMPLETE" ]; then
		echo "openid-conformance: oidcc-basic-certification-test-plan RAN TO FULL COMPLETION — the recorded incomplete modules (see conformance/expected-basic-incomplete.txt) no longer stall. The floor MOVED: re-measure and re-record the expected files deliberately."
		overall=1
	else
		echo "openid-conformance: oidcc-basic-certification-test-plan green against the committed expected-failures floor"
	fi
else
	# Extract the "Incomplete test modules:" names (indented lines of the
	# form '  <module-name> <id> (status: ...)').
	ACTUAL_INCOMPLETE=$(sed -n '/Incomplete test modules:/,$p' "$BASIC_LOG" | sed -n 's/^.\{0,25\}  \(oidcc-[a-z0-9-]*\) [A-Za-z0-9]* (status: .*$/\1/p' | sort -u)
	if [ -n "$EXPECTED_INCOMPLETE" ] && [ "$ACTUAL_INCOMPLETE" = "$EXPECTED_INCOMPLETE" ] &&
		! grep -q 'unexpected condition failures/warnings' "$BASIC_LOG" &&
		! grep -q 'expected failures were not found' "$BASIC_LOG" &&
		! grep -q 'expected skips were not found' "$BASIC_LOG" &&
		! grep -q 'UNEXPECTEDLY SKIPPED' "$BASIC_LOG" &&
		! grep -q 'EXPECTED TO BE SKIPPED BUT COMPLETED' "$BASIC_LOG"; then
		echo "openid-conformance: oidcc-basic-certification-test-plan incomplete EXACTLY as recorded (re-auth finding; see conformance/expected-basic-incomplete.txt) — green against the committed floor"
	else
		echo "openid-conformance: oidcc-basic-certification-test-plan failed BEYOND the recorded floor — an unexpected change; read the output above"
		overall=1
	fi
fi

if [ "$overall" -ne 0 ]; then
	echo "openid-conformance: RESULT: FAIL — unexpected failures above (or an expected failure that now passes; update the expected files deliberately, floor semantics)"
else
	echo "openid-conformance: RESULT: GREEN against the committed expected-failure floor"
fi
exit "$overall"
