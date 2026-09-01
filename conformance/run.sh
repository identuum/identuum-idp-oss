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
# ISOLATION: one dedicated compose project (identuum-conformance) holds both
# stacks on one network, with host ports 127.0.0.1:28443/28444 (suite) and
# 127.0.0.1:27113 (OP, provisioning glue only). The dev stack, its ports and
# its data are never touched. Teardown is `down --volumes` on the project —
# both stacks, all volumes, one trap. Only the cached suite clone (and its
# python venv) survive between runs.
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
#   CONFORMANCE_STUB_STACK=1     skips clone/pull/up/wait/provision
#   (a fake `docker` earlier on PATH records the compose invocations)
set -u

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO=$(dirname "$HERE")
CACHE="$REPO/.conformance-suite"
PIN_FILE="$HERE/PIN"
PROJECT="identuum-conformance"

# The one pinned truth about the suite version.
PIN_TAG=$(sed -n 's/^tag: //p' "$PIN_FILE")
PIN_SHA=$(sed -n 's/^sha: //p' "$PIN_FILE")

COMPOSE_FILES=(-f "$CACHE/docker-compose-prebuilt.yml" -f "$HERE/compose.suite-override.yml" -f "$HERE/compose.appliance.yml" -f "$HERE/compose.tls.yml")

compose() {
	IMAGE_TAG="$PIN_TAG" docker compose -p "$PROJECT" "${COMPOSE_FILES[@]}" "$@"
}

WORK=""
teardown() {
	ec=$?
	echo "openid-conformance: teardown (down --volumes on project $PROJECT — both stacks, every volume; the cached clone survives)"
	if [ -z "${CONFORMANCE_STUB_STACK:-}" ] || [ -n "${CONFORMANCE_STUB_TEARDOWN:-}" ]; then
		compose down --volumes --remove-orphans || true
	fi
	[ -n "$WORK" ] && rm -rf "$WORK"
	exit "$ec"
}
trap teardown EXIT INT TERM

fail() { echo "openid-conformance: $*" >&2; exit 2; }

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

# ── stand everything up ─────────────────────────────────────────────────────
# https by default: the DO-3 measurement showed the suite RUNS against an
# http OP but fails every endpoint on scheme alone, drowning real findings.
CONFORMANCE_OP_ISSUER="${CONFORMANCE_OP_ISSUER:-https://conformance-op:8443}"
export CONFORMANCE_OP_ISSUER

# Per-run self-signed cert + nginx config for the TLS sidecar. The work dir
# lives INSIDE the repo (gitignored) because macOS Docker file sharing only
# covers shared paths — the default TMPDIR (/var/folders) is not mountable.
# Removed by teardown; never committed, never reused.
WORK=$(mktemp -d "$REPO/.conformance-work.XXXXXX")
export CONFORMANCE_TLS_DIR="$WORK"
if [ -z "${CONFORMANCE_STUB_STACK:-}" ]; then
	openssl req -x509 -newkey rsa:2048 -keyout "$WORK/op.key" -out "$WORK/op.crt" \
		-days 2 -nodes -subj "/CN=conformance-op" \
		-addext "subjectAltName=DNS:conformance-op" >/dev/null 2>&1 || fail "self-signed cert generation failed"
	cat >"$WORK/default.conf" <<'NGINX'
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
	# FRESH is a guarantee, not an assumption: a previous run that was kept
	# or crashed leaves volumes `up -d` would silently reuse — measured as a
	# bootstrap that "skips create" against a stale database and a
	# provisioner that cannot log in. Torn down BEFORE standing up.
	compose down --volumes --remove-orphans >/dev/null 2>&1 || true

	echo "openid-conformance: pulling pinned suite images ($PIN_TAG) + building the appliance"
	compose pull mongodb nginx server || fail "image pull failed"
	compose build conformance-idp || fail "appliance build failed"
	compose up -d || fail "compose up failed"

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
	# PKCE pair (the OP mandates PKCE; a recorded conformance finding).
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
	*) echo "login-smoke: consent approve did not yield a code (redirect: ${loc:-none})"; return 1 ;;
	esac

	# And with consent stored, a plain authorize on the SAME session mints a
	# code directly — the exact request the suite's browser makes.
	loc=$(curl -s -o /dev/null -w '%{redirect_url}' -b "$jar" \
		"$base/api/v1/oauth/authorize?client_id=$c1&redirect_uri=$(printf '%s' "$cb" | sed 's/:/%3A/g;s|/|%2F|g')&response_type=code&scope=openid&state=smoke2&nonce=smoke2&code_challenge=$challenge&code_challenge_method=S256")
	case "$loc" in
	*code=*) echo "login-smoke: PASS — authorize on the logged-in session mints a code" ;;
	*) echo "login-smoke: authorize on the logged-in session did not mint a code (redirect: ${loc:-none})"; return 1 ;;
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
		cd "$CACHE" || exit 2
		if [ ! -d .venv ]; then
			python3 -m venv .venv && ./.venv/bin/pip -q install -r scripts/requirements.txt || exit 2
		fi
		CONFORMANCE_SERVER="https://localhost.emobix.co.uk:28443/" \
			CONFORMANCE_DEV_MODE=1 DISABLE_SSL_VERIFY=1 \
			./.venv/bin/python scripts/run-test-plan.py \
			--verbose \
			--expected-failures-file "$3" \
			--expected-skips-file "$4" \
			"$1" "$2"
	)
}

overall=0
echo "openid-conformance: PLAN 1/2 — oidcc-config-certification-test-plan"
run_plan "oidcc-config-certification-test-plan" "$WORK/plan-config.json" \
	"$HERE/expected-failures-config.json" "$HERE/expected-skips-config.json" || overall=1

echo "openid-conformance: PLAN 2/2 — oidcc-basic-certification-test-plan"
# FLOOR FOR AN ABORT the suite's expected-failures format cannot express
# (see expected-basic-abort.txt): the OP mandates PKCE, the Basic profile is
# plain code, every browser module goes INTERRUPTED and the circuit breaker
# aborts. The plan is GREEN-AGAINST-FLOOR only when the abort matches the
# recorded signature exactly; a plan that IMPROVES also fails, so the floor
# moves only by deliberately re-recording it.
BASIC_LOG="$WORK/plan-basic-output.log"
run_plan "oidcc-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client]" \
	"$WORK/plan-basic.json" \
	"$HERE/expected-failures-basic.json" "$HERE/expected-skips-basic.json" 2>&1 | tee "$BASIC_LOG"
basic_ec=${PIPESTATUS[0]}
EXPECTED_ABORT=$(grep -v '^#' "$HERE/expected-basic-abort.txt" | grep -v '^$' | head -1)
if [ "$basic_ec" -eq 0 ]; then
	echo "openid-conformance: BASIC PLAN COMPLETED — the recorded PKCE abort no longer happens. The floor MOVED: re-measure, update expected-basic-abort.txt (or retire it) and the expected-failures files deliberately."
	overall=1
elif grep -qF "$EXPECTED_ABORT" "$BASIC_LOG"; then
	echo "openid-conformance: basic plan aborted exactly as recorded (mandatory-PKCE finding; see conformance/expected-basic-abort.txt) — green against the committed floor"
else
	echo "openid-conformance: basic plan failed DIFFERENTLY than the recorded abort — an unexpected change; read the output above"
	overall=1
fi

if [ "$overall" -ne 0 ]; then
	echo "openid-conformance: RESULT: FAIL — unexpected failures above (or an expected failure that now passes; update the expected files deliberately, floor semantics)"
else
	echo "openid-conformance: RESULT: GREEN against the committed expected-failure floor"
fi
exit "$overall"
