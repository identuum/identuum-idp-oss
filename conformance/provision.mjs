// conformance/provision.mjs — THE-CONFORMANCE-HARNESS.
//
// Provisions the conformance fixtures on the FRESH disposable appliance:
// one organization (mfa_policy=optional), one test user WITHOUT MFA, and two
// confidential OAuth clients registered for the suite's callback.
//
// This is the SAME API provisioning path the e2e-full provisioner drives
// (bootstrapped site_admin -> org -> activation -> org_admin -> resources).
// The e2e provisioner spec itself TOTP-enrolls every principal, which the
// suite's static browser automation cannot type — so the conformance user is
// deliberately provisioned WITHOUT MFA on an mfa_policy=optional org.
//
// stdout: exactly one JSON line {client1_id, client1_secret, client2_id,
// client2_secret} for run.sh to substitute into the plan config. Secrets go
// no further than the gitignored work directory of one run.
import { createHmac } from "node:crypto";

const BASE = process.env.CONFORMANCE_OP_BASE ?? "http://127.0.0.1:27113";
const ADMIN_PW = process.env.IDENTUUM_IDP_BOOTSTRAP_PASSWORD;
const USER_PW = process.env.CONFORMANCE_USER_PASSWORD;
const CALLBACK = process.env.CONFORMANCE_CALLBACK ?? "https://localhost.emobix.co.uk:8443/test/a/identuum-oss/callback";
if (!ADMIN_PW || !USER_PW) {
  console.error("provision: IDENTUUM_IDP_BOOTSTRAP_PASSWORD and CONFORMANCE_USER_PASSWORD are required");
  process.exit(2);
}

function b32(s) {
  const A = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let b = 0, v = 0;
  const o = [];
  for (const c of s.toUpperCase().replace(/=+$/, "")) {
    v = (v << 5) | A.indexOf(c);
    b += 5;
    if (b >= 8) { o.push((v >> (b - 8)) & 255); b -= 8; }
  }
  return Buffer.from(o);
}
const totp = (secret, drift = 0) => {
  const k = b32(secret);
  const step = Math.floor(Date.now() / 1000 / 30) + drift;
  const c = Buffer.alloc(8);
  c.writeBigUInt64BE(BigInt(step));
  const d = createHmac("sha1", k).update(c).digest();
  const off = d[d.length - 1] & 15;
  return (((d.readUInt32BE(off) & 0x7fffffff) % 1e6) + "").padStart(6, "0");
};

async function api(method, path, body, token) {
  const headers = { "Content-Type": "application/json" };
  if (token) headers.Authorization = `Bearer ${token}`;
  const res = await fetch(BASE + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  const text = await res.text();
  let json = {};
  try { json = text ? JSON.parse(text) : {}; } catch { json = { _raw: text.slice(0, 200) }; }
  return { status: res.status, json };
}
function must(r, want, what) {
  if (r.status !== want) {
    console.error(`provision: ${what} -> ${r.status} (${JSON.stringify(r.json).slice(0, 200)})`);
    process.exit(1);
  }
  return r.json;
}

// 1. site_admin: first login enrolls TOTP (bootstrap ships none).
const login = await api("POST", "/api/v1/auth/login", { email: "site_admin@system.local", password: ADMIN_PW });
let saToken = login.json.access_token;
if (!saToken) {
  const sid = login.json.session_id;
  const init = must(await api("POST", "/api/v1/auth/login/mfa/enroll/initiate", { session_id: sid }), 200, "mfa enroll initiate");
  let done = await api("POST", "/api/v1/auth/login/mfa/enroll/complete", { session_id: sid, code: totp(init.secret, 0) });
  if (done.status !== 200) done = await api("POST", "/api/v1/auth/login/mfa/enroll/complete", { session_id: sid, code: totp(init.secret, 1) });
  saToken = must(done, 200, "mfa enroll complete").access_token;
}

// 2. The conformance organization + its org_admin, activated via the link.
const org = must(await api("POST", "/api/v1/organizations", {
  name: "Conformance Org", slug: "conformance", domain: "conformance.test",
  admin_email: "admin@conformance.test",
}, saToken), 201, "create org");
const orgId = org.organization?.id;
const resend = must(await api("POST", `/api/v1/organizations/${orgId}/resend-activation`, {}, saToken), 200, "resend activation");
const tokenFromLink = resend.activation_url ? new URL(resend.activation_url).searchParams.get("token") : resend.activation_token;
must(await api("POST", "/api/v1/auth/organizations/activate", { token: tokenFromLink, password: USER_PW + "-Adm1n" }), 200, "activate org_admin");

// 3. mfa_policy=optional so a NO-MFA user can complete the browser login.
must(await api("PUT", `/api/v1/organizations/${orgId}`, { mfa_policy: "optional" }, saToken), 200, "set mfa_policy optional");

// 4. org_admin session (fresh admin: enroll its required TOTP once).
const aLogin = await api("POST", "/api/v1/auth/login", { email: "admin@conformance.test", password: USER_PW + "-Adm1n" });
let oaToken = aLogin.json.access_token;
if (!oaToken) {
  const sid = aLogin.json.session_id;
  const init = must(await api("POST", "/api/v1/auth/login/mfa/enroll/initiate", { session_id: sid }), 200, "org_admin mfa initiate");
  let done = await api("POST", "/api/v1/auth/login/mfa/enroll/complete", { session_id: sid, code: totp(init.secret, 0) });
  if (done.status !== 200) done = await api("POST", "/api/v1/auth/login/mfa/enroll/complete", { session_id: sid, code: totp(init.secret, 1) });
  oaToken = must(done, 200, "org_admin mfa complete").access_token;
}

// 5. The conformance test user — NO MFA, plain password login. Login
// refuses an unverified account (measured: 401 account_unverified), and no
// mail flows in the harness, so the org_admin marks the address verified —
// the same email_verified flag the admin update API exposes.
const created = must(await api("POST", "/api/v1/users", {
  email: "conformance-user@conformance.test", password: USER_PW,
  name: "Conformance User", role: "org_user",
}, oaToken), 201, "create test user");
const userId = created.user?.id ?? created.id;
must(await api("PUT", `/api/v1/users/${userId}`, { email_verified: true }, oaToken), 200, "mark test user verified");

// 5b. SELF-CHECK: the test user must be able to log in with exactly the
// password the browser automation will type. Failing here names the real
// error; failing later looks like a suite timeout.
{
  const check = await api("POST", "/api/v1/auth/login", { email: "conformance-user@conformance.test", password: USER_PW });
  if (check.status !== 200 || !check.json.access_token) {
    console.error(`provision: test-user JSON login self-check -> ${check.status} (${JSON.stringify(check.json).slice(0, 200)})`);
    process.exit(1);
  }
}

// 6. Two confidential clients registered for the suite callback.
const c1 = must(await api("POST", "/api/v1/clients", {
  name: "Conformance Client One", redirect_uris: [CALLBACK], scope: "openid",
}, oaToken), 201, "create client1");
const c2 = must(await api("POST", "/api/v1/clients", {
  name: "Conformance Client Two", redirect_uris: [CALLBACK], scope: "openid",
}, oaToken), 201, "create client2");

process.stdout.write(JSON.stringify({
  client1_id: c1.client?.client_id, client1_secret: c1.client_secret,
  client2_id: c2.client?.client_id, client2_secret: c2.client_secret,
}) + "\n");
