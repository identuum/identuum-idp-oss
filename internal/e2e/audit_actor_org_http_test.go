//go:build integration

// Package e2e — OSS-FIN-3: the audit log says who did what to which
// organization, through the whole OSS engine (runtime.New + Start on the
// test database).
//
//   - Every row carries its actor, filled centrally from the authenticated
//     principal (user, client, service_account, setup_token, system), and
//     "anonymous" only where no principal exists. The census below counts
//     the rows these flows wrote (tagged by a per-run User-Agent): no empty
//     actor_type, and anonymous only for the named anonymous-by-design
//     events.
//   - Every row that concerns an organization carries the organization acted
//     upon (organization_id), not the actor's.
//   - An org_admin's GET /api/v1/audit/events returns every row of its own
//     organization, whoever acted — the site_admin included — and none of
//     another organization's.
//
// Tokens and passwords are never printed.
package e2e

import (
	"encoding/json"
	"io"
	"net/http"
	"sort"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// anonymousByDesign are the events a caller without a principal produces.
var anonymousByDesign = map[string]bool{
	"user_session.login.failure": true,
}

func TestE2E_OSS_AuditActorAndOrganization(t *testing.T) {
	w := startInviteEngine(t, map[string]string{"UI": inviteUIBase, "IDENTUUM_IDP_RATE_LIMIT_LOGIN_REQUESTS": "1000"})
	db := w.pool
	ua := "fin3-census-" + uuid.NewString()
	call := func(bearer, method, path, body string) (int, map[string]any) {
		t.Helper()
		req, _ := http.NewRequest(method, w.base+path, strings.NewReader(body))
		req.Header.Set("User-Agent", ua)
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		defer res.Body.Close()
		raw, _ := io.ReadAll(res.Body)
		var m map[string]any
		_ = json.Unmarshal(raw, &m)
		return res.StatusCode, m
	}
	must := func(want, st int, what string) {
		t.Helper()
		if st != want {
			t.Fatalf("%s = %d; want %d", what, st, want)
		}
	}

	// ── The flows ──────────────────────────────────────────────────────────
	st, _ := call("", http.MethodPost, "/api/v1/auth/login", `{"email":"nobody-`+uuid.NewString()+`@example.invalid","password":"wrong-password-1"}`)
	if st == http.StatusOK {
		t.Fatalf("a sign-in with an unknown email succeeded")
	}
	st, _ = call(w.bearers["adminA"], http.MethodPost, "/api/v1/users", `{"email":"fin3-a-`+uuid.NewString()+`@example.invalid","name":"Invited A"}`)
	must(http.StatusCreated, st, "org_admin A invites a user")
	st, pm := call(w.bearers["adminA"], http.MethodPost, "/api/v1/users", `{"email":"fin3-pw-`+uuid.NewString()+`@example.invalid","password":"Fin3-Pass-2026!x","role":"org_user"}`)
	must(http.StatusCreated, st, "org_admin A creates a user with a password")
	pwUser, _ := pm["id"].(string)
	pwEmail, _ := pm["email"].(string)
	st, _ = call("", http.MethodPost, "/api/v1/auth/login", `{"email":"`+pwEmail+`","password":"Fin3-Pass-2026!x"}`)
	must(http.StatusUnauthorized, st, "the created user's first sign-in stops at the change step")
	st, _ = call(w.bearers["adminA"], http.MethodPut, "/api/v1/users/"+pwUser, `{"name":"Renamed A"}`)
	must(http.StatusOK, st, "org_admin A renames the user")
	st, _ = call(w.bearers["adminA"], http.MethodPost, "/api/v1/clients", `{"name":"fin3-app","redirect_uris":["https://rp.example.test/cb"],"scope":"openid"}`)
	must(http.StatusCreated, st, "org_admin A creates a client")
	st, _ = call(w.bearers["adminB"], http.MethodPost, "/api/v1/users", `{"email":"fin3-b-`+uuid.NewString()+`@example.invalid","name":"Invited B"}`)
	must(http.StatusCreated, st, "org_admin B invites a user")
	st, _ = call(w.bearers["site"], http.MethodPut, "/api/v1/organizations/"+w.orgA.ID.String(), `{"name":"Fin3 Org A `+uuid.NewString()[:8]+`"}`)
	must(http.StatusOK, st, "site_admin changes organization A")

	// ── 1. The actor on every row ──────────────────────────────────────────
	rows, err := db.Query(w.ctx, `SELECT event_type, actor_type, coalesce(actor_id::text, ''), coalesce(organization_id::text, '') FROM audit_events WHERE user_agent = $1`, ua)
	if err != nil {
		t.Fatalf("census query: %v", err)
	}
	type row struct{ event, actorType, actorID, org string }
	var census []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.event, &r.actorType, &r.actorID, &r.org); err != nil {
			t.Fatalf("census scan: %v", err)
		}
		census = append(census, r)
	}
	rows.Close()
	if len(census) < 6 {
		t.Fatalf("census found %d rows for the flows; want at least 6", len(census))
	}
	var empty, anonOutside []string
	for _, r := range census {
		switch {
		case r.actorType == "":
			empty = append(empty, r.event)
		case r.actorType == "anonymous" && !anonymousByDesign[r.event]:
			anonOutside = append(anonOutside, r.event)
		case r.actorType != "anonymous" && r.actorID == "":
			empty = append(empty, r.event+" (type "+r.actorType+", no actor_id)")
		}
	}
	sort.Strings(empty)
	if len(empty) != 0 || len(anonOutside) != 0 {
		t.Errorf("census over %d rows: empty actor %v; anonymous outside the named list %v", len(census), empty, anonOutside)
	}

	// ── 2. The organization acted upon ─────────────────────────────────────
	var siteRow struct{ id, actorType, actorID, org, actorOrg string }
	if err := db.QueryRow(w.ctx, `SELECT id::text, actor_type, coalesce(actor_id::text, ''), coalesce(organization_id::text, ''), coalesce(actor_organization_id::text, '')
		FROM audit_events WHERE user_agent = $1 AND event_type = 'organization.updated'`, ua).Scan(&siteRow.id, &siteRow.actorType, &siteRow.actorID, &siteRow.org, &siteRow.actorOrg); err != nil {
		t.Fatalf("read the site_admin's organization.updated row: %v", err)
	}
	if siteRow.org != w.orgA.ID.String() || siteRow.actorType != "user" || siteRow.actorID == "" || siteRow.actorOrg == w.orgA.ID.String() {
		t.Errorf("site_admin's organization.updated: organization %q actor_type %q actor_id set %v actor_org is A %v; want organization A, a user actor, the site_admin's own organization as actor_org",
			siteRow.org, siteRow.actorType, siteRow.actorID != "", siteRow.actorOrg == w.orgA.ID.String())
	}
	for _, r := range census {
		if strings.HasPrefix(r.event, "user.") || r.event == "client.created" || r.event == "user_created" {
			if r.org != w.orgA.ID.String() && r.org != w.orgB.ID.String() {
				t.Errorf("%s carries organization %q; want the organization acted upon", r.event, r.org)
			}
		}
	}

	// ── 3. The org_admin's view ────────────────────────────────────────────
	list := func(who string) []map[string]any {
		st, m := call(w.bearers[who], http.MethodGet, "/api/v1/audit/events?limit=200", "")
		must(http.StatusOK, st, who+" reads the audit log")
		evs, _ := m["events"].([]any)
		out := make([]map[string]any, 0, len(evs))
		for _, e := range evs {
			if mm, ok := e.(map[string]any); ok {
				out = append(out, mm)
			}
		}
		return out
	}
	seesSite, seesUserEvents := false, false
	for _, e := range list("adminA") {
		if e["organization_id"] != w.orgA.ID.String() && e["actor_organization_id"] != w.orgA.ID.String() {
			t.Errorf("org_admin A sees a row of another organization (%v)", e["event_type"])
		}
		if e["id"] == siteRow.id {
			seesSite = e["actor_role"] == "site_admin" && e["actor_type"] == "user"
		}
		if et, _ := e["event_type"].(string); strings.HasPrefix(et, "user.") {
			seesUserEvents = true
		}
	}
	if !seesSite || !seesUserEvents {
		t.Errorf("org_admin A sees the site_admin's change with its actor %v, its user.* events %v; want both", seesSite, seesUserEvents)
	}
	for _, e := range list("adminB") {
		if e["organization_id"] == w.orgA.ID.String() || e["id"] == siteRow.id {
			t.Errorf("org_admin B sees organization A's row %v", e["event_type"])
		}
	}
}
