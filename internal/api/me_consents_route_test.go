package api

// D3 (self-service consents). GET /api/v1/me/consents lists the caller's
// ACTIVE OAuth consents (oauth_consents via ConsentService), one entry per
// client_id across audiences, joined to the live client for its name; DELETE
// /api/v1/me/consents/:client_id revokes every audience row of (caller,
// client) AND the caller's refresh tokens for that client, denylisting the
// access JTIs linked to them, and records an audit event.
//
// Driven through the REAL router (NewOSSEngine) on deps that already exist in
// OSSRouterDeps (ConsentService, RefreshTokenService, TokenRevocationService,
// ClientRepo), with in-memory stores.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/repository"
	"github.com/identuum/identuum-idp-oss/internal/server"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// ---------- in-memory stores ----------

// d3ConsentRepo is the oauth_consents store. The embedded interface keeps the
// fake compiling if the slice names its new methods differently; such a call
// then panics loudly instead of passing.
type d3ConsentRepo struct {
	repository.OAuthConsentRepository
	mu   sync.Mutex
	rows map[string]*domain.OAuthConsent
}

func d3ConsentKey(u uuid.UUID, client, aud string) string {
	return u.String() + "|" + client + "|" + aud
}

func (r *d3ConsentRepo) Upsert(_ context.Context, c *domain.OAuthConsent) (*domain.OAuthConsent, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	k := d3ConsentKey(c.UserID, c.ClientID, c.Audience)
	if ex, ok := r.rows[k]; ok {
		ex.Scope, ex.Claims, ex.GrantedAt, ex.RevokedAt, ex.UpdatedAt = c.Scope, c.Claims, c.GrantedAt, nil, c.GrantedAt
		cp := *ex
		return &cp, nil
	}
	cp := *c
	cp.CreatedAt, cp.UpdatedAt = c.GrantedAt, c.GrantedAt
	r.rows[k] = &cp
	out := cp
	return &out, nil
}

func (r *d3ConsentRepo) GetActive(_ context.Context, u uuid.UUID, client, aud string) (*domain.OAuthConsent, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	row, ok := r.rows[d3ConsentKey(u, client, aud)]
	if !ok || row.RevokedAt != nil {
		return nil, nil
	}
	cp := *row
	return &cp, nil
}

func (r *d3ConsentRepo) Revoke(_ context.Context, u uuid.UUID, client, aud string, at time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if row, ok := r.rows[d3ConsentKey(u, client, aud)]; ok && row.RevokedAt == nil {
		row.RevokedAt = &at
	}
	return nil
}

// ListActiveByUser mirrors the pgx query: user_id = $1 AND revoked_at IS NULL.
func (r *d3ConsentRepo) ListActiveByUser(_ context.Context, u uuid.UUID) ([]*domain.OAuthConsent, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []*domain.OAuthConsent
	for _, row := range r.rows {
		if row.UserID == u && row.RevokedAt == nil {
			cp := *row
			out = append(out, &cp)
		}
	}
	return out, nil
}

// RevokeAllForClient mirrors the pgx UPDATE: every active audience row of
// (user, client); returns the rows flipped.
func (r *d3ConsentRepo) RevokeAllForClient(_ context.Context, u uuid.UUID, client string, at time.Time) (int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var n int64
	for _, row := range r.rows {
		if row.UserID == u && row.ClientID == client && row.RevokedAt == nil {
			t := at
			row.RevokedAt = &t
			n++
		}
	}
	return n, nil
}

// d3RefreshRepo is the oauth_refresh_tokens store.
type d3RefreshRepo struct {
	mu   sync.Mutex
	byID map[uuid.UUID]*domain.RefreshToken
}

func (r *d3RefreshRepo) Insert(_ context.Context, rt *domain.RefreshToken) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	cp := *rt
	r.byID[rt.ID] = &cp
	return nil
}

func (r *d3RefreshRepo) GetByID(_ context.Context, id uuid.UUID) (*domain.RefreshToken, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	row, ok := r.byID[id]
	if !ok {
		return nil, nil
	}
	cp := *row
	return &cp, nil
}

func (r *d3RefreshRepo) MarkRevoked(_ context.Context, id uuid.UUID, at time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if row, ok := r.byID[id]; ok {
		row.RevokedAt = &at
	}
	return nil
}

func (r *d3RefreshRepo) MarkRotated(_ context.Context, oldID, newID uuid.UUID, at time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	row, ok := r.byID[oldID]
	if !ok {
		return nil
	}
	if row.RevokedAt != nil {
		return repository.ErrRefreshAlreadyRotated
	}
	row.RevokedAt, row.LastUsedAt, row.ReplacedBy = &at, &at, &newID
	return nil
}

func (r *d3RefreshRepo) SetAccessJTI(_ context.Context, id uuid.UUID, jti string, _ time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if row, ok := r.byID[id]; ok {
		row.AccessJTI = jti
	}
	return nil
}

func (r *d3RefreshRepo) revokeWhere(match func(*domain.RefreshToken) bool, at time.Time) (int64, []repository.RevokedRefreshTokenAccessJTI) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var n int64
	var jtis []repository.RevokedRefreshTokenAccessJTI
	for _, row := range r.byID {
		if row.RevokedAt == nil && match(row) {
			t := at
			row.RevokedAt = &t
			n++
			if row.AccessJTI != "" {
				jtis = append(jtis, repository.RevokedRefreshTokenAccessJTI{JTI: row.AccessJTI, ExpiresAt: row.ExpiresAt})
			}
		}
	}
	return n, jtis
}

func (r *d3RefreshRepo) RevokeAllBySubject(_ context.Context, subject string, at time.Time) (int64, error) {
	n, _ := r.revokeWhere(func(row *domain.RefreshToken) bool { return row.Subject == subject }, at)
	return n, nil
}

func (r *d3RefreshRepo) RevokeByFamily(_ context.Context, family string, at time.Time) (int64, error) {
	n, _ := r.revokeWhere(func(row *domain.RefreshToken) bool { return family != "" && row.FamilyID == family }, at)
	return n, nil
}

func (r *d3RefreshRepo) DeleteExpiredBefore(context.Context, time.Time) (int64, error) { return 0, nil }

func (r *d3RefreshRepo) RevokeAllBySubjectReturningAccessJTIs(_ context.Context, subject string, at time.Time) (int64, []repository.RevokedRefreshTokenAccessJTI, error) {
	n, j := r.revokeWhere(func(row *domain.RefreshToken) bool { return row.Subject == subject }, at)
	return n, j, nil
}

func (r *d3RefreshRepo) RevokeByFamilyReturningAccessJTIs(_ context.Context, family string, at time.Time) (int64, []repository.RevokedRefreshTokenAccessJTI, error) {
	n, j := r.revokeWhere(func(row *domain.RefreshToken) bool { return family != "" && row.FamilyID == family }, at)
	return n, j, nil
}

func (r *d3RefreshRepo) RevokeAllByClientReturningAccessJTIs(_ context.Context, client string, at time.Time) (int64, []repository.RevokedRefreshTokenAccessJTI, error) {
	n, j := r.revokeWhere(func(row *domain.RefreshToken) bool { return row.ClientID == client }, at)
	return n, j, nil
}

// RevokeAllBySubjectAndClientReturningAccessJTIs mirrors the pgx
// UPDATE ... WHERE subject = $1 AND client_id = $2 AND revoked_at IS NULL.
func (r *d3RefreshRepo) RevokeAllBySubjectAndClientReturningAccessJTIs(_ context.Context, subject, client string, at time.Time) (int64, []repository.RevokedRefreshTokenAccessJTI, error) {
	if subject == "" || client == "" {
		return 0, nil, nil
	}
	n, j := r.revokeWhere(func(row *domain.RefreshToken) bool { return row.Subject == subject && row.ClientID == client }, at)
	return n, j, nil
}

// d3DenyRepo is the access-token jti denylist.
type d3DenyRepo struct {
	mu   sync.Mutex
	jtis map[string]bool
}

func (r *d3DenyRepo) Insert(_ context.Context, tr *domain.TokenRevocation) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.jtis[tr.Jti] = true
	return nil
}

func (r *d3DenyRepo) Exists(_ context.Context, jti string) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.jtis[jti], nil
}

func (r *d3DenyRepo) DeleteExpiredBefore(context.Context, time.Time) (int64, error) { return 0, nil }

// d3ClientRepo resolves only LIVE clients, as PgxClientRepository.
// GetClientByClientID does (deleted_at IS NULL): a deleted client answers
// domain.ErrClientNotFound.
type d3ClientRepo struct {
	repository.ClientRepository
	live map[string]*domain.Client
}

func (r *d3ClientRepo) GetClientByClientID(_ context.Context, clientID string) (*domain.Client, error) {
	if c, ok := r.live[clientID]; ok {
		cp := *c
		return &cp, nil
	}
	return nil, domain.ErrClientNotFound
}

type d3Verifier struct{ principals map[string]*domain.Principal }

func (v d3Verifier) VerifyBearerToken(_ context.Context, token string) (*domain.Principal, error) {
	if p, ok := v.principals[token]; ok {
		return p, nil
	}
	return nil, errors.New("stub: unknown bearer token")
}

type d3UserLookup struct{ users map[uuid.UUID]*domain.User }

func (l d3UserLookup) GetByID(_ context.Context, id uuid.UUID) (*domain.User, error) {
	if u, ok := l.users[id]; ok {
		cp := *u
		return &cp, nil
	}
	return nil, errors.New("stub: no such user")
}

type d3SessionRepo struct{ repository.SessionRepository }

// ---------- fixture ----------

type d3World struct {
	engine   *gin.Engine
	consents *service.ConsentService
	refresh  *service.RefreshTokenService
	denylist *service.TokenRevocationService
	audit    *audit.Recorder
	alice    uuid.UUID
	bob      uuid.UUID
	// raw refresh tokens, by owner/client
	aliceX, aliceY, bobB string
}

const (
	d3AliceToken = "alice-bearer"
	d3BobToken   = "bob-bearer"
	d3AliceXJTI  = "access-jti-alice-x"
)

func newD3World(t *testing.T) *d3World {
	t.Helper()
	ctx := context.Background()
	alice, bob := uuid.New(), uuid.New()
	org := uuid.New()
	users := d3UserLookup{users: map[uuid.UUID]*domain.User{
		alice: {ID: alice, OrganizationID: org, Email: "alice@example.com", Role: domain.RoleOrgUser, AuthSource: domain.AuthSourceLocal, EmailVerified: true},
		bob:   {ID: bob, OrganizationID: org, Email: "bob@example.com", Role: domain.RoleOrgUser, AuthSource: domain.AuthSourceLocal, EmailVerified: true},
	}}
	clients := &d3ClientRepo{live: map[string]*domain.Client{
		"client-x": {ID: uuid.New(), ClientID: "client-x", Name: "Expense App", OrganizationID: &org, GrantTypes: []string{"authorization_code", "refresh_token"}},
		"client-y": {ID: uuid.New(), ClientID: "client-y", Name: "Wiki", OrganizationID: &org, GrantTypes: []string{"authorization_code", "refresh_token"}},
		"client-b": {ID: uuid.New(), ClientID: "client-b", Name: "Bob Only", OrganizationID: &org, GrantTypes: []string{"authorization_code", "refresh_token"}},
		"client-z": {ID: uuid.New(), ClientID: "client-z", Name: "Revoked Earlier", OrganizationID: &org},
		// "client-gone" is deliberately absent: deleted.
	}}
	consentRepo := &d3ConsentRepo{rows: map[string]*domain.OAuthConsent{}}
	consents := service.NewConsentService(nil, consentRepo)
	grant := func(u uuid.UUID, client, aud, scope string) {
		t.Helper()
		if _, err := consents.Grant(ctx, service.GrantConsentInput{UserID: u, OrganizationID: &org, ClientID: client, Audience: aud, Scope: scope}); err != nil {
			t.Fatalf("seed consent %s/%s: %v", client, aud, err)
		}
	}
	grant(alice, "client-x", "", "openid profile")
	grant(alice, "client-x", "https://api.x.example/", "openid read:x")
	grant(alice, "client-y", "", "openid")
	grant(alice, "client-z", "", "openid")
	grant(alice, "client-gone", "", "openid")
	grant(bob, "client-b", "", "openid email")
	if err := consents.Revoke(ctx, alice, "client-z", ""); err != nil {
		t.Fatalf("seed revoke: %v", err)
	}

	denylist := service.NewTokenRevocationService(nil, &d3DenyRepo{jtis: map[string]bool{}})
	refresh := service.NewRefreshTokenService(nil, &d3RefreshRepo{byID: map[uuid.UUID]*domain.RefreshToken{}}, service.RefreshTokenServiceOptions{}).
		WithTokenRevocationService(denylist)
	issue := func(u uuid.UUID, client, jti string) string {
		t.Helper()
		got, err := refresh.Issue(ctx, service.IssueRefreshTokenInput{ClientID: client, Subject: u.String(), Scope: "openid offline_access", AccessJTI: jti})
		if err != nil {
			t.Fatalf("seed refresh %s: %v", client, err)
		}
		return got.Token
	}
	w := &d3World{consents: consents, refresh: refresh, denylist: denylist, audit: &audit.Recorder{}, alice: alice, bob: bob}
	w.aliceX = issue(alice, "client-x", d3AliceXJTI)
	w.aliceY = issue(alice, "client-y", "access-jti-alice-y")
	w.bobB = issue(bob, "client-b", "access-jti-bob-b")

	w.engine = NewOSSEngine(OSSRouterDeps{
		DiscoveryConfig: server.OIDCDiscoveryConfig{Issuer: "https://idp.test"},
		TokenVerifier: d3Verifier{principals: map[string]*domain.Principal{
			d3AliceToken: {UserID: alice, Sub: alice.String(), Role: domain.RoleOrgUser, OrganizationID: org},
			d3BobToken:   {UserID: bob, Sub: bob.String(), Role: domain.RoleOrgUser, OrganizationID: org},
		}},
		UserLookup:             users,
		UserSessionService:     service.NewUserSessionService(nil, d3SessionRepo{}, service.UserSessionServiceOptions{}),
		ConsentService:         consents,
		RefreshTokenService:    refresh,
		TokenRevocationService: denylist,
		ClientRepo:             clients,
		Audit:                  w.audit,
	})
	return w
}

func (w *d3World) do(method, path, bearer string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	req.Header.Set("Authorization", "Bearer "+bearer)
	rec := httptest.NewRecorder()
	w.engine.ServeHTTP(rec, req)
	return rec
}

type d3ConsentView struct {
	ClientID       string   `json:"client_id"`
	Name           string   `json:"name"`
	Scopes         []string `json:"scopes"`
	FirstGrantedAt string   `json:"first_granted_at"`
	LastGrantedAt  string   `json:"last_granted_at"`
}

type d3ListBody struct {
	Consents                   []d3ConsentView `json:"consents"`
	AccessTokenLifetimeSeconds int64           `json:"access_token_lifetime_seconds"`
}

// ---------- tests ----------

// Control (green before and after the slice): the fixture's premises hold, so
// a red below is the route's, not the fixture's. Alice's client-x consent is
// covered on both audiences, her client-x refresh token is redeemable and its
// access jti is not yet denylisted.
func TestMeConsents_FixturePremises(t *testing.T) {
	w := newD3World(t)
	ctx := context.Background()
	for _, aud := range []string{"", "https://api.x.example/"} {
		if d, err := w.consents.Lookup(ctx, w.alice, "client-x", aud, "openid"); err != nil || !d.Covered {
			t.Fatalf("PREMISE: alice/client-x audience %q not covered: %+v err=%v", aud, d, err)
		}
	}
	if revoked, _ := w.denylist.IsRevoked(ctx, d3AliceXJTI); revoked {
		t.Fatalf("PREMISE: access jti denylisted before any DELETE")
	}
	if _, err := w.refresh.Consume(ctx, service.ConsumeRefreshTokenInput{RawToken: w.aliceX, ClientID: "client-x"}); err != nil {
		t.Fatalf("PREMISE: alice's client-x refresh token not redeemable before DELETE: %v", err)
	}
}

// GET lists ONLY the caller's ACTIVE consents on LIVE clients: a revoked
// consent (client-z), a deleted client (client-gone) and another user's
// consent (client-b) never appear; client-x's two audience rows are one
// entry whose scopes are their union.
// RULE: SELF-CONSENT-LIST-1
func TestMeConsents_ListIgnoresRevokedDeletedAndOtherUsers(t *testing.T) {
	w := newD3World(t)
	rec := w.do(http.MethodGet, "/api/v1/me/consents", d3AliceToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/me/consents = %d body=%q, want 200 — the self-service consent list is not served", rec.Code, rec.Body.String())
	}
	if cc := rec.Header().Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Errorf("Cache-Control = %q, want no-store like the other /me reads", cc)
	}
	var body d3ListBody
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body is not the consent list JSON: %v (%q)", err, rec.Body.String())
	}
	got := map[string]d3ConsentView{}
	for _, c := range body.Consents {
		if _, dup := got[c.ClientID]; dup {
			t.Fatalf("client %s listed twice — audiences must be grouped per client_id", c.ClientID)
		}
		got[c.ClientID] = c
	}
	for _, never := range []string{"client-z", "client-gone", "client-b"} {
		if _, ok := got[never]; ok {
			t.Errorf("%s listed — revoked consents, deleted clients and other users' consents must never appear", never)
		}
	}
	if len(got) != 2 {
		t.Fatalf("listed %d clients %v, want exactly client-x and client-y", len(got), body.Consents)
	}
	x := got["client-x"]
	if x.Name != "Expense App" {
		t.Errorf("client-x name = %q, want the client's name", x.Name)
	}
	scopes := append([]string(nil), x.Scopes...)
	sort.Strings(scopes)
	if strings.Join(scopes, " ") != "openid profile read:x" {
		t.Errorf("client-x scopes = %v, want the union across audiences [openid profile read:x]", x.Scopes)
	}
	first, ferr := time.Parse(time.RFC3339, x.FirstGrantedAt)
	last, lerr := time.Parse(time.RFC3339, x.LastGrantedAt)
	if ferr != nil || lerr != nil || last.Before(first) {
		t.Errorf("client-x first/last granted = %q/%q, want RFC3339 with first <= last", x.FirstGrantedAt, x.LastGrantedAt)
	}
	if body.AccessTokenLifetimeSeconds != 3600 {
		t.Errorf("access_token_lifetime_seconds = %d, want 3600 (the user access-token TTL the UI must show)", body.AccessTokenLifetimeSeconds)
	}
}

// DELETE revokes every audience row of (caller, client), the caller's refresh
// tokens for that client (the refresh grant is then refused) with their
// linked access JTIs denylisted, leaves the caller's other client and other
// users untouched, makes the next authorize ask for consent again, and
// records an audit event.
// RULE: SELF-CONSENT-REVOKE-1
func TestMeConsents_DeleteRevokesConsentAndRefreshTokens(t *testing.T) {
	w := newD3World(t)
	ctx := context.Background()
	rec := w.do(http.MethodDelete, "/api/v1/me/consents/client-x", d3AliceToken)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("DELETE /api/v1/me/consents/client-x = %d body=%q, want 204 — the consent revoke route is not served", rec.Code, rec.Body.String())
	}
	// Next authorize asks again: AuthorizeService.Authorize mints a code
	// only when ConsentService.Lookup reports Covered.
	for _, aud := range []string{"", "https://api.x.example/"} {
		d, err := w.consents.Lookup(ctx, w.alice, "client-x", aud, "openid")
		if err != nil || d.Found || d.Covered {
			t.Errorf("after DELETE, consent lookup for audience %q = %+v err=%v, want not found (authorize must ask consent again)", aud, d, err)
		}
	}
	if _, err := w.refresh.Consume(ctx, service.ConsumeRefreshTokenInput{RawToken: w.aliceX, ClientID: "client-x"}); !errors.Is(err, service.ErrRefreshTokenInvalidGrant) {
		t.Errorf("refresh grant with alice's client-x token after DELETE: err=%v, want ErrRefreshTokenInvalidGrant", err)
	}
	if revoked, _ := w.denylist.IsRevoked(ctx, d3AliceXJTI); !revoked {
		t.Errorf("access jti linked to alice's client-x refresh token not denylisted — the access-JTI cascade is missing")
	}
	// Untouched: alice's other client, bob.
	if d, _ := w.consents.Lookup(ctx, w.alice, "client-y", "", "openid"); !d.Covered {
		t.Errorf("alice's client-y consent was revoked by a client-x DELETE")
	}
	if _, err := w.refresh.Consume(ctx, service.ConsumeRefreshTokenInput{RawToken: w.aliceY, ClientID: "client-y"}); err != nil {
		t.Errorf("alice's client-y refresh token refused after a client-x DELETE: %v", err)
	}
	if _, err := w.refresh.Consume(ctx, service.ConsumeRefreshTokenInput{RawToken: w.bobB, ClientID: "client-b"}); err != nil {
		t.Errorf("bob's refresh token refused after alice's DELETE: %v", err)
	}
	var found bool
	for _, ev := range w.audit.Events() {
		if ev.ActorID == w.alice && ev.SubjectID == w.alice && ev.Metadata["client_id"] == "client-x" {
			found = true
		}
	}
	if !found {
		t.Errorf("no audit event with actor/subject alice and metadata client_id=client-x; events=%+v", w.audit.Events())
	}
}

// Another user's client_id answers 404 from the HANDLER (JSON not_found, not
// the router's unmatched-route 404) and revokes nothing of theirs.
func TestMeConsents_DeleteOtherUsersClientIs404(t *testing.T) {
	w := newD3World(t)
	ctx := context.Background()
	rec := w.do(http.MethodDelete, "/api/v1/me/consents/client-b", d3AliceToken)
	var body struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if rec.Code != http.StatusNotFound || body.Error != "not_found" {
		t.Fatalf("DELETE another user's client = %d body=%q, want 404 {\"error\":\"not_found\"} from the consent handler", rec.Code, rec.Body.String())
	}
	if d, _ := w.consents.Lookup(ctx, w.bob, "client-b", "", "openid"); !d.Covered {
		t.Errorf("bob's consent was revoked by alice's DELETE")
	}
	if _, err := w.refresh.Consume(ctx, service.ConsumeRefreshTokenInput{RawToken: w.bobB, ClientID: "client-b"}); err != nil {
		t.Errorf("bob's refresh token refused after alice's DELETE: %v", err)
	}
}
