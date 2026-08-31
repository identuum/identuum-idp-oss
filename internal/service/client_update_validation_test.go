package service

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/repository"
)

// recordingClientRepo records the client the service tried to persist. The
// embedded interface is nil on purpose — a method this test does not stub is
// one the guard must never reach.
type recordingClientRepo struct {
	repository.ClientRepository
	stored      domain.Client
	updateCalls int
	last        *domain.Client
}

func (r *recordingClientRepo) GetClientByID(_ context.Context, _ uuid.UUID) (*domain.Client, error) {
	c := r.stored
	return &c, nil
}

func (r *recordingClientRepo) Update(_ context.Context, c *domain.Client) error {
	r.updateCalls++
	r.last = c
	return nil
}

func newRecordingClientService() (*ClientService, *recordingClientRepo) {
	repo := &recordingClientRepo{stored: domain.Client{
		ID:           uuid.New(),
		ClientID:     "cid",
		Name:         "Original Name",
		RedirectURIs: []string{"https://app.example.com/callback"},
	}}
	return NewClientService(nil, repo), repo
}

// THE-UNVALIDATED-REST (2026-08-31): ClientService.UpdateClient validated
// redirect-URI SHAPE and the logout URIs, but not the two rules
// prepareClient enforces at create: a name that is non-empty after trimming,
// and AT LEAST ONE redirect URI. Both were measured live answering 200 and
// PERSISTING — PUT {"redirect_uris":[]} left an authorization-code client
// that can never complete a flow, and PUT {"name":"   "} stored a blank
// name the create path refuses.
//
// Asserted THROUGH the service with a recording repository: a proof that
// called validateClientName/validateClientRedirectURIs directly would still
// pass with the calls deleted from UpdateClient.
//
// RULE: CLIENT-UPDATE-VALIDATION-1
func TestClientServiceUpdate_RefusesMalformedBeforeReachingTheRepository(t *testing.T) {
	for _, bad := range []struct {
		why  string
		opts UpdateClientOptions
	}{
		{"a name that is whitespace only", UpdateClientOptions{Name: strPtr("   ")}},
		{"a name that is a single tab", UpdateClientOptions{Name: strPtr("\t")}},
		{"a name that is SUPPLIED EMPTY — a rename to nothing", UpdateClientOptions{Name: strPtr("")}},
		{"an EMPTY redirect-URI list — the client could never complete a flow", UpdateClientOptions{RedirectURIs: []string{}}},
		{"a redirect URI with a dangerous scheme", UpdateClientOptions{RedirectURIs: []string{"javascript:alert(1)"}}},
		{"a redirect URI with no scheme", UpdateClientOptions{RedirectURIs: []string{"not-a-uri"}}},
	} {
		svc, repo := newRecordingClientService()
		if _, err := svc.UpdateClient(context.Background(), uuid.New(), bad.opts); err == nil {
			t.Errorf("UpdateClient ACCEPTED %s — the update path does not apply the create rule", bad.why)
		}
		if repo.updateCalls != 0 {
			t.Errorf("%s: the repository was called %d time(s) with an invalid client", bad.why, repo.updateCalls)
		}
	}

	// ── legitimate changes still land ──
	for _, ok := range []struct {
		why  string
		opts UpdateClientOptions
	}{
		{"an empty option set changes nothing", UpdateClientOptions{}},
		{"a real name", UpdateClientOptions{Name: strPtr("Billing Portal")}},
		{"one redirect URI", UpdateClientOptions{RedirectURIs: []string{"https://app.example.com/cb"}}},
		{"several redirect URIs", UpdateClientOptions{RedirectURIs: []string{"https://a.example.com/cb", "https://b.example.com/cb"}}},
		{"a custom-scheme native redirect", UpdateClientOptions{RedirectURIs: []string{"com.example.app:/oauth"}}},
	} {
		svc, repo := newRecordingClientService()
		if _, err := svc.UpdateClient(context.Background(), uuid.New(), ok.opts); err != nil {
			t.Errorf("UpdateClient rejected a legitimate change (%s): %v", ok.why, err)
		}
		if repo.updateCalls != 1 {
			t.Errorf("%s: repository update calls = %d, want 1", ok.why, repo.updateCalls)
		}
	}

	// ── a refused update must leave the STORED values untouched ──
	svc, repo := newRecordingClientService()
	if _, err := svc.UpdateClient(context.Background(), uuid.New(), UpdateClientOptions{
		Name:         strPtr("New Name"),
		RedirectURIs: []string{},
	}); err == nil {
		t.Fatal("UpdateClient accepted an empty redirect-URI list alongside a valid name")
	}
	if repo.last != nil {
		t.Fatalf("a refused update still handed the repository a client (name=%q)", repo.last.Name)
	}

	// ── NOT trimmed, deliberately: prepareClient stores opts.Name verbatim,
	// so trimming on update only would make one spelling become two rows.
	svc, repo = newRecordingClientService()
	if _, err := svc.UpdateClient(context.Background(), uuid.New(), UpdateClientOptions{Name: strPtr("  Padded  ")}); err != nil {
		t.Fatalf("UpdateClient rejected a padded but non-blank name: %v", err)
	}
	if repo.last == nil || repo.last.Name != "  Padded  " {
		t.Fatalf("the update path transformed the name; create stores it verbatim, so the two paths must agree")
	}
}
