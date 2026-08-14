package service

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/repository"
)

// inMemoryClientRepo is a tiny in-memory ClientRepository for
// service-level tests. Only the methods exercised by the OSS
// service are implemented; the rest panic.
type inMemoryClientRepo struct {
	mu      sync.Mutex
	rows    map[uuid.UUID]*domain.Client
	listErr error
}

func newClientRepo() *inMemoryClientRepo {
	return &inMemoryClientRepo{rows: map[uuid.UUID]*domain.Client{}}
}

func (r *inMemoryClientRepo) RegisterClient(_ context.Context, c *domain.Client) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rows[c.ID] = c
	return nil
}
func (r *inMemoryClientRepo) GetClientByID(_ context.Context, id uuid.UUID) (*domain.Client, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.rows[id], nil
}
func (r *inMemoryClientRepo) GetClientByClientID(_ context.Context, clientID string) (*domain.Client, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range r.rows {
		if c.ClientID == clientID {
			return c, nil
		}
	}
	return nil, nil
}
func (r *inMemoryClientRepo) Update(_ context.Context, c *domain.Client) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rows[c.ID] = c
	return nil
}
func (r *inMemoryClientRepo) Delete(_ context.Context, id uuid.UUID, _ *uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.rows, id)
	return nil
}
func (r *inMemoryClientRepo) List(_ context.Context, _ repository.Pagination, _ *uuid.UUID) ([]*domain.Client, int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.listErr != nil {
		return nil, 0, r.listErr
	}
	out := make([]*domain.Client, 0, len(r.rows))
	for _, c := range r.rows {
		out = append(out, c)
	}
	return out, len(out), nil
}
func (r *inMemoryClientRepo) ListByServiceAccountID(_ context.Context, _, _ uuid.UUID) ([]*domain.Client, error) {
	panic("not used")
}
func (r *inMemoryClientRepo) SaveConsent(_ context.Context, _ *domain.Consent) error {
	panic("not used")
}
func (r *inMemoryClientRepo) GetConsent(_ context.Context, _, _ uuid.UUID, _ *uuid.UUID) (*domain.Consent, error) {
	panic("not used")
}

func TestClientService_RegisterRequiresNameAndRedirects(t *testing.T) {
	svc := NewClientService(nil, newClientRepo())
	_, _, err := svc.RegisterClient(context.Background(), RegisterClientOptions{})
	if err == nil {
		t.Error("RegisterClient(empty opts) returned nil error")
	}
	_, _, err = svc.RegisterClient(context.Background(), RegisterClientOptions{Name: "X"})
	if err == nil {
		t.Error("RegisterClient(no redirects) returned nil error")
	}
}

func TestClientService_RegisterPublicHasNoSecret(t *testing.T) {
	svc := NewClientService(nil, newClientRepo())
	client, plaintext, err := svc.RegisterClient(context.Background(), RegisterClientOptions{
		Name:         "Public Client",
		IsPublic:     true,
		RedirectURIs: []string{"https://example.com/cb"},
	})
	if err != nil {
		t.Fatalf("RegisterClient: %v", err)
	}
	if plaintext != "" {
		t.Errorf("public client must NOT get a plaintext secret")
	}
	if client.ClientSecretHash != "" {
		t.Errorf("public client must NOT have a stored secret hash")
	}
}

// RULE: SECRET-ONCE-1
func TestClientService_RegisterConfidentialReturnsSecretOnce(t *testing.T) {
	svc := NewClientService(nil, newClientRepo())
	client, plaintext, err := svc.RegisterClient(context.Background(), RegisterClientOptions{
		Name:         "Confidential",
		IsPublic:     false,
		RedirectURIs: []string{"https://example.com/cb"},
	})
	if err != nil {
		t.Fatalf("RegisterClient: %v", err)
	}
	if plaintext == "" {
		t.Errorf("confidential client must receive a one-time plaintext")
	}
	if client.ClientSecretHash == "" {
		t.Errorf("confidential client must have a stored secret hash")
	}
	if client.ClientSecretHash == plaintext {
		t.Errorf("stored hash must NOT equal plaintext")
	}
}

// RULE: SECRET-ROTATE-1
func TestClientService_RegenerateRotatesAndReturnsOnce(t *testing.T) {
	repo := newClientRepo()
	svc := NewClientService(nil, repo)
	client, _, _ := svc.RegisterClient(context.Background(), RegisterClientOptions{
		Name:         "Confidential",
		RedirectURIs: []string{"https://example.com/cb"},
	})
	oldHash := client.ClientSecretHash
	_, newPlain, err := svc.RegenerateClientSecret(context.Background(), client.ID)
	if err != nil {
		t.Fatalf("RegenerateClientSecret: %v", err)
	}
	if newPlain == "" {
		t.Errorf("rotation must return new plaintext once")
	}
	rotated := repo.rows[client.ID]
	if rotated.ClientSecretHash == oldHash {
		t.Errorf("hash did not rotate")
	}
}

func TestClientService_RegeneratePublicRejected(t *testing.T) {
	svc := NewClientService(nil, newClientRepo())
	client, _, _ := svc.RegisterClient(context.Background(), RegisterClientOptions{
		Name:         "Public",
		IsPublic:     true,
		RedirectURIs: []string{"https://example.com/cb"},
	})
	_, _, err := svc.RegenerateClientSecret(context.Background(), client.ID)
	if err == nil {
		t.Errorf("RegenerateClientSecret on public client must fail")
	}
}

func TestClientService_GetNotFound(t *testing.T) {
	svc := NewClientService(nil, newClientRepo())
	_, err := svc.GetClient(context.Background(), uuid.New())
	if !errors.Is(err, ErrClientNotFound()) {
		t.Errorf("GetClient(missing) = %v, want ErrClientNotFound", err)
	}
}

// --- API Resource service -------------------------------------------------

type inMemoryAPIResourceRepo struct {
	mu   sync.Mutex
	rows map[uuid.UUID]*domain.APIResource
}

func newAPIResourceRepo() *inMemoryAPIResourceRepo {
	return &inMemoryAPIResourceRepo{rows: map[uuid.UUID]*domain.APIResource{}}
}

func (r *inMemoryAPIResourceRepo) Create(_ context.Context, res *domain.APIResource, _ []domain.APIScope) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rows[res.ID] = res
	return nil
}
func (r *inMemoryAPIResourceRepo) GetByID(_ context.Context, id uuid.UUID, _ *uuid.UUID) (*domain.APIResource, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.rows[id], nil
}
func (r *inMemoryAPIResourceRepo) GetByAudienceGlobal(_ context.Context, audience string) (*domain.APIResource, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, v := range r.rows {
		if v.Audience == audience {
			return v, nil
		}
	}
	return nil, nil
}
func (r *inMemoryAPIResourceRepo) Update(_ context.Context, res *domain.APIResource) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rows[res.ID] = res
	return nil
}
func (r *inMemoryAPIResourceRepo) Delete(_ context.Context, id uuid.UUID, _ *uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.rows, id)
	return nil
}
func (r *inMemoryAPIResourceRepo) List(_ context.Context, _ repository.Pagination, _ *uuid.UUID) ([]*domain.APIResource, int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*domain.APIResource, 0, len(r.rows))
	for _, v := range r.rows {
		out = append(out, v)
	}
	return out, len(out), nil
}
func (r *inMemoryAPIResourceRepo) AddScopes(_ context.Context, _ uuid.UUID, _ []domain.APIScope) error {
	panic("not used")
}
func (r *inMemoryAPIResourceRepo) RemoveScope(_ context.Context, _, _ uuid.UUID) error {
	panic("not used")
}
func (r *inMemoryAPIResourceRepo) ReplaceScopes(_ context.Context, _ uuid.UUID, _ []domain.APIScope) error {
	return nil
}
func (r *inMemoryAPIResourceRepo) UpdateWithScopes(_ context.Context, res *domain.APIResource, scopes []domain.APIScope) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	res.Scopes = scopes
	r.rows[res.ID] = res
	return nil
}

func TestAPIResourceService_CreateReturnsOneTimeSecret(t *testing.T) {
	svc := NewAPIResourceService(nil, newAPIResourceRepo())
	resource, plaintext, err := svc.Create(context.Background(), CreateAPIResourceOptions{
		OrganizationID: uuid.New(),
		Name:           "Resource",
		Audience:       "https://api.example.com",
		Active:         true,
		TokenTTLSecs:   3600,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if plaintext == "" {
		t.Errorf("Create must return one-time plaintext secret")
	}
	if resource.ResourceSecretHash == "" || resource.ResourceSecretHash == plaintext {
		t.Errorf("stored hash invalid: %q", resource.ResourceSecretHash)
	}
}

func TestAPIResourceService_RegenerateRotates(t *testing.T) {
	svc := NewAPIResourceService(nil, newAPIResourceRepo())
	resource, _, _ := svc.Create(context.Background(), CreateAPIResourceOptions{
		OrganizationID: uuid.New(),
		Name:           "R",
		Audience:       "https://api.example.com",
		Active:         true,
		TokenTTLSecs:   3600,
	})
	oldHash := resource.ResourceSecretHash
	_, plaintext, err := svc.RegenerateSecret(context.Background(), resource.ID)
	if err != nil {
		t.Fatalf("RegenerateSecret: %v", err)
	}
	if plaintext == "" {
		t.Errorf("rotation must return new plaintext once")
	}
	fresh, _ := svc.GetByID(context.Background(), resource.ID, nil)
	if fresh.ResourceSecretHash == oldHash {
		t.Errorf("hash did not rotate")
	}
}

func TestAPIResourceService_CreateRequiresNameAudience(t *testing.T) {
	svc := NewAPIResourceService(nil, newAPIResourceRepo())
	_, _, err := svc.Create(context.Background(), CreateAPIResourceOptions{})
	if err == nil {
		t.Error("Create(empty) must fail")
	}
}

// --- Scope Template service -----------------------------------------------

type inMemoryScopeTemplateRepo struct {
	mu   sync.Mutex
	rows map[uuid.UUID]*domain.ScopeTemplate
}

func newScopeTemplateRepo() *inMemoryScopeTemplateRepo {
	return &inMemoryScopeTemplateRepo{rows: map[uuid.UUID]*domain.ScopeTemplate{}}
}

func (r *inMemoryScopeTemplateRepo) Create(_ context.Context, t *domain.ScopeTemplate) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rows[t.ID] = t
	return nil
}
func (r *inMemoryScopeTemplateRepo) GetByID(_ context.Context, id, _ uuid.UUID) (*domain.ScopeTemplate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.rows[id], nil
}
func (r *inMemoryScopeTemplateRepo) List(_ context.Context, _ uuid.UUID) ([]*domain.ScopeTemplate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*domain.ScopeTemplate, 0, len(r.rows))
	for _, v := range r.rows {
		out = append(out, v)
	}
	return out, nil
}
func (r *inMemoryScopeTemplateRepo) Update(_ context.Context, t *domain.ScopeTemplate) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rows[t.ID] = t
	return nil
}
func (r *inMemoryScopeTemplateRepo) Delete(_ context.Context, id, _ uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.rows, id)
	return nil
}

func TestScopeTemplateService_CreateRequiresOrg(t *testing.T) {
	svc := NewScopeTemplateService(nil, newScopeTemplateRepo())
	_, err := svc.Create(context.Background(), CreateScopeTemplateOptions{Name: "X"})
	if err == nil || !strings.Contains(err.Error(), "organization") {
		t.Errorf("Create without org must fail; got %v", err)
	}
}

func TestScopeTemplateService_CreateHappy(t *testing.T) {
	svc := NewScopeTemplateService(nil, newScopeTemplateRepo())
	t1, err := svc.Create(context.Background(), CreateScopeTemplateOptions{
		OrganizationID: uuid.New(),
		Name:           "Admin",
		Scopes:         []string{"org:read"},
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if t1.Name != "Admin" || len(t1.Scopes) != 1 {
		t.Errorf("unexpected template: %+v", t1)
	}
}

func TestScopeTemplateService_UpdateNotFound(t *testing.T) {
	svc := NewScopeTemplateService(nil, newScopeTemplateRepo())
	_, err := svc.Update(context.Background(), uuid.New(), uuid.New(), UpdateScopeTemplateOptions{Name: "n"})
	if !errors.Is(err, ErrScopeTemplateNotFound()) {
		t.Errorf("Update(missing) = %v, want ErrScopeTemplateNotFound", err)
	}
}

// Pinning concurrent service creation does not cross-pollute IDs.
func TestServices_ConcurrentRegistersAreIsolated(t *testing.T) {
	svc := NewClientService(nil, newClientRepo())
	const n = 8
	var wg sync.WaitGroup
	wg.Add(n)
	seen := make([]string, n)
	for i := 0; i < n; i++ {
		go func(idx int) {
			defer wg.Done()
			c, _, err := svc.RegisterClient(context.Background(), RegisterClientOptions{
				Name:         "C",
				IsPublic:     true,
				RedirectURIs: []string{"https://example.com/cb"},
			})
			if err != nil {
				t.Errorf("RegisterClient: %v", err)
				return
			}
			seen[idx] = c.ClientID
		}(i)
	}
	wg.Wait()
	check := map[string]bool{}
	for _, id := range seen {
		if id == "" {
			t.Errorf("got empty client_id")
		}
		if check[id] {
			t.Errorf("duplicate client_id generated: %s", id)
		}
		check[id] = true
	}
	_ = time.Second
}
