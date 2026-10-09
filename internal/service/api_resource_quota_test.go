package service

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/repository"
	"github.com/identuum/identuum-idp-oss/pkg/extension"
)

// quotaRepo is the in-memory repository with the quota store.
type quotaRepo struct {
	*inMemoryAPIResourceRepo
	bounded int
}

func (r *quotaRepo) CountByOrg(_ context.Context, org uuid.UUID) (int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var n int64
	for _, row := range r.rows {
		if row.OrganizationID == org {
			n++
		}
	}
	return n, nil
}

func (r *quotaRepo) CreateUnderCeiling(ctx context.Context, res *domain.APIResource, scopes []domain.APIScope, ceiling int64) error {
	r.bounded++
	if n, _ := r.CountByOrg(ctx, res.OrganizationID); n >= ceiling {
		return repository.ErrQuotaExceeded
	}
	return r.Create(ctx, res, scopes)
}

type ceilingFunc func(context.Context, extension.QuotaFacts) (int64, error)

func (f ceilingFunc) Ceiling(ctx context.Context, q extension.QuotaFacts) (int64, error) {
	return f(ctx, q)
}

type snapshotFunc func(context.Context) (extension.EntitlementSnapshot, error)

func (f snapshotFunc) Snapshot(ctx context.Context) (extension.EntitlementSnapshot, error) {
	return f(ctx)
}

var available = snapshotFunc(func(context.Context) (extension.EntitlementSnapshot, error) {
	return extension.EntitlementSnapshot{Available: true}, nil
})

func quotaCreate(svc *APIResourceService, actor *domain.Principal, audience string) error {
	_, _, err := svc.Create(context.Background(), actor, CreateAPIResourceOptions{Name: "q", Audience: audience, Active: true})
	return err
}

// OSS-SEAM-5: the ceiling is what OSS enforces; the policy sees the tenant,
// the family and the count; one past the ceiling is 409 quota_exceeded.
func TestQuota_CeilingIsEnforcedWithItsFacts(t *testing.T) {
	org := uuid.New()
	repo := &quotaRepo{inMemoryAPIResourceRepo: newAPIResourceRepo()}
	var seen []extension.QuotaFacts
	svc := NewAPIResourceService(nil, repo).WithQuotas(available, ceilingFunc(func(_ context.Context, q extension.QuotaFacts) (int64, error) {
		seen = append(seen, q)
		return 2, nil
	}))
	admin := apiResourceOrgAdmin(org)
	for i, aud := range []string{"https://q1.api.test", "https://q2.api.test"} {
		if err := quotaCreate(svc, admin, aud); err != nil {
			t.Fatalf("create %d under the ceiling: %v", i+1, err)
		}
	}
	if err := quotaCreate(svc, admin, "https://q3.api.test"); !isDenial(err, extension.QuotaExceeded) {
		t.Fatalf("the third create: %v; want quota_exceeded", err)
	}
	if len(seen) != 3 || seen[2].Tenant() != org.String() || seen[2].Family() != extension.QuotaFamilyAPIResource || seen[2].Count() != 2 {
		t.Fatalf("facts = %+v; want three, the last for %s, api_resource, count 2", seen, org)
	}
}

// OSS-SEAM-5 proof 3: a ceiling never bypasses a base denial, tenant
// authority or the site_admin limit; the policy is not even asked.
func TestQuota_NeverBypassesABaseCheck(t *testing.T) {
	org := uuid.New()
	repo := &quotaRepo{inMemoryAPIResourceRepo: newAPIResourceRepo()}
	asked := 0
	deny := restrictionFunc(func(context.Context, extension.Decision) error { return errors.New("no") })
	svc := NewAPIResourceService(nil, repo).
		WithReservedAudiences(func(_ context.Context, aud string) (bool, error) { return aud == "https://issuer.test", nil }).
		WithQuotas(available, ceilingFunc(func(context.Context, extension.QuotaFacts) (int64, error) { asked++; return 1 << 40, nil }))
	admin := apiResourceOrgAdmin(org)
	cases := []struct {
		name  string
		svc   *APIResourceService
		actor *domain.Principal
		opts  CreateAPIResourceOptions
		want  func(error) bool
	}{
		{"site_admin", svc, apiResourcePrincipal(domain.RoleSiteAdmin, org), CreateAPIResourceOptions{Name: "s", Audience: "https://s.api.test"}, func(e error) bool { return errors.Is(e, ErrAPIResourceForbidden) }},
		{"org_user", svc, apiResourcePrincipal(domain.RoleOrgUser, org), CreateAPIResourceOptions{Name: "u", Audience: "https://u.api.test"}, func(e error) bool { return errors.Is(e, ErrAPIResourceForbidden) }},
		{"another tenant", svc, admin, CreateAPIResourceOptions{OrganizationID: uuid.New(), Name: "x", Audience: "https://x.api.test"}, func(e error) bool { return errors.Is(e, errAPIResourceNotFound) }},
		{"invalid input", svc, admin, CreateAPIResourceOptions{}, func(e error) bool { return e != nil }},
		{"reserved audience", svc, admin, CreateAPIResourceOptions{Name: "r", Audience: "https://issuer.test"}, func(e error) bool { return errors.Is(e, errAPIResourceInvalid) }},
		{"a restriction refuses", NewAPIResourceService(nil, repo).WithRestrictions([]extension.Restriction{deny}).
			WithQuotas(available, ceilingFunc(func(context.Context, extension.QuotaFacts) (int64, error) { asked++; return 1 << 40, nil })),
			admin, CreateAPIResourceOptions{Name: "d", Audience: "https://d.api.test"}, func(e error) bool { return isDenial(e, extension.Restricted) }},
	}
	for _, c := range cases {
		if _, _, err := c.svc.Create(context.Background(), c.actor, c.opts); !c.want(err) {
			t.Errorf("%s with a ceiling of 2^40: %v", c.name, err)
		}
	}
	if asked != 0 || repo.bounded != 0 || len(repo.rows) != 0 {
		t.Fatalf("the policy was asked %d time(s), %d bounded create(s), %d row(s); want none", asked, repo.bounded, len(repo.rows))
	}
}

// OSS-SEAM-5 proof 4: an error, a panic, an unavailable snapshot, a negative
// ceiling or a repository without the quota store is 403 restricted, and no
// row is written.
func TestQuota_FailsClosed(t *testing.T) {
	boom := errors.New("store down")
	ceiling := func(n int64, err error) extension.QuotaPolicy {
		return ceilingFunc(func(context.Context, extension.QuotaFacts) (int64, error) { return n, err })
	}
	cases := []struct {
		name string
		e    extension.Entitlements
		q    extension.QuotaPolicy
		bare bool
	}{
		{"snapshot error", snapshotFunc(func(context.Context) (extension.EntitlementSnapshot, error) {
			return extension.EntitlementSnapshot{}, boom
		}), nil, false},
		{"snapshot panic", snapshotFunc(func(context.Context) (extension.EntitlementSnapshot, error) { panic("boom") }), ceiling(10, nil), false},
		{"snapshot unavailable", snapshotFunc(func(context.Context) (extension.EntitlementSnapshot, error) {
			return extension.EntitlementSnapshot{}, nil
		}), ceiling(10, nil), false},
		{"ceiling error", available, ceiling(10, boom), false},
		{"ceiling panic", available, ceilingFunc(func(context.Context, extension.QuotaFacts) (int64, error) { panic("boom") }), false},
		{"negative ceiling", available, ceiling(-1, nil), false},
		{"no quota store", available, ceiling(10, nil), true},
	}
	for _, c := range cases {
		mem := newAPIResourceRepo()
		var repo repository.APIResourceRepository = &quotaRepo{inMemoryAPIResourceRepo: mem}
		if c.bare {
			repo = mem
		}
		svc := NewAPIResourceService(nil, repo).WithQuotas(c.e, c.q)
		if err := quotaCreate(svc, apiResourceOrgAdmin(uuid.New()), "https://f.api.test"); !isDenial(err, extension.Restricted) {
			t.Errorf("%s: %v; want restricted", c.name, err)
		}
		if len(mem.rows) != 0 {
			t.Errorf("%s: %d row(s) written; want none", c.name, len(mem.rows))
		}
	}
}
