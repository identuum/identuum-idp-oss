package service

import (
	"context"
	"errors"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/extensionmint"
	"github.com/identuum/identuum-idp-oss/internal/repository"
	"github.com/identuum/identuum-idp-oss/pkg/extension"
)

// WithQuotas adds the entitlement snapshot and the quota ceiling to API
// resource create (OSS-SEAM-5). They run after the restrictions and before
// the write; nil for both keeps OSS as it is.
func (s *APIResourceService) WithQuotas(e extension.Entitlements, q extension.QuotaPolicy) *APIResourceService {
	s.entitlements, s.quotas = e, q
	return s
}

// createRow writes the resource. With quotas it reads the snapshot and the
// ceiling first, failing closed (403 restricted), and then creates only while
// the organization's count, taken under its lock, is below the ceiling (409
// quota_exceeded otherwise).
func (s *APIResourceService) createRow(ctx context.Context, resource *domain.APIResource, scopes []domain.APIScope) error {
	if s.entitlements == nil && s.quotas == nil {
		return s.repo.Create(ctx, resource, scopes)
	}
	restricted := &extension.Denial{Code: extension.Restricted}
	if s.entitlements != nil {
		snap, err := snapshotOf(ctx, s.entitlements)
		if err != nil || !snap.Available {
			return restricted
		}
	}
	if s.quotas == nil {
		return s.repo.Create(ctx, resource, scopes)
	}
	store, ok := s.repo.(repository.APIResourceQuotaStore)
	if !ok {
		return restricted
	}
	count, err := store.CountByOrg(ctx, resource.OrganizationID)
	if err != nil {
		return restricted
	}
	ceiling, err := ceilingOf(ctx, s.quotas, resource.OrganizationID, count)
	if err != nil || ceiling < 0 {
		return restricted
	}
	err = store.CreateUnderCeiling(ctx, resource, scopes, ceiling)
	if errors.Is(err, repository.ErrQuotaExceeded) {
		return &extension.Denial{Code: extension.QuotaExceeded}
	}
	return err
}

func snapshotOf(ctx context.Context, e extension.Entitlements) (snap extension.EntitlementSnapshot, err error) {
	defer func() {
		if recover() != nil {
			snap, err = extension.EntitlementSnapshot{}, errors.New("service: entitlements panicked")
		}
	}()
	return e.Snapshot(ctx)
}

func ceilingOf(ctx context.Context, q extension.QuotaPolicy, org uuid.UUID, count int64) (ceiling int64, err error) {
	defer func() {
		if recover() != nil {
			ceiling, err = -1, errors.New("service: quota policy panicked")
		}
	}()
	facts, _ := extensionmint.NewQuotaFacts(org.String(), extension.QuotaFamilyAPIResource, count).(extension.QuotaFacts)
	return q.Ceiling(ctx, facts)
}
