package service_test

import (
	"context"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/repository"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// memProtoSettingsRepo is an in-memory
// repository.OrganizationProtocolSettingsRepository for the
// service-layer test.
type memProtoSettingsRepo struct {
	mu   sync.Mutex
	rows map[uuid.UUID]*domain.OrganizationProtocolSettings
}

func newMemProtoSettingsRepo() *memProtoSettingsRepo {
	return &memProtoSettingsRepo{rows: map[uuid.UUID]*domain.OrganizationProtocolSettings{}}
}

func (r *memProtoSettingsRepo) GetByOrgID(_ context.Context, orgID uuid.UUID) (*domain.OrganizationProtocolSettings, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	row, ok := r.rows[orgID]
	if !ok {
		return nil, repository.ErrOrganizationProtocolSettingsNotFound
	}
	cp := *row
	return &cp, nil
}

func (r *memProtoSettingsRepo) Upsert(_ context.Context, s *domain.OrganizationProtocolSettings) (*domain.OrganizationProtocolSettings, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	cp := *s
	r.rows[s.OrganizationID] = &cp
	cp2 := cp
	return &cp2, nil
}

// TestOrgProtocolSettings_AbsentRowDefaultsBothFalse pins the
// system default: a row that does NOT exist yet resolves to
// "both protocols disabled" — operator must explicitly enable.
func TestOrgProtocolSettings_AbsentRowDefaultsBothFalse(t *testing.T) {
	svc := service.NewOrganizationProtocolSettingsService(nil, newMemProtoSettingsRepo())
	org := uuid.New()
	eff, err := svc.GetEffective(context.Background(), org)
	if err != nil {
		t.Fatalf("GetEffective: %v", err)
	}
	if eff.DCREnabled || eff.SCIMEnabled {
		t.Errorf("absent row → effective = {DCR=%v SCIM=%v}, want {false false}", eff.DCREnabled, eff.SCIMEnabled)
	}
}

// TestOrgProtocolSettings_NilUUIDDefaultsBothFalse pins the
// guard for org-less callers — the service returns the system
// default rather than hitting the repository.
func TestOrgProtocolSettings_NilUUIDDefaultsBothFalse(t *testing.T) {
	svc := service.NewOrganizationProtocolSettingsService(nil, newMemProtoSettingsRepo())
	eff, err := svc.GetEffective(context.Background(), uuid.Nil)
	if err != nil {
		t.Fatalf("GetEffective: %v", err)
	}
	if eff.DCREnabled || eff.SCIMEnabled {
		t.Errorf("nil uuid → effective = {DCR=%v SCIM=%v}, want {false false}", eff.DCREnabled, eff.SCIMEnabled)
	}
}

// TestOrgProtocolSettings_SetForOrgRoundtrip pins the upsert
// + readback contract: a flipped flag is observable on the next
// GetEffective.
func TestOrgProtocolSettings_SetForOrgRoundtrip(t *testing.T) {
	svc := service.NewOrganizationProtocolSettingsService(nil, newMemProtoSettingsRepo())
	org := uuid.New()
	if _, err := svc.SetForOrg(context.Background(), org, true, false); err != nil {
		t.Fatalf("SetForOrg: %v", err)
	}
	eff, _ := svc.GetEffective(context.Background(), org)
	if !eff.DCREnabled || eff.SCIMEnabled {
		t.Errorf("set DCR=true SCIM=false → effective = {DCR=%v SCIM=%v}", eff.DCREnabled, eff.SCIMEnabled)
	}
	// Flip both.
	if _, err := svc.SetForOrg(context.Background(), org, false, true); err != nil {
		t.Fatalf("SetForOrg flip: %v", err)
	}
	eff, _ = svc.GetEffective(context.Background(), org)
	if eff.DCREnabled || !eff.SCIMEnabled {
		t.Errorf("flipped → effective = {DCR=%v SCIM=%v}", eff.DCREnabled, eff.SCIMEnabled)
	}
}

// TestOrgProtocolSettings_IsFeatureEnabledForOrgKeys pins the
// per-feature dispatch.
func TestOrgProtocolSettings_IsFeatureEnabledForOrgKeys(t *testing.T) {
	svc := service.NewOrganizationProtocolSettingsService(nil, newMemProtoSettingsRepo())
	org := uuid.New()
	if _, err := svc.SetForOrg(context.Background(), org, true, false); err != nil {
		t.Fatalf("SetForOrg: %v", err)
	}
	dcr, _ := svc.IsFeatureEnabledForOrg(context.Background(), org, service.OrgFeatureDynamicClientRegistration)
	if !dcr {
		t.Errorf("DCR expected true")
	}
	scim, _ := svc.IsFeatureEnabledForOrg(context.Background(), org, service.OrgFeatureSCIM)
	if scim {
		t.Errorf("SCIM expected false")
	}
	// Unknown feature → false.
	unknown, _ := svc.IsFeatureEnabledForOrg(context.Background(), org, "unknown_feature_key")
	if unknown {
		t.Errorf("unknown feature must default false")
	}
}

// TestOrgProtocolSettings_SetForOrgRejectsNilUUID pins the
// programmer-error guard on the admin-write path.
func TestOrgProtocolSettings_SetForOrgRejectsNilUUID(t *testing.T) {
	svc := service.NewOrganizationProtocolSettingsService(nil, newMemProtoSettingsRepo())
	if _, err := svc.SetForOrg(context.Background(), uuid.Nil, true, true); err == nil {
		t.Errorf("SetForOrg with nil orgID must error")
	}
}
