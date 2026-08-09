package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/metrics"
	"github.com/identuum/identuum-idp-oss/internal/repository"
	"github.com/identuum/identuum-idp-oss/logger"
	"github.com/jackc/pgx/v5"
	"github.com/prometheus/client_golang/prometheus"
)

// PgxIdentityProviderRepository implements repository.IdentityProviderRepository using pgx
type PgxIdentityProviderRepository struct {
	db DBTX
}

// NewPgxIdentityProviderRepository creates a new pgx repository instance
func NewPgxIdentityProviderRepository(db DBTX) *PgxIdentityProviderRepository {
	return &PgxIdentityProviderRepository{
		db: db,
	}
}

// Compile-time interface check
var _ repository.IdentityProviderRepository = (*PgxIdentityProviderRepository)(nil)

// Create persists a new identity provider
func (r *PgxIdentityProviderRepository) Create(ctx context.Context, provider *domain.IdentityProvider) (*domain.IdentityProvider, error) {
	timer := prometheus.NewTimer(metrics.DBQueryDuration.WithLabelValues("idp_repo", "create", "all"))
	defer timer.ObserveDuration()

	dto := toProviderConfigDTO(provider.Config)
	configJSON, err := json.Marshal(dto)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal provider config: %w", err)
	}

	query := `
		INSERT INTO identity_providers (organization_id, type, name, slug, priority, active, config, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), NOW())
		RETURNING id, organization_id, type, name, slug, priority, active, config, created_at, updated_at`

	created, err := r.scanProvider(r.db.QueryRow(ctx, query,
		provider.OrganizationID,
		provider.Type,
		provider.Name,
		provider.Slug,
		provider.Priority,
		provider.Active,
		configJSON,
	))

	if err != nil {
		metrics.DBQueryDuration.WithLabelValues("idp_repo", "create", "error").Observe(timer.ObserveDuration().Seconds())
		return nil, fmt.Errorf("failed to create identity provider: %w", err)
	}

	metrics.DBQueryDuration.WithLabelValues("idp_repo", "create", "success").Observe(timer.ObserveDuration().Seconds())
	logger.Info.Printf("Created identity provider: %s (Type: %s, Org: %s)", created.Name, created.Type, created.OrganizationID)
	return created, nil
}

// GetByID retrieves a provider by its unique ID
func (r *PgxIdentityProviderRepository) GetByID(ctx context.Context, id uuid.UUID) (*domain.IdentityProvider, error) {
	timer := prometheus.NewTimer(metrics.DBQueryDuration.WithLabelValues("idp_repo", "get_by_id", "all"))
	defer timer.ObserveDuration()

	// A provider whose row is soft-deleted, or whose organization is not
	// operational (soft-deleted OR deactivated), MUST NOT resolve at OIDC
	// login/callback time — tenant deletion is an authentication boundary.
	// Org predicate mirrors domain.Organization.IsOperational() (deleted_at
	// IS NULL AND active).
	query := `
		SELECT id, organization_id, type, name, slug, priority, active, config, created_at, updated_at
		FROM identity_providers ip
		WHERE ip.id = $1
		  AND ip.deleted_at IS NULL
		  AND EXISTS (SELECT 1 FROM organizations o WHERE o.id = ip.organization_id AND o.deleted_at IS NULL AND o.active)`

	provider, err := r.scanProvider(r.db.QueryRow(ctx, query, id))
	if err != nil {
		metrics.DBQueryDuration.WithLabelValues("idp_repo", "get_by_id", "error").Observe(timer.ObserveDuration().Seconds())
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("identity provider not found")
		}
		return nil, fmt.Errorf("failed to get identity provider: %w", err)
	}

	metrics.DBQueryDuration.WithLabelValues("idp_repo", "get_by_id", "success").Observe(timer.ObserveDuration().Seconds())
	return provider, nil
}

// GetByOrgAndType retrieves a provider for an org by its type
func (r *PgxIdentityProviderRepository) GetByOrgAndType(ctx context.Context, orgID uuid.UUID, providerType domain.IdentityProviderType) (*domain.IdentityProvider, error) {
	timer := prometheus.NewTimer(metrics.DBQueryDuration.WithLabelValues("idp_repo", "get_by_org_type", "all"))
	defer timer.ObserveDuration()

	// P3-13: soft-deleted rows (written only by the org-delete cascade)
	// are invisible to every read of this table.
	query := `
		SELECT id, organization_id, type, name, slug, priority, active, config, created_at, updated_at
		FROM identity_providers
		WHERE organization_id = $1 AND type = $2 AND deleted_at IS NULL
		ORDER BY priority ASC
		LIMIT 1`

	provider, err := r.scanProvider(r.db.QueryRow(ctx, query, orgID, providerType))
	if err != nil {
		metrics.DBQueryDuration.WithLabelValues("idp_repo", "get_by_org_type", "error").Observe(timer.ObserveDuration().Seconds())
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("identity provider not found for type %s", providerType)
		}
		return nil, fmt.Errorf("failed to get identity provider by org/type: %w", err)
	}

	metrics.DBQueryDuration.WithLabelValues("idp_repo", "get_by_org_type", "success").Observe(timer.ObserveDuration().Seconds())
	return provider, nil
}

// ListByOrganization retrieves all providers for an organization
func (r *PgxIdentityProviderRepository) ListByOrganization(ctx context.Context, orgID uuid.UUID) ([]*domain.IdentityProvider, error) {
	timer := prometheus.NewTimer(metrics.DBQueryDuration.WithLabelValues("idp_repo", "list_by_org", "all"))
	defer timer.ObserveDuration()

	// P3-13: soft-deleted rows never list — this also un-blocks the
	// one-provider-per-org check (existingOIDCProvider) after an org
	// restore cycle and keeps the public org-lookup projection honest.
	query := `
		SELECT id, organization_id, type, name, slug, priority, active, config, created_at, updated_at
		FROM identity_providers
		WHERE organization_id = $1 AND deleted_at IS NULL
		ORDER BY priority ASC`

	rows, err := r.db.Query(ctx, query, orgID)
	if err != nil {
		return nil, fmt.Errorf("failed to list identity providers: %w", err)
	}
	defer rows.Close()

	providers := []*domain.IdentityProvider{}
	for rows.Next() {
		provider, err := r.scanProvider(rows)
		if err != nil {
			return nil, fmt.Errorf("failed to scan provider: %w", err)
		}
		providers = append(providers, provider)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("row iteration failed: %w", err)
	}

	return providers, nil
}

// Update updates a provider's configuration
func (r *PgxIdentityProviderRepository) Update(ctx context.Context, provider *domain.IdentityProvider) (*domain.IdentityProvider, error) {
	dto := toProviderConfigDTO(provider.Config)
	configJSON, err := json.Marshal(dto)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal provider config: %w", err)
	}

	query := `
		UPDATE identity_providers
		SET name = $1, slug = $2, priority = $3, active = $4, config = $5, updated_at = NOW()
		WHERE id = $6 AND deleted_at IS NULL
		RETURNING id, organization_id, type, name, slug, priority, active, config, created_at, updated_at`

	updated, err := r.scanProvider(r.db.QueryRow(ctx, query,
		provider.Name,
		provider.Slug,
		provider.Priority,
		provider.Active,
		configJSON,
		provider.ID,
	))

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("identity provider not found")
		}
		return nil, fmt.Errorf("failed to update identity provider: %w", err)
	}

	logger.Info.Printf("Updated identity provider: %s", updated.ID)
	return updated, nil
}

// Delete removes a provider
func (r *PgxIdentityProviderRepository) Delete(ctx context.Context, id uuid.UUID, orgID uuid.UUID) error {
	// P3-14 PART B: tombstones are inert to writes; a tombstoned provider
	// deletes like a nonexistent one (rows-affected 0 -> not-found below).
	query := `DELETE FROM identity_providers WHERE id = $1 AND organization_id = $2 AND deleted_at IS NULL`
	result, err := r.db.Exec(ctx, query, id, orgID)
	if err != nil {
		return fmt.Errorf("failed to delete identity provider: %w", err)
	}

	if result.RowsAffected() == 0 {
		return fmt.Errorf("identity provider not found")
	}

	return nil
}

// scanProvider helper
// Uses pgx.Row interface (which both QueryRow and Rows satisfy)
func (r *PgxIdentityProviderRepository) scanProvider(row pgx.Row) (*domain.IdentityProvider, error) {
	var provider domain.IdentityProvider
	var configBytes []byte
	var typeStr string

	err := row.Scan(
		&provider.ID,
		&provider.OrganizationID,
		&typeStr,
		&provider.Name,
		&provider.Slug,
		&provider.Priority,
		&provider.Active,
		&configBytes,
		&provider.CreatedAt,
		&provider.UpdatedAt,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to scan provider row: %w", err)
	}

	provider.Type = domain.IdentityProviderType(typeStr)

	if len(configBytes) > 0 {
		var dto providerConfigDTO
		if err := json.Unmarshal(configBytes, &dto); err != nil {
			return nil, fmt.Errorf("failed to unmarshal config: %w", err)
		}
		provider.Config = dto.toDomain()
	}

	return &provider, nil
}

// providerConfigDTO maps the JSONB configuration column
type providerConfigDTO struct {
	Host                  string            `json:"host,omitempty"`
	Port                  int               `json:"port,omitempty"`
	BindDN                string            `json:"bind_dn,omitempty"`
	BindPasswordEncrypted string            `json:"bind_password_encrypted,omitempty"`
	BaseDN                string            `json:"base_dn,omitempty"`
	UserFilter            string            `json:"user_filter,omitempty"`
	AttributeMapping      map[string]string `json:"attribute_mapping,omitempty"`
	TLSOptions            *tlsOptionsDTO    `json:"tls_options,omitempty"`
	IssuerURL             string            `json:"issuer_url,omitempty"`
	ClientID              string            `json:"client_id,omitempty"`
	ClientSecretEncrypted string            `json:"client_secret_encrypted,omitempty"`
	RedirectURIs          []string          `json:"redirect_uris,omitempty"`
	Scopes                []string          `json:"scopes,omitempty"`
	PKCERequired          bool              `json:"pkce_required,omitempty"`
	ClaimMapping          map[string]string `json:"claim_mapping,omitempty"`
	AllowExternalDomains  bool              `json:"allow_external_domains,omitempty"`
	SyncEnabled           bool              `json:"sync_enabled,omitempty"`
	SyncSchedule          string            `json:"sync_schedule,omitempty"`
}

type tlsOptionsDTO struct {
	InsecureSkipVerify bool `json:"insecure_skip_verify,omitempty"`
	DisableTLS         bool `json:"disable_tls,omitempty"`
}

func toProviderConfigDTO(cfg domain.ProviderConfig) providerConfigDTO {
	dto := providerConfigDTO{
		Host:                  cfg.Host,
		Port:                  cfg.Port,
		BindDN:                cfg.BindDN,
		BindPasswordEncrypted: cfg.BindPasswordEncrypted,
		BaseDN:                cfg.BaseDN,
		UserFilter:            cfg.UserFilter,
		AttributeMapping:      cfg.AttributeMapping,
		IssuerURL:             cfg.IssuerURL,
		ClientID:              cfg.ClientID,
		ClientSecretEncrypted: cfg.ClientSecretEncrypted,
		RedirectURIs:          cfg.RedirectURIs,
		Scopes:                cfg.Scopes,
		PKCERequired:          cfg.PKCERequired,
		ClaimMapping:          cfg.ClaimMapping,
		AllowExternalDomains:  cfg.AllowExternalDomains,
		SyncEnabled:           cfg.SyncEnabled,
		SyncSchedule:          cfg.SyncSchedule,
	}
	if cfg.TLSOptions != nil {
		dto.TLSOptions = &tlsOptionsDTO{
			InsecureSkipVerify: cfg.TLSOptions.InsecureSkipVerify,
			DisableTLS:         cfg.TLSOptions.DisableTLS,
		}
	}
	return dto
}

func (dto providerConfigDTO) toDomain() domain.ProviderConfig {
	d := domain.ProviderConfig{
		Host:                  dto.Host,
		Port:                  dto.Port,
		BindDN:                dto.BindDN,
		BindPasswordEncrypted: dto.BindPasswordEncrypted,
		BaseDN:                dto.BaseDN,
		UserFilter:            dto.UserFilter,
		AttributeMapping:      dto.AttributeMapping,
		IssuerURL:             dto.IssuerURL,
		ClientID:              dto.ClientID,
		ClientSecretEncrypted: dto.ClientSecretEncrypted,
		RedirectURIs:          dto.RedirectURIs,
		Scopes:                dto.Scopes,
		PKCERequired:          dto.PKCERequired,
		ClaimMapping:          dto.ClaimMapping,
		AllowExternalDomains:  dto.AllowExternalDomains,
		SyncEnabled:           dto.SyncEnabled,
		SyncSchedule:          dto.SyncSchedule,
	}
	if dto.TLSOptions != nil {
		d.TLSOptions = &domain.TLSOptions{
			InsecureSkipVerify: dto.TLSOptions.InsecureSkipVerify,
			DisableTLS:         dto.TLSOptions.DisableTLS,
		}
	}
	return d
}
