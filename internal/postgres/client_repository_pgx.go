package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/metrics"
	"github.com/identuum/identuum-idp-oss/internal/repository"
	"github.com/identuum/identuum-idp-oss/internal/utils/uuidgen"
	"github.com/jackc/pgx/v5"
	"github.com/prometheus/client_golang/prometheus"
)

// PgxClientRepository implements ClientRepository using pgx
type PgxClientRepository struct {
	db DBTX
}

// NewPgxClientRepository creates a new pgx client repository
func NewPgxClientRepository(db DBTX) *PgxClientRepository {
	return &PgxClientRepository{db: db}
}

// Compile-time check
var _ repository.ClientRepository = (*PgxClientRepository)(nil)

// RegisterClient creates a new OAuth client
func (r *PgxClientRepository) RegisterClient(ctx context.Context, client *domain.Client) error {
	timer := prometheus.NewTimer(metrics.DBQueryDuration.WithLabelValues("client_repo", "register", "all"))
	defer timer.ObserveDuration()

	// Generate ID if not present
	if client.ID == uuid.Nil {
		id, err := uuidgen.NewV7()
		if err != nil {
			return fmt.Errorf("failed to generate client id: %w", err)
		}
		client.ID = id
	}
	if client.ClientID == "" {
		cid, err := uuidgen.NewV7String()
		if err != nil {
			return fmt.Errorf("failed to generate client_id: %w", err)
		}
		client.ClientID = cid
	}

	query := `
		INSERT INTO oauth_clients (id, client_id, client_secret_hash, name, organization_id, redirect_uris, post_logout_redirect_uris, scope, service_account_id, is_public, skip_consent, allowed_audiences, token_ttl_secs, token_endpoint_auth_method, jwks_uri, jwks, token_endpoint_auth_signing_alg, frontchannel_logout_uri, frontchannel_logout_session_required, backchannel_logout_uri, backchannel_logout_session_required, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23)
		RETURNING id`

	// Resolve stored values: empty string → NULL for optional columns, else use provided value.
	storedAuthMethod := client.TokenEndpointAuthMethod
	if storedAuthMethod == "" {
		if client.IsPublic {
			storedAuthMethod = "none"
		} else {
			storedAuthMethod = "client_secret_basic"
		}
	}
	storedSigningAlg := client.TokenEndpointAuthSigningAlg
	if storedSigningAlg == "" {
		storedSigningAlg = "EdDSA"
	}
	var storedJWKSUri, storedJWKS *string
	if client.JWKSUri != "" {
		storedJWKSUri = &client.JWKSUri
	}
	if client.JWKS != "" {
		storedJWKS = &client.JWKS
	}
	var storedFrontchannelURI, storedBackchannelURI *string
	if client.FrontchannelLogoutURI != "" {
		storedFrontchannelURI = &client.FrontchannelLogoutURI
	}
	if client.BackchannelLogoutURI != "" {
		storedBackchannelURI = &client.BackchannelLogoutURI
	}

	err := r.db.QueryRow(ctx, query,
		client.ID,
		client.ClientID,
		client.ClientSecretHash,
		client.Name,
		client.OrganizationID,
		client.RedirectURIs,
		client.PostLogoutRedirectURIs,
		client.Scope,
		client.ServiceAccountID,
		client.IsPublic,
		client.SkipConsent,
		client.AllowedAudiences,
		client.TokenTTLSecs,
		storedAuthMethod,
		storedJWKSUri,
		storedJWKS,
		storedSigningAlg,
		storedFrontchannelURI,
		client.FrontchannelLogoutSessionRequired,
		storedBackchannelURI,
		client.BackchannelLogoutSessionRequired,
		client.CreatedAt,
		client.UpdatedAt,
	).Scan(&client.ID)

	if err != nil {
		metrics.DBQueryDuration.WithLabelValues("client_repo", "register", "error").Observe(timer.ObserveDuration().Seconds())
		return fmt.Errorf("failed to register client: %w", err)
	}

	metrics.DBQueryDuration.WithLabelValues("client_repo", "register", "success").Observe(timer.ObserveDuration().Seconds())
	return nil
}

// scanClient maps a row to a Client struct
func (r *PgxClientRepository) scanClient(row pgx.Row) (*domain.Client, error) {
	var client domain.Client
	var jwksURI, jwks *string
	var frontchannelURI, backchannelURI *string

	err := row.Scan(
		&client.ID,
		&client.ClientID,
		&client.ClientSecretHash,
		&client.Name,
		&client.OrganizationID,
		&client.RedirectURIs,
		&client.PostLogoutRedirectURIs,
		&client.Scope,
		&client.ServiceAccountID,
		&client.IsPublic,
		&client.SkipConsent,
		&client.AllowedAudiences,
		&client.TokenTTLSecs,
		&client.TokenEndpointAuthMethod,
		&jwksURI,
		&jwks,
		&client.TokenEndpointAuthSigningAlg,
		&frontchannelURI,
		&client.FrontchannelLogoutSessionRequired,
		&backchannelURI,
		&client.BackchannelLogoutSessionRequired,
		&client.CreatedAt,
		&client.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to scan client: %w", err)
	}

	if jwksURI != nil {
		client.JWKSUri = *jwksURI
	}
	if jwks != nil {
		client.JWKS = *jwks
	}
	if frontchannelURI != nil {
		client.FrontchannelLogoutURI = *frontchannelURI
	}
	if backchannelURI != nil {
		client.BackchannelLogoutURI = *backchannelURI
	}

	return &client, nil
}

// GetClientByID retrieves a client by its UUID
func (r *PgxClientRepository) GetClientByID(ctx context.Context, id uuid.UUID) (*domain.Client, error) {
	timer := prometheus.NewTimer(metrics.DBQueryDuration.WithLabelValues("client_repo", "get_by_id", "all"))
	defer timer.ObserveDuration()

	// P3-13: the SOFT-DELETE boundary is repository-wide — a soft-deleted
	// row (written only by the org-delete cascade) is invisible to EVERY
	// read, including this admin-surface UUID lookup, so a deleted org's
	// client cannot be read, updated, or secret-regenerated through the
	// admin API. Org Undelete restores rows via its own SQL and needs no
	// tombstone read. (Org-LIVENESS is the separate AUTH boundary and is
	// enforced on the auth-time lookup GetClientByClientID below.)
	query := `
		SELECT id, client_id, client_secret_hash, name, organization_id, redirect_uris, post_logout_redirect_uris, scope, service_account_id, is_public, skip_consent, allowed_audiences, token_ttl_secs, token_endpoint_auth_method, jwks_uri, jwks, token_endpoint_auth_signing_alg, frontchannel_logout_uri, frontchannel_logout_session_required, backchannel_logout_uri, backchannel_logout_session_required, created_at, updated_at
		FROM oauth_clients
		WHERE id = $1 AND deleted_at IS NULL`

	client, err := r.scanClient(r.db.QueryRow(ctx, query, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrClientNotFound
	}
	if err != nil {
		metrics.DBQueryDuration.WithLabelValues("client_repo", "get_by_id", "error").Observe(timer.ObserveDuration().Seconds())
		return nil, fmt.Errorf("failed to get client by id: %w", err)
	}

	metrics.DBQueryDuration.WithLabelValues("client_repo", "get_by_id", "success").Observe(timer.ObserveDuration().Seconds())
	return client, nil
}

// GetClientByClientID retrieves a client by its client_id string
func (r *PgxClientRepository) GetClientByClientID(ctx context.Context, clientID string) (*domain.Client, error) {
	timer := prometheus.NewTimer(metrics.DBQueryDuration.WithLabelValues("client_repo", "get_by_client_id", "all"))
	defer timer.ObserveDuration()

	// A client whose row is soft-deleted, or whose organization is not
	// operational (soft-deleted OR deactivated), MUST NOT resolve at auth
	// time — tenant deletion is an authentication boundary. Two boundaries,
	// both in SQL so no caller can forget (P3-13): the SOFT-DELETE predicate
	// (deleted_at IS NULL) holds on EVERY read AND write of this table —
	// see GetClientByID / List / ListByServiceAccountID / Update / Delete
	// (P3-14: a tombstone is inert, not just invisible) — while the org-LIVENESS
	// EXISTS below is the AUTH boundary and holds on this auth-time lookup
	// (a merely-deactivated org keeps its rows admin-visible; a deleted org
	// does not, because the delete cascade soft-deletes them). The org
	// predicate mirrors domain.Organization.IsOperational() (deleted_at IS
	// NULL AND active). organization_id IS NULL guards any non-tenant/system
	// client.
	query := `
		SELECT id, client_id, client_secret_hash, name, organization_id, redirect_uris, post_logout_redirect_uris, scope, service_account_id, is_public, skip_consent, allowed_audiences, token_ttl_secs, token_endpoint_auth_method, jwks_uri, jwks, token_endpoint_auth_signing_alg, frontchannel_logout_uri, frontchannel_logout_session_required, backchannel_logout_uri, backchannel_logout_session_required, created_at, updated_at
		FROM oauth_clients oc
		WHERE oc.client_id = $1
		  AND oc.deleted_at IS NULL
		  AND (oc.organization_id IS NULL OR EXISTS (
		      SELECT 1 FROM organizations o
		      WHERE o.id = oc.organization_id AND o.deleted_at IS NULL AND o.active))`

	client, err := r.scanClient(r.db.QueryRow(ctx, query, clientID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrClientNotFound
	}
	if err != nil {
		metrics.DBQueryDuration.WithLabelValues("client_repo", "get_by_client_id", "error").Observe(timer.ObserveDuration().Seconds())
		return nil, fmt.Errorf("failed to get client by client_id: %w", err)
	}

	metrics.DBQueryDuration.WithLabelValues("client_repo", "get_by_client_id", "success").Observe(timer.ObserveDuration().Seconds())
	return client, nil
}

// ListByServiceAccountID returns the OAuth clients linked to a service
// account within an organization. LIMIT 2 so callers can detect the
// (currently impossible) cardinality violation of multiple clients backing
// the same SA without unbounded scans.
func (r *PgxClientRepository) ListByServiceAccountID(ctx context.Context, orgID uuid.UUID, saID uuid.UUID) ([]*domain.Client, error) {
	timer := prometheus.NewTimer(metrics.DBQueryDuration.WithLabelValues("client_repo", "list_by_sa_id", "all"))
	defer timer.ObserveDuration()

	query := `
		SELECT id, client_id, client_secret_hash, name, organization_id, redirect_uris, post_logout_redirect_uris, scope, service_account_id, is_public, skip_consent, allowed_audiences, token_ttl_secs, token_endpoint_auth_method, jwks_uri, jwks, token_endpoint_auth_signing_alg, frontchannel_logout_uri, frontchannel_logout_session_required, backchannel_logout_uri, backchannel_logout_session_required, created_at, updated_at
		FROM oauth_clients
		WHERE organization_id = $1 AND service_account_id = $2 AND deleted_at IS NULL
		LIMIT 2`

	rows, err := r.db.Query(ctx, query, orgID, saID)
	if err != nil {
		metrics.DBQueryDuration.WithLabelValues("client_repo", "list_by_sa_id", "error").Observe(timer.ObserveDuration().Seconds())
		return nil, fmt.Errorf("failed to list clients by service_account_id: %w", err)
	}
	defer rows.Close()

	clients := make([]*domain.Client, 0, 2)
	for rows.Next() {
		client, scanErr := r.scanClient(rows)
		if scanErr != nil {
			return nil, fmt.Errorf("failed to scan client row: %w", scanErr)
		}
		clients = append(clients, client)
	}
	if rows.Err() != nil {
		return nil, fmt.Errorf("row iteration failed: %w", rows.Err())
	}

	metrics.DBQueryDuration.WithLabelValues("client_repo", "list_by_sa_id", "success").Observe(timer.ObserveDuration().Seconds())
	return clients, nil
}

func (r *PgxClientRepository) Update(ctx context.Context, client *domain.Client) error {
	// Resolve stored auth method default.
	storedAuthMethod := client.TokenEndpointAuthMethod
	if storedAuthMethod == "" {
		if client.IsPublic {
			storedAuthMethod = "none"
		} else {
			storedAuthMethod = "client_secret_basic"
		}
	}
	storedSigningAlg := client.TokenEndpointAuthSigningAlg
	if storedSigningAlg == "" {
		storedSigningAlg = "EdDSA"
	}
	var storedJWKSUri, storedJWKS *string
	if client.JWKSUri != "" {
		storedJWKSUri = &client.JWKSUri
	}
	if client.JWKS != "" {
		storedJWKS = &client.JWKS
	}
	var storedFrontchannelURI, storedBackchannelURI *string
	if client.FrontchannelLogoutURI != "" {
		storedFrontchannelURI = &client.FrontchannelLogoutURI
	}
	if client.BackchannelLogoutURI != "" {
		storedBackchannelURI = &client.BackchannelLogoutURI
	}

	query := `
		UPDATE oauth_clients
		SET name = $1, organization_id = $2, redirect_uris = $3, post_logout_redirect_uris = $4, scope = $5, is_public = $6, skip_consent = $7, client_secret_hash = $8, service_account_id = $9, allowed_audiences = $10, token_ttl_secs = $11, token_endpoint_auth_method = $12, jwks_uri = $13, jwks = $14, token_endpoint_auth_signing_alg = $15, frontchannel_logout_uri = $16, frontchannel_logout_session_required = $17, backchannel_logout_uri = $18, backchannel_logout_session_required = $19, updated_at = $20
		WHERE id = $21 AND deleted_at IS NULL
	`
	_, err := r.db.Exec(ctx, query,
		client.Name,
		client.OrganizationID,
		client.RedirectURIs,
		client.PostLogoutRedirectURIs,
		client.Scope,
		client.IsPublic,
		client.SkipConsent,
		client.ClientSecretHash,
		client.ServiceAccountID,
		client.AllowedAudiences,
		client.TokenTTLSecs,
		storedAuthMethod,
		storedJWKSUri,
		storedJWKS,
		storedSigningAlg,
		storedFrontchannelURI,
		client.FrontchannelLogoutSessionRequired,
		storedBackchannelURI,
		client.BackchannelLogoutSessionRequired,
		client.UpdatedAt,
		client.ID,
	)
	if err != nil {
		return fmt.Errorf("failed to update client: %w", err)
	}
	return nil
}

func (r *PgxClientRepository) Delete(ctx context.Context, id uuid.UUID, orgID *uuid.UUID) error {
	// P3-14 PART A: orgID is nil for the site-admin route (nil == any org,
	// the documented handler semantic) — the previous body dereferenced it
	// unconditionally and panicked on EVERY call of the mounted
	// DELETE /api/v1/clients/:id route. Branch on nil exactly like the
	// sibling PgxAPIResourceRepository.Delete.
	// P3-14 PART B: `deleted_at IS NULL` — a tombstone (a deleted org's row,
	// written only by the org-delete cascade) is INERT: invisible to reads
	// (P3-13) and immutable to writes, so this hard delete cannot destroy a
	// tombstone that org Undelete would otherwise restore. A tombstone
	// behaves exactly like a nonexistent row here (0 rows affected, no
	// error — the route's existing idempotent-delete semantic).
	var err error
	if orgID != nil {
		_, err = r.db.Exec(ctx, `DELETE FROM oauth_clients WHERE id = $1 AND organization_id = $2 AND deleted_at IS NULL`, id, *orgID)
	} else {
		_, err = r.db.Exec(ctx, `DELETE FROM oauth_clients WHERE id = $1 AND deleted_at IS NULL`, id)
	}
	if err != nil {
		return fmt.Errorf("failed to delete client: %w", err)
	}
	return nil
}

// List retrieves clients with optional organization filtering
func (r *PgxClientRepository) List(ctx context.Context, pagination repository.Pagination, orgID *uuid.UUID) ([]*domain.Client, int, error) {
	// 1. Get total count
	var totalCount int
	countQuery := "SELECT COUNT(*) FROM oauth_clients"
	// P3-13: soft-deleted rows (a deleted org's tombstones) never list.
	whereClause := " WHERE deleted_at IS NULL"
	args := []any{}

	if orgID != nil {
		whereClause += " AND organization_id = $1"
		args = append(args, *orgID)
	}

	if err := r.db.QueryRow(ctx, countQuery+whereClause, args...).Scan(&totalCount); err != nil {
		return nil, 0, fmt.Errorf("failed to count clients: %w", err)
	}

	// 2. List items
	query := `
		SELECT id, client_id, client_secret_hash, name, organization_id, redirect_uris, post_logout_redirect_uris, scope, service_account_id, is_public, skip_consent, allowed_audiences, token_ttl_secs, token_endpoint_auth_method, jwks_uri, jwks, token_endpoint_auth_signing_alg, frontchannel_logout_uri, frontchannel_logout_session_required, backchannel_logout_uri, backchannel_logout_session_required, created_at, updated_at
		FROM oauth_clients
	` + whereClause + `
		ORDER BY created_at DESC
		LIMIT $` + fmt.Sprintf("%d", len(args)+1) + ` OFFSET $` + fmt.Sprintf("%d", len(args)+2)

	args = append(args, pagination.PageSize, (pagination.Page-1)*pagination.PageSize)

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list clients: %w", err)
	}
	defer rows.Close()

	var clients []*domain.Client
	for rows.Next() {
		// Can't use scanClient easily here because rows is pgx.Rows, not pgx.Row
		// But pgx.Rows satisfies the minimal interface required if we define scanClient to take it?
		// pgx.Rows has Scan, but scanClient takes pgx.Row (which is interface { Scan }).
		// Correct. pgx.Rows implements Scan.

		client, err := r.scanClient(rows)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to scan client from list: %w", err)
		}
		clients = append(clients, client)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("row iteration failed: %w", err)
	}

	return clients, totalCount, nil
}

// SaveConsent creates or updates a user's consent for a client
func (r *PgxClientRepository) SaveConsent(ctx context.Context, consent *domain.Consent) error {
	timer := prometheus.NewTimer(metrics.DBQueryDuration.WithLabelValues("client_repo", "save_consent", "all"))
	defer timer.ObserveDuration()

	if consent.ID == uuid.Nil {
		id, err := uuidgen.NewV7()
		if err != nil {
			return fmt.Errorf("failed to generate consent id: %w", err)
		}
		consent.ID = id
	}

	query := `
		INSERT INTO oauth2_consents (id, user_id, client_id, api_resource_id, scope, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (user_id, client_id, api_resource_id) DO UPDATE
		SET scope = EXCLUDED.scope, updated_at = EXCLUDED.updated_at
		RETURNING id
	`

	err := r.db.QueryRow(ctx, query,
		consent.ID,
		consent.UserID,
		consent.ClientID,
		consent.APIResourceID,
		consent.Scope,
		consent.CreatedAt,
		consent.UpdatedAt,
	).Scan(&consent.ID)

	if err != nil {
		metrics.DBQueryDuration.WithLabelValues("client_repo", "save_consent", "error").Observe(timer.ObserveDuration().Seconds())
		return fmt.Errorf("failed to save consent: %w", err)
	}

	metrics.DBQueryDuration.WithLabelValues("client_repo", "save_consent", "success").Observe(timer.ObserveDuration().Seconds())
	return nil
}

// GetConsent retrieves a user's consent for a client and optional API Resource
func (r *PgxClientRepository) GetConsent(ctx context.Context, userID, clientID uuid.UUID, apiResourceID *uuid.UUID) (*domain.Consent, error) {
	timer := prometheus.NewTimer(metrics.DBQueryDuration.WithLabelValues("client_repo", "get_consent", "all"))
	defer timer.ObserveDuration()

	query := `
		SELECT id, user_id, client_id, api_resource_id, scope, created_at, updated_at
		FROM oauth2_consents
		WHERE user_id = $1 AND client_id = $2
	`
	args := []any{userID, clientID}

	if apiResourceID != nil {
		query += " AND api_resource_id = $3"
		args = append(args, *apiResourceID)
	} else {
		query += " AND api_resource_id IS NULL"
	}

	var consent domain.Consent
	err := r.db.QueryRow(ctx, query, args...).Scan(
		&consent.ID,
		&consent.UserID,
		&consent.ClientID,
		&consent.APIResourceID,
		&consent.Scope,
		&consent.CreatedAt,
		&consent.UpdatedAt,
	)

	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil // Return nil if no consent found (not an error)
	}
	if err != nil {
		metrics.DBQueryDuration.WithLabelValues("client_repo", "get_consent", "error").Observe(timer.ObserveDuration().Seconds())
		return nil, fmt.Errorf("failed to get consent: %w", err)
	}

	metrics.DBQueryDuration.WithLabelValues("client_repo", "get_consent", "success").Observe(timer.ObserveDuration().Seconds())
	return &consent, nil
}
