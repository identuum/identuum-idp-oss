package service

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/crypto"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/lifecycle"
	"github.com/identuum/identuum-idp-oss/internal/repository"
	"github.com/identuum/identuum-idp-oss/internal/utils/uuidgen"
)

// ClientService is the OSS-narrow OAuth client admin surface. It
// covers exactly the operations that the OSS Gin scaffold exposes
// today — list / get / register / update / delete / regenerate
// secret — and stays out of token issuance, assertion validation,
// M2M, redirect-URI lookups, and license/feature gating. Those are
// CE / future-slice concerns.
//
// Authorization (site-admin / org-admin scoping) is enforced at the
// HTTP layer via mw.RequireSiteAdmin; this service runs after the
// guard has already approved the caller.
//
// Audit emission is best-effort via the audit.Service seam — see
// the OSS audit package. Default OSS wiring is audit.NoopService{};
// the commercial edition can substitute an append-only
// implementation.
type ClientService struct {
	repo      repository.ClientRepository
	saBinding ServiceAccountBindingValidator
}

// ServiceAccountBindingValidator is the optional seam ClientService
// consults at register/update time to gate a non-nil
// ServiceAccountID against the live SA repository. The production
// wiring is *ServiceAccountService.ValidateBindingForClient.
//
// Returns nil on success; the OSS ServiceAccount* sentinels on
// failure (unbound, not-found, inactive, expired, org-mismatch).
type ServiceAccountBindingValidator interface {
	ValidateBindingForClient(ctx context.Context, saID uuid.UUID, clientOrgID *uuid.UUID) error
}

// WithServiceAccountBindingValidator wires the SA binding gate so
// RegisterClient and UpdateClient reject a client tied to a
// missing / inactive / expired / cross-org SA at the admin layer.
// Without this wired, the legacy "accept any ServiceAccountID
// verbatim" behavior is preserved for backwards compat (the
// runtime ServiceAccountLookup catches any drift at token-issuance
// time).
//
// Returns the receiver so the call composes with construction.
func (s *ClientService) WithServiceAccountBindingValidator(v ServiceAccountBindingValidator) *ClientService {
	s.saBinding = v
	return s
}

// NewClientService builds a ClientService bound to repo. repo MUST
// be non-nil; passing nil is a bootstrap bug and panics.
func NewClientService(report *lifecycle.StartupReport, repo repository.ClientRepository) *ClientService {
	if repo == nil {
		report.Fatal("NewClientService", "service: NewClientService requires a non-nil ClientRepository")
	}
	return &ClientService{repo: repo}
}

// RegisterClientOptions is the OSS request shape for creating a new
// OAuth client. Mirrors the monolith's RegisterClientOptions for
// the OSS-safe fields only.
type RegisterClientOptions struct {
	Name                              string
	OrganizationID                    *uuid.UUID
	ServiceAccountID                  *uuid.UUID
	RedirectURIs                      []string
	PostLogoutRedirectURIs            []string
	AllowedAudiences                  []string
	Scope                             string
	IsPublic                          bool
	TokenEndpointAuthMethod           string
	TokenEndpointAuthSigningAlg       string
	JWKSUri                           string
	JWKS                              string
	FrontchannelLogoutURI             string
	FrontchannelLogoutSessionRequired bool
	BackchannelLogoutURI              string
	BackchannelLogoutSessionRequired  bool
}

// UpdateClientOptions captures every field operators can mutate
// after the row exists. Any zero-value string is treated as
// "leave unchanged"; slices replace the prior value when non-nil.
//
// ServiceAccountID is a tri-state: nil means "leave unchanged",
// a non-nil pointer to uuid.Nil means "unbind", and a non-nil
// pointer to a real UUID means "bind to this SA". The
// binding-validator seam (if wired) verifies the SA exists +
// active + not-expired + org-match before persisting.
type UpdateClientOptions struct {
	Name                        string
	Scope                       string
	ServiceAccountID            *uuid.UUID
	RedirectURIs                []string
	PostLogoutRedirectURIs      []string
	AllowedAudiences            []string
	TokenEndpointAuthMethod     string
	TokenEndpointAuthSigningAlg string
	JWKSUri                     string
	JWKS                        string
	// The four logout-URI fields are tri-state:
	//   nil   = leave unchanged
	//   &""   = clear (set NULL / false)
	//   &"v"  = set to v
	FrontchannelLogoutURI             *string
	FrontchannelLogoutSessionRequired *bool
	BackchannelLogoutURI              *string
	BackchannelLogoutSessionRequired  *bool
}

// errClientNotFound is the sentinel for missing rows. Handlers map
// it to 404; service callers may errors.Is it.
var errClientNotFound = errors.New("service: client not found")

// RegisterClient creates a new OAuth client.
//
// Returns the persisted client and (for confidential clients) the
// plaintext secret. The plaintext is returned EXACTLY ONCE — it is
// hashed before insert and never persisted in raw form.
//
// For public clients (IsPublic=true) the plaintext is empty and no
// secret is stored.
func (s *ClientService) RegisterClient(ctx context.Context, opts RegisterClientOptions) (*domain.Client, string, error) {
	// Pure validation + credential/ID generation + struct build.
	client, plaintextSecret, err := s.prepareClient(opts)
	if err != nil {
		return nil, "", err
	}

	// Service-account binding gate (the READ). Kept HERE — not in
	// prepareClient — so the bundle path can reuse prepareClient and bind
	// the SA it creates in the SAME transaction (valid by construction, no
	// read of a not-yet-committed row). Public clients are NOT permitted to
	// bind a service account — client_credentials is a
	// confidential-client-only grant per RFC 6749 §4.4.
	if opts.ServiceAccountID != nil {
		if opts.IsPublic {
			return nil, "", fmt.Errorf("public client may not bind a service account")
		}
		if s.saBinding != nil {
			if err := s.saBinding.ValidateBindingForClient(ctx, *opts.ServiceAccountID, opts.OrganizationID); err != nil {
				return nil, "", err
			}
		}
	}

	if err := s.repo.RegisterClient(ctx, client); err != nil {
		return nil, "", err
	}
	return client, plaintextSecret, nil
}

// prepareClient runs the PURE portion of client creation: input
// validation, credential/ID generation (client_id, secret + hash,
// uuidv7), and domain.Client assembly. It performs NO database access and
// does NOT run the service-account binding read — the caller owns that.
//
// The bundle path (ServiceAccountClientBundleService) calls this directly
// with opts.ServiceAccountID == nil and binds the SA inside the same
// transaction that creates it, so the binding is valid by construction.
// RegisterClient calls it, then runs the binding read + repo write. The
// returned plaintext secret is the one-time value for secret-based
// confidential clients ("" for public / private_key_jwt clients).
func (s *ClientService) prepareClient(opts RegisterClientOptions) (*domain.Client, string, error) {
	if strings.TrimSpace(opts.Name) == "" {
		return nil, "", fmt.Errorf("client name is required")
	}
	if len(opts.RedirectURIs) == 0 {
		return nil, "", fmt.Errorf("at least one redirect URI is required")
	}
	if err := domain.ValidateRedirectURIs(opts.RedirectURIs); err != nil {
		return nil, "", err
	}
	if err := domain.ValidateLogoutURI(opts.FrontchannelLogoutURI); err != nil {
		return nil, "", err
	}
	if err := domain.ValidateLogoutURI(opts.BackchannelLogoutURI); err != nil {
		return nil, "", err
	}

	clientPublicID, err := crypto.GenerateRandomString(16) // 32 hex chars
	if err != nil {
		return nil, "", fmt.Errorf("client_id generation failed: %w", err)
	}

	// A private_key_jwt (assertion-only) client authenticates with a signed
	// JWT, never a shared secret — issuing one would leave a downgradeable
	// password on the record (P0-7). Only secret-based confidential clients
	// (client_secret_basic / client_secret_post, including the empty default
	// that resolves to basic) get a generated secret; public clients get none.
	var plaintextSecret, secretHash string
	if !opts.IsPublic && opts.TokenEndpointAuthMethod != "private_key_jwt" {
		plaintextSecret, err = crypto.GenerateRandomString(32) // 64 hex chars
		if err != nil {
			return nil, "", fmt.Errorf("client_secret generation failed: %w", err)
		}
		secretHash = crypto.HashSecret(plaintextSecret)
	}

	id, err := uuidgen.NewV7()
	if err != nil {
		return nil, "", fmt.Errorf("client uuid generation failed: %w", err)
	}

	now := time.Now().UTC()
	client := &domain.Client{
		ID:               id,
		ClientID:         clientPublicID,
		ClientSecretHash: secretHash,
		Name:             opts.Name,
		OrganizationID:   opts.OrganizationID,
		ServiceAccountID: opts.ServiceAccountID,
		// Persist the caller's public/confidential choice. This literal
		// dropped the flag (the DCR path sets it; this admin path lost it),
		// so every admin-created public client stored is_public=false —
		// invisible on reads AND able to slip past UpdateClient's
		// public-clients-may-not-bind-a-service-account guard, which reads
		// the STORED flag (v0.3.1 gap A).
		IsPublic:                          opts.IsPublic,
		Scope:                             opts.Scope,
		RedirectURIs:                      opts.RedirectURIs,
		PostLogoutRedirectURIs:            opts.PostLogoutRedirectURIs,
		AllowedAudiences:                  opts.AllowedAudiences,
		TokenEndpointAuthMethod:           opts.TokenEndpointAuthMethod,
		TokenEndpointAuthSigningAlg:       opts.TokenEndpointAuthSigningAlg,
		JWKSUri:                           opts.JWKSUri,
		JWKS:                              opts.JWKS,
		FrontchannelLogoutURI:             opts.FrontchannelLogoutURI,
		FrontchannelLogoutSessionRequired: opts.FrontchannelLogoutSessionRequired,
		BackchannelLogoutURI:              opts.BackchannelLogoutURI,
		BackchannelLogoutSessionRequired:  opts.BackchannelLogoutSessionRequired,
		CreatedAt:                         now,
		UpdatedAt:                         now,
	}
	return client, plaintextSecret, nil
}

// UpdateClient mutates an existing client by id. Empty string
// fields are interpreted as "leave unchanged"; non-nil slices
// replace the prior value.
func (s *ClientService) UpdateClient(ctx context.Context, id uuid.UUID, opts UpdateClientOptions) (*domain.Client, error) {
	client, err := s.repo.GetClientByID(ctx, id)
	if err != nil || client == nil {
		return nil, errClientNotFound
	}
	if opts.Name != "" {
		client.Name = opts.Name
	}
	if opts.Scope != "" {
		client.Scope = opts.Scope
	}
	if opts.RedirectURIs != nil {
		if err := domain.ValidateRedirectURIs(opts.RedirectURIs); err != nil {
			return nil, err
		}
		client.RedirectURIs = opts.RedirectURIs
	}
	if opts.PostLogoutRedirectURIs != nil {
		client.PostLogoutRedirectURIs = opts.PostLogoutRedirectURIs
	}
	if opts.AllowedAudiences != nil {
		client.AllowedAudiences = opts.AllowedAudiences
	}
	if opts.TokenEndpointAuthMethod != "" {
		client.TokenEndpointAuthMethod = opts.TokenEndpointAuthMethod
		// P0-7b — CLEAR THE SECRET ON A METHOD SWITCH. Moving a client to
		// private_key_jwt or none leaves it authenticating by assertion or not at
		// all, so the stored hash becomes credential material that can never be
		// presented and will never be rotated. The auth layer already refuses to
		// consult it; this stops it being retained. Data hygiene, not a
		// behaviour change at the token endpoint.
		if !domain.AuthMethodUsesClientSecret(client.EffectiveAuthMethod()) {
			client.ClientSecretHash = ""
		}
	}
	if opts.TokenEndpointAuthSigningAlg != "" {
		client.TokenEndpointAuthSigningAlg = opts.TokenEndpointAuthSigningAlg
	}
	if opts.JWKSUri != "" {
		client.JWKSUri = opts.JWKSUri
	}
	if opts.JWKS != "" {
		client.JWKS = opts.JWKS
	}
	if opts.FrontchannelLogoutURI != nil {
		if err := domain.ValidateLogoutURI(*opts.FrontchannelLogoutURI); err != nil {
			return nil, err
		}
		client.FrontchannelLogoutURI = *opts.FrontchannelLogoutURI
	}
	if opts.FrontchannelLogoutSessionRequired != nil {
		client.FrontchannelLogoutSessionRequired = *opts.FrontchannelLogoutSessionRequired
	}
	if opts.BackchannelLogoutURI != nil {
		if err := domain.ValidateLogoutURI(*opts.BackchannelLogoutURI); err != nil {
			return nil, err
		}
		client.BackchannelLogoutURI = *opts.BackchannelLogoutURI
	}
	if opts.BackchannelLogoutSessionRequired != nil {
		client.BackchannelLogoutSessionRequired = *opts.BackchannelLogoutSessionRequired
	}
	if opts.ServiceAccountID != nil {
		if *opts.ServiceAccountID == uuid.Nil {
			// Explicit unbind — caller sent a non-nil pointer to
			// uuid.Nil to mean "remove the binding".
			client.ServiceAccountID = nil
		} else {
			if client.IsPublic {
				return nil, fmt.Errorf("public client may not bind a service account")
			}
			if s.saBinding != nil {
				if err := s.saBinding.ValidateBindingForClient(ctx, *opts.ServiceAccountID, client.OrganizationID); err != nil {
					return nil, err
				}
			}
			bound := *opts.ServiceAccountID
			client.ServiceAccountID = &bound
		}
	}
	client.UpdatedAt = time.Now().UTC()
	if err := s.repo.Update(ctx, client); err != nil {
		return nil, err
	}
	return client, nil
}

// RegenerateClientSecret rotates the client's secret. Returns the
// new plaintext secret EXACTLY ONCE. Public clients are rejected.
func (s *ClientService) RegenerateClientSecret(ctx context.Context, id uuid.UUID) (*domain.Client, string, error) {
	client, err := s.repo.GetClientByID(ctx, id)
	if err != nil || client == nil {
		return nil, "", errClientNotFound
	}
	// A client is "public" when it has no secret hash on file. The
	// monolith carries the same invariant.
	if client.ClientSecretHash == "" {
		return nil, "", fmt.Errorf("cannot regenerate secret for a public client")
	}
	plaintext, err := crypto.GenerateRandomString(32)
	if err != nil {
		return nil, "", fmt.Errorf("client_secret generation failed: %w", err)
	}
	client.ClientSecretHash = crypto.HashSecret(plaintext)
	client.UpdatedAt = time.Now().UTC()
	if err := s.repo.Update(ctx, client); err != nil {
		return nil, "", err
	}
	return client, plaintext, nil
}

// DeleteClient soft-deletes (or hard-deletes per repo behavior) the
// client with id, scoped to orgID when non-nil.
func (s *ClientService) DeleteClient(ctx context.Context, id uuid.UUID, orgID *uuid.UUID) error {
	return s.repo.Delete(ctx, id, orgID)
}

// GetClient fetches a client by its UUID id.
func (s *ClientService) GetClient(ctx context.Context, id uuid.UUID) (*domain.Client, error) {
	c, err := s.repo.GetClientByID(ctx, id)
	if err != nil || c == nil {
		return nil, errClientNotFound
	}
	return c, nil
}

// ListClients returns a paginated set of clients, optionally scoped
// to orgID. Pass nil orgID for cross-tenant listing.
func (s *ClientService) ListClients(ctx context.Context, pagination repository.Pagination, orgID *uuid.UUID) ([]*domain.Client, int, error) {
	return s.repo.List(ctx, pagination, orgID)
}

// ErrClientNotFound exposes the OSS sentinel for handler-side
// errors.Is checks.
func ErrClientNotFound() error { return errClientNotFound }

// AuthenticateClient mirrors monolith
// (*ClientService).AuthenticateClient. Returns the resolved
// *domain.Client on success.
//
// Rules:
//   - Unknown client_id → ErrInvalidClientCredentials (NOT
//     ErrClientNotFound: a 404 vs 401 distinction at the
//     authentication boundary lets an attacker enumerate
//     client_ids by status code).
//   - Confidential client (IsPublic=false): clientSecret REQUIRED;
//     blank secret or hash mismatch → ErrInvalidClientCredentials.
//   - Public client (IsPublic=true): a supplied secret MUST match
//     when present (defense against a public client being
//     misconfigured with a leaked secret); an absent secret on a
//     public client returns the client unauthenticated.
//   - Hash compare is constant-time via subtle.ConstantTimeCompare
//     of the hex-encoded sha256 digests. This is stricter than the
//     monolith's plain `!=` comparison (which depends on Go string
//     comparison) — both yield equivalent security for hex
//     fixed-length digests, but constant-time is the documented
//     OSS norm for credential paths.
//
// The raw clientSecret is NEVER returned, logged, or echoed in any
// error message. The error sentinel is opaque — callers map it to
// 401 + WWW-Authenticate at the HTTP layer.
// GetClientByClientID looks up a client by its public client_id
// WITHOUT a credential check. Used by the assertion-based
// (private_key_jwt) auth path so it can read the client's
// configured JWKS / signing alg before verifying the assertion.
// Returns (nil, nil) for unknown client_ids.
func (s *ClientService) GetClientByClientID(ctx context.Context, clientID string) (*domain.Client, error) {
	if clientID == "" {
		return nil, nil
	}
	return s.repo.GetClientByClientID(ctx, clientID)
}

func (s *ClientService) AuthenticateClient(ctx context.Context, clientID, clientSecret string) (*domain.Client, error) {
	if clientID == "" {
		return nil, ErrInvalidClientCredentials
	}
	client, err := s.repo.GetClientByClientID(ctx, clientID)
	if err != nil {
		return nil, ErrInvalidClientCredentials
	}
	if client == nil {
		return nil, ErrInvalidClientCredentials
	}
	if !client.IsPublic {
		if clientSecret == "" {
			return nil, ErrInvalidClientCredentials
		}
		got := crypto.HashSecret(clientSecret)
		if subtle.ConstantTimeCompare([]byte(got), []byte(client.ClientSecretHash)) != 1 {
			return nil, ErrInvalidClientCredentials
		}
	} else if clientSecret != "" {
		got := crypto.HashSecret(clientSecret)
		if subtle.ConstantTimeCompare([]byte(got), []byte(client.ClientSecretHash)) != 1 {
			return nil, ErrInvalidClientCredentials
		}
	}
	return client, nil
}

// ErrInvalidClientCredentials is the single opaque sentinel
// returned by every credential-check failure path. Equality on
// this sentinel does NOT distinguish "unknown client" from "wrong
// secret" — callers must map both to 401 + WWW-Authenticate +
// invalid_client per RFC 6749 §5.2.
var ErrInvalidClientCredentials = errors.New("service: invalid client credentials")
