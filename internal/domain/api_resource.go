package domain

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// APIResource represents an OAuth2 Resource Server
type APIResource struct {
	ID                 uuid.UUID
	OrganizationID     uuid.UUID
	Name               string
	Audience           string
	Active             bool
	TokenTTLSecs       int
	ResourceSecretHash string
	CreatedAt          time.Time
	UpdatedAt          time.Time

	Scopes []APIScope // Loaded relationally
}

// APIScope represents a specific scope under an APIResource
type APIScope struct {
	ID          uuid.UUID
	ResourceID  uuid.UUID
	Name        string
	Description string
}

// Validate checks if the APIResource is reasonably valid
func (a *APIResource) Validate() error {
	if a.Name == "" {
		return errors.New("API resource name is required")
	}
	if a.Audience == "" {
		return errors.New("API resource audience is required")
	}
	if a.TokenTTLSecs <= 0 {
		return errors.New("API resource token TTL must be greater than zero")
	}
	// ResourceSecretHash may be empty during initial creation before hashing,
	// but generally it's required for persistence. We only validate business logic here.
	return nil
}

// ValidateAPIScopes applies the per-scope invariants that §2.11 shares with
// §2.2's ScopeTemplate.Validate: each scope name must be non-empty, contain no
// internal whitespace (RFC 6749 §3.3), and not carry one of the reserved
// platform prefixes (`system:`, `keys:`, `backups:`) that org_admin callers
// must never be able to plant on an org-owned resource. Without this guard
// an org admin could create an API Resource with a scope named `system:admin`
// and bind it via RBAC to a role, side-channeling the prefix invariant that
// `ClientService.validateScopePermissions` and `ScopeTemplate.Validate`
// enforce at their own entry points.
func ValidateAPIScopes(scopes []APIScope) error {
	for _, s := range scopes {
		if s.Name == "" {
			return fmt.Errorf("%w: api resource scope name must not be empty", ErrInvalidRequest)
		}
		if strings.ContainsAny(s.Name, " \t\r\n") {
			return fmt.Errorf("%w: api resource scope %q contains whitespace and is not a valid OAuth2 scope token", ErrInvalidRequest, s.Name)
		}
		for _, reserved := range reservedScopePrefixes {
			if strings.HasPrefix(s.Name, reserved) {
				return fmt.Errorf("%w: api resource scope %q is reserved and cannot be assigned by an org admin", ErrInvalidRequest, s.Name)
			}
		}
	}
	return nil
}

// ScopeTemplate is a named, reusable bundle of OAuth2 scope strings scoped
// to an organization. Templates are CRUD-only inert records: no service or
// middleware in this codebase reads stored templates to apply them to an
// API Resource or Service Account — the bundle is shipped to operators
// (UI / API consumers) for them to copy into the appropriate target.
//
// Forward-looking note for any future apply-to-resource path: the apply
// step MUST re-run `Validate` on each scope before persisting it on the
// target row. The §2.2 RBAC bound (no `system:` / `keys:` / `backups:`,
// no whitespace, no empty entries) is currently enforced only at template
// create/update time; an apply path that copies the stored slice without
// re-validation would silently bypass that bound the day a stored row
// pre-dating a future Validate change carries a now-forbidden value.
type ScopeTemplate struct {
	ID             uuid.UUID
	OrganizationID uuid.UUID
	Name           string
	Description    string
	Scopes         []string
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// reservedScopePrefixes contains scope prefixes that are restricted to system-level
// service accounts and must never be stored in org-admin-controlled scope templates.
// Storing these would allow an Org Admin to later apply them to a Service Account,
// bypassing the RBAC privilege boundary this feature is designed to enforce.
var reservedScopePrefixes = []string{"system:", "keys:", "backups:"}

// Validate checks that the ScopeTemplate has the required fields.
//
// Per-scope rules close §2.2's RBAC-bound bypass paths: each scope must be
// non-empty and contain no internal whitespace before the reserved-prefix
// check runs. Without these guards, an Org Admin could submit
// `" system:admin"` (leading space) and bypass the strings.HasPrefix check
// — RFC 6749 §3.3 forbids whitespace inside a scope token in the first
// place, so the reject is both spec-compliant and security-load-bearing.
func (t *ScopeTemplate) Validate() error {
	if t.Name == "" {
		return errors.New("scope template name is required")
	}
	if len(t.Name) > 100 {
		return errors.New("scope template name must not exceed 100 characters")
	}
	if len(t.Scopes) == 0 {
		return errors.New("scope template must have at least one scope")
	}
	for _, scope := range t.Scopes {
		if scope == "" {
			return errors.New("scope template entries must be non-empty")
		}
		if strings.ContainsAny(scope, " \t\r\n") {
			return fmt.Errorf("scope %q contains whitespace and is not a valid OAuth2 scope token", scope)
		}
		for _, reserved := range reservedScopePrefixes {
			if strings.HasPrefix(scope, reserved) {
				return fmt.Errorf("scope %q is reserved and cannot be assigned to a template", scope)
			}
		}
	}
	return nil
}
