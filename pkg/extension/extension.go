// Package extension is the seam through which a trusted module that links
// identuum-idp-oss statically adds restrictions to OSS decisions (OSS-SEAM-4,
// owner rulings z and aa, 2026-10-08). It is deny-only: OSS builds every
// Decision after its own authentication, tenant authority and base checks,
// and a Restriction can only refuse what those checks allowed. A refusal, an
// error or a panic of a Restriction is a denial. Compatibility:
// docs/PUBLIC-API.md.
package extension

import (
	"context"

	"github.com/identuum/identuum-idp-oss/internal/extensionmint"
)

// The operations a Decision names.
const (
	OperationAPIResourceCreate = "api_resource.create"
	OperationAPIResourceUpdate = "api_resource.update"
	OperationAPIResourceDelete = "api_resource.delete"
)

// Decision is one operation OSS is about to perform, as OSS resolved it. It
// is immutable, and only OSS builds one; the zero Decision names no operation
// and is refused.
type Decision struct {
	actor, tenant, operation, target string
	scopes                           []string
}

func init() {
	extensionmint.NewDecision = func(f extensionmint.Fields) any {
		return Decision{actor: f.Actor, tenant: f.Tenant, operation: f.Operation, target: f.Target,
			scopes: append([]string(nil), f.RequiredScopes...)}
	}
}

// Actor is the acting user or client id.
func (d Decision) Actor() string { return d.actor }

// Tenant is the organization id the operation acts in.
func (d Decision) Tenant() string { return d.tenant }

// Operation is one of the Operation constants.
func (d Decision) Operation() string { return d.operation }

// Target is the id of the object the operation changes.
func (d Decision) Target() string { return d.target }

// RequiredScopes are the scopes the operation requires; a copy.
func (d Decision) RequiredScopes() []string { return append([]string(nil), d.scopes...) }

// IsZero reports whether d names no operation.
func (d Decision) IsZero() bool { return d.operation == "" }

// Restriction may refuse a Decision. A nil error allows what OSS allowed;
// anything else denies it.
type Restriction interface {
	Check(context.Context, Decision) error
}

// Code is the stable error code of a denial (owner ruling aa).
type Code string

const (
	Restricted      Code = "restricted"
	LicenseRequired Code = "license_required"
	QuotaExceeded   Code = "quota_exceeded"
)

// Denial is the error a Restriction returns to refuse with a stable code. Any
// other error, and a Code not listed above, is answered as Restricted.
type Denial struct {
	Code Code
}

func (d *Denial) Error() string { return "extension: denied: " + string(d.Code) }

// Status is the HTTP status of the denial: 409 for QuotaExceeded, 403
// otherwise. 429 stays for rate limits.
func (d *Denial) Status() int {
	if d.Code == QuotaExceeded {
		return 409
	}
	return 403
}
