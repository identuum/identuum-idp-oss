// Package extensionmint holds the one constructor of a pkg/extension.Decision
// (OSS-SEAM-4). pkg/extension sets NewDecision when it initialises; the Go
// toolchain refuses an import of this package from outside the module, so a
// downstream module can hold a Decision but never build one.
package extensionmint

// Fields are the facts OSS resolved for one decision.
type Fields struct {
	Actor, Tenant, Operation, Target string
	RequiredScopes                   []string
}

// NewDecision returns a pkg/extension.Decision holding f. It is nil only
// before pkg/extension initialises, which happens before any importer runs.
var NewDecision func(f Fields) any
