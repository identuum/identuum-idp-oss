package audit

import (
	"context"

	"github.com/google/uuid"
)

// Actor is who performs an action, as the authenticated request knows it
// (OSS-FIN-3). The bearer middleware attaches it to the request's context
// when it authenticates a principal, so a persistent Service fills an event's
// actor centrally instead of trusting every call site to.
//
// Type is one of the ActorType* values. ID is the user or service account;
// uuid.Nil for a client (ClientID then names it) and for the system.
// OrganizationID is the actor's OWN organization — never the organization
// acted upon, which the event carries in Event.OrganizationID.
type Actor struct {
	Type           string
	ID             uuid.UUID
	Email          string
	Role           string
	OrganizationID uuid.UUID
	ClientID       string
}

// The actor types a row carries. Anonymous is only a request with no
// principal (a failed sign-in, a public link); System is work no request
// started (a background sweep, a CLI command).
const (
	ActorTypeUser           = "user"
	ActorTypeServiceAccount = "service_account"
	ActorTypeClient         = "client"
	ActorTypeSetupToken     = "setup_token"
	ActorTypeSystem         = "system"
	ActorTypeAnonymous      = "anonymous"
)

type actorKey struct{}
type requestKey struct{}

// WithActor returns ctx carrying the actor of the current request.
func WithActor(ctx context.Context, a Actor) context.Context {
	return context.WithValue(ctx, actorKey{}, a)
}

// ActorFrom returns the actor attached by WithActor.
func ActorFrom(ctx context.Context) (Actor, bool) {
	if ctx == nil {
		return Actor{}, false
	}
	a, ok := ctx.Value(actorKey{}).(Actor)
	return a, ok
}

// WithRequest marks ctx as serving an HTTP request, so an event recorded
// without an actor is anonymous rather than system.
func WithRequest(ctx context.Context) context.Context {
	return context.WithValue(ctx, requestKey{}, true)
}

// IsRequest reports whether ctx was marked by WithRequest.
func IsRequest(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	v, _ := ctx.Value(requestKey{}).(bool)
	return v
}
