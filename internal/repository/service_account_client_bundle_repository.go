package repository

import (
	"context"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// ServiceAccountClientBundleRepository atomically provisions a service
// account together with a confidential OAuth client bound to it, in a
// SINGLE database transaction. Either BOTH rows persist or NEITHER does —
// there is no window in which a service account exists without its client
// (the orphan-SA hazard that the prior compensating-delete flow left open
// on a double failure / crash — P2-16b).
//
// The caller supplies a fully-prepared (validated, ID/secret-generated)
// service account and client; the client's ServiceAccountID is set by the
// implementation to the just-created SA's id inside the same transaction,
// so the binding is valid by construction (no read of a not-yet-committed
// row). On any error nothing is persisted and the returned rows are nil.
type ServiceAccountClientBundleRepository interface {
	CreateWithClient(ctx context.Context, sa *domain.ServiceAccount, client *domain.Client) (*domain.ServiceAccount, *domain.Client, error)
}
