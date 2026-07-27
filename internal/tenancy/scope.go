package tenancy

import (
	"context"

	"github.com/jackc/pgx/v5"
)

// The request-scoped transaction is carried in the context so that EVERY package touching
// tenant-scoped tables — not just internal/store, but the sibling stores (enroll, tickets) that own
// their own pools — runs its queries inside the same scoped transaction opened by
// store.WithTenantScope. That transaction has the tenant GUCs + the restricted deuswatch_app role set
// (SET LOCAL), so RLS filters every query. Keeping the key here (a leaf package with no deps but pgx)
// lets those packages share it without importing internal/store and creating an import cycle.
type txCtxKey struct{}

// WithTx returns a context carrying the scoped transaction. Called by store.WithTenantScope.
func WithTx(ctx context.Context, tx pgx.Tx) context.Context {
	return context.WithValue(ctx, txCtxKey{}, tx)
}

// TxFrom returns the scoped transaction carried in ctx, if any. A package's q(ctx) helper uses it to
// run scoped when a request opened a scope, and falls back to its raw pool otherwise (worker/gateway
// paths, which either bypass RLS via the super-admin GUC or don't need scoping).
func TxFrom(ctx context.Context) (pgx.Tx, bool) {
	tx, ok := ctx.Value(txCtxKey{}).(pgx.Tx)
	return tx, ok
}
