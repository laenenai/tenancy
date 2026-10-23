// This file must NOT compile. It is the negative half of the charter's
// control-plane/data-plane asymmetry, and it lives under testdata/ so the
// go tool's package patterns ignore it —
// TestControlPlaneIsNotADataPlaneHandle compiles it by explicit filename
// and requires the compiler to reject every line below.
//
// If this file ever builds, the guarantee the charter asks for has been
// lost. Each numbered case is one way the loss would present:
//
//   - A control-plane handle able to run caller-supplied SQL. The registry
//     tables carry no row-level-security policy, by necessity — resolution
//     must read them before any tenant context exists — so there is
//     nothing behind that path to catch a mistake. An unscoped predicate
//     there reads every tenant's row.
//   - A control-plane handle standing where a data-plane handle is
//     expected, or convertible into one. Either would let a statement
//     believing itself tenant-scoped run with no scope at all.
//   - A forged TenantTx. The whole value of that type is that holding one
//     is proof the session context was set. A forgeable proof is not a
//     proof.
package main

import (
	"context"

	"github.com/laenenai/tenancy"
	"github.com/laenenai/tenancy/internal/pg"
)

// runsTenantQuery stands in for every consumer function that runs
// tenant-scoped SQL.
func runsTenantQuery(tenancy.Scoped) {}

// readsRegistry stands in for every function that reads the registry.
func readsRegistry(*tenancy.Control) {}

func main() {
	ctx := context.Background()

	ten, err := tenancy.Open(ctx, tenancy.Config{RegistryDSN: "postgres:///example"})
	if err != nil {
		return
	}
	control := ten.Control()
	scoped, err := ten.Scope(ctx, tenancy.NewTenantID(tenancy.SystemClock{}))
	if err != nil {
		return
	}

	// 1. The control plane has no statement method at all. This is the
	//    charter's "must never be reachable with caller-supplied
	//    predicates", as a compile error rather than a code-review rule.
	_, _ = control.Query(ctx, "SELECT * FROM tenancy.tenants")
	_, _ = control.Exec(ctx, "UPDATE tenancy.tenants SET pool_id = $1", "whatever")
	_ = control.QueryRow(ctx, "SELECT 1")
	_, _ = control.Begin(ctx)

	// 2. A control-plane handle passed where a data-plane handle is
	//    required.
	runsTenantQuery(control)

	// 3. The conversion a named type, or a shared interface, would have
	//    allowed: one expression that turns the unscoped registry handle
	//    into something that looks tenant-scoped.
	runsTenantQuery(tenancy.Scoped(control))

	// 4. The reverse direction, so a data-plane handle cannot be used to
	//    read the registry unscoped either.
	readsRegistry(scoped)

	// 5. Nor through the representation: Scoped's fields are unexported,
	//    so no package outside internal/pg can assemble one.
	runsTenantQuery(tenancy.Scoped{tenant: control, db: nil})

	// 6. A forged TenantTx: holding one must be proof that the tenant
	//    session context was set, so there must be no way to make one
	//    from a transaction that has not been scoped.
	var raw pg.DDL
	_ = tenancy.TenantTx(raw)
	_ = tenancy.TenantTx{tx: nil, tenant: "01ARZ3NDEKTSV4RRFFQ69G5FAV"}

	// 7. And the transaction inside a real TenantTx must not be reachable:
	//    a caller able to commit early could run the rest of its work on a
	//    connection whose context has already been discarded.
	_ = scoped.Tx(ctx, func(_ context.Context, tx tenancy.TenantTx) error {
		return tx.Commit(ctx)
	})
}
