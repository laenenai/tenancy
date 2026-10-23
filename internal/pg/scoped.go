package pg

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/puddle/v2"

	"github.com/laenenai/tenancy/internal/domain"
)

// TenantGUC is the Postgres session variable every row-level-security
// policy this module creates keys off.
//
// It is `app.tenant_id` rather than `tenancy.tenant_id`, and the name is
// load-bearing in a way worth stating: it appears verbatim in the policy
// SQL of every consumer that has already adopted this convention —
// `cas`'s db/migrations/00003_rls.sql, `audit`'s 00001_audit.sql — so
// renaming it would silently stop matching their existing policies while
// everything still compiled.
//
// It deliberately does NOT contain this module's import path. That is
// checked by a test, because on 2026-10-23 a module rename rewrote a hash
// function's domain-separation tag in a sibling module and invalidated its
// committed test vectors; a GUC name is the same class of constant, and
// the consequence of it moving is worse — a policy that no longer matches
// does not fail, it stops filtering.
const TenantGUC = "app.tenant_id"

// Scoped is a data-plane handle: exactly one resolved tenant, on the pool
// that hosts it, and the only path in this module through which
// caller-supplied SQL reaches a database.
//
// # Why it has no Query method of its own
//
// Every statement runs through Tx, inside a transaction that has already
// established the tenant's row-level-security session context. There is no
// unscoped way in. A caller cannot forget to set the predicate, because a
// caller never sets it: the type does, before handing over a TenantTx.
//
// A Scoped cannot be built outside this module (NewScoped is internal) and
// cannot be converted from anything, because its fields are unexported.
// The control-plane handle — internal/registry.Control — is a different
// type with no SQL-taking method at all, so "run a data-plane query on a
// control-plane handle" is not an expressible program. See
// testdata/control_plane_is_not_a_data_plane_handle.go, which the compiler
// is required to reject.
//
// # The zero value denies
//
// The zero Scoped carries no tenant and no pool, and every method on it
// returns domain.ErrNoTenantScope. That is the charter's "a missing
// predicate denies rather than leaking", applied to the one data-plane
// shape Go cannot forbid: a struct's zero value. It is a validated refusal
// rather than a nil-pointer panic, so a caller can assert on it.
type Scoped struct {
	tenant  domain.Tenant
	poolRow domain.Pool
	db      *pgxpool.Pool
	appRole string
}

// NewScoped builds the data-plane handle for a resolved tenant. It is
// unexported from the module's public surface on purpose: only resolution
// produces a Scoped, which is what makes "this handle is scoped to a
// tenant that was actually resolved and found active" true by
// construction.
//
// appRole may be empty, meaning "do not switch roles" — see Tx.
func NewScoped(tenant domain.Tenant, poolRow domain.Pool, db *pgxpool.Pool, appRole string) Scoped {
	return Scoped{tenant: tenant, poolRow: poolRow, db: db, appRole: appRole}
}

// Tenant returns the tenant this handle is scoped to.
func (s Scoped) Tenant() domain.Tenant { return s.tenant }

// Pool returns the pool hosting this handle's tenant.
func (s Scoped) Pool() domain.Pool { return s.poolRow }

// AppRole returns the role every transaction this handle opens narrows
// itself to, or the empty string if it narrows to nothing.
func (s Scoped) AppRole() string { return s.appRole }

// Valid reports whether this handle came from a resolution. The zero
// Scoped is not valid and every operation on it is refused with
// domain.ErrNoTenantScope.
func (s Scoped) Valid() bool { return s.db != nil && s.tenant.ID != "" }

// Tx runs fn inside a transaction whose row-level-security session context
// is already established for this handle's tenant, and commits it if fn
// returns nil.
//
// Two settings are applied, both transaction-local, before fn sees the
// transaction:
//
//  1. `SET LOCAL ROLE <AppRole>`, when AppRole is set. This narrows a
//     connection that may hold more privilege than the application needs —
//     notably, it drops a superuser's unconditional bypass of row
//     security, which is the single most common reason an RLS backstop is
//     believed to be working while enforcing nothing. SET LOCAL ROLE takes
//     no bound parameter, so the role name reaches Postgres as SQL text;
//     it is quoted through pgx.Identifier and validated as a plain
//     identifier at configuration time.
//
//  2. `set_config(TenantGUC, <tenant id>, true)`. The is_local=true third
//     argument gives it exactly SET LOCAL's semantics, so the tenant id
//     travels as a bound query parameter rather than as interpolated SQL
//     text.
//
// Both being transaction-local is what makes a pooled connection safe to
// hand to the very next borrower: the instant this transaction ends, by
// commit or by rollback, neither setting remains. That property is the one
// the fail-closed backstop depends on, and
// Enforcement.ResidualTenantContext is how a deployment checks that it
// holds rather than assuming it.
//
// If fn returns an error the transaction is rolled back and that error is
// returned unwrapped — not joined with a sentinel of this module's — so a
// caller can still inspect it with errors.Is and errors.As.
func (s Scoped) Tx(ctx context.Context, fn func(ctx context.Context, tx TenantTx) error) error {
	if !s.Valid() {
		return fmt.Errorf("%w: this handle was not produced by resolving a tenant, so there is no tenant to scope to", domain.ErrNoTenantScope)
	}
	if fn == nil {
		return fmt.Errorf("%w: pg: Tx was given no function to run", domain.ErrInvalidConfig)
	}

	tx, err := s.begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if err := s.scope(ctx, tx); err != nil {
		return err
	}

	if err := fn(ctx, TenantTx{tx: tx, tenant: s.tenant.ID}); err != nil {
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("%w: commit the tenant-scoped transaction: %w", domain.ErrUnavailable, err)
	}
	return nil
}

// begin starts the transaction, mapping a closed pool onto this module's
// taxonomy.
//
// A handle borrowed before the resolver closed its pool and used
// afterwards lands here. puddle.ErrClosedPool is pgx's own signal and it
// must not reach a caller as a third-party error: the answer a caller
// needs is "this is not usable right now, and a fresh resolution against a
// running resolver would be", which is exactly ErrUnavailable. See the
// conformance suite's HandleBorrowedAfterCloseIsRefused.
func (s Scoped) begin(ctx context.Context) (pgx.Tx, error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		if errors.Is(err, puddle.ErrClosedPool) {
			return nil, fmt.Errorf("%w: this handle's pool has been closed; resolve the tenant again", domain.ErrUnavailable)
		}
		return nil, fmt.Errorf("%w: begin a tenant-scoped transaction: %w", domain.ErrUnavailable, err)
	}
	return tx, nil
}

// scope applies the role narrowing and the tenant GUC. It runs before fn
// sees the transaction and a failure in either is fatal to the
// transaction: a transaction that reached a caller with the role switched
// but the tenant unset would be the exact fail-open this module exists to
// prevent.
func (s Scoped) scope(ctx context.Context, tx pgx.Tx) error {
	if s.appRole != "" {
		if _, err := tx.Exec(ctx, "SET LOCAL ROLE "+pgx.Identifier{s.appRole}.Sanitize()); err != nil {
			return fmt.Errorf("%w: narrow the transaction to the application role: %w", domain.ErrUnavailable, err)
		}
	}
	if _, err := tx.Exec(ctx,
		"SELECT set_config($1, $2, true)", TenantGUC, string(s.tenant.ID),
	); err != nil {
		return fmt.Errorf("%w: set the tenant session context: %w", domain.ErrUnavailable, err)
	}
	return nil
}

// TenantTx is a Postgres transaction that already carries one tenant's
// row-level-security session context.
//
// It is a struct with unexported fields and no constructor reachable from
// outside this module, which is the point: a value of this type is proof
// that the context was set, and no package can forge that proof. A named
// interface type would not do — any pgx.Tx would satisfy it, and the
// guarantee would evaporate at the first call site that passed a raw
// transaction.
//
// Its three statement methods are exactly sqlc's generated DBTX interface
// for pgx/v5, so a consumer hands a TenantTx straight to its own
// generated Queries constructor and every query it has ever written runs
// tenant-scoped with no wrapper and no remembering.
//
// It deliberately exposes no Commit, Rollback or Begin. The transaction's
// lifetime belongs to Scoped.Tx, which is what guarantees the scope and
// the statements share one transaction — a caller able to commit early
// could run the rest of its work on a connection whose context has
// already been discarded.
type TenantTx struct {
	tx     pgx.Tx
	tenant domain.TenantID
}

// Tenant returns the tenant this transaction is scoped to. A consumer
// filling in its own tenant_id column reads it from here rather than
// carrying the id separately, so the column and the policy cannot disagree.
func (t TenantTx) Tenant() domain.TenantID { return t.tenant }

// Exec runs one statement in the tenant-scoped transaction.
func (t TenantTx) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	return t.tx.Exec(ctx, sql, args...)
}

// Query runs one query in the tenant-scoped transaction.
func (t TenantTx) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	return t.tx.Query(ctx, sql, args...)
}

// QueryRow runs one single-row query in the tenant-scoped transaction.
func (t TenantTx) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	return t.tx.QueryRow(ctx, sql, args...)
}
