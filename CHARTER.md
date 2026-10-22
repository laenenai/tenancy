# Charter: `tenancy`

**It does this one thing:** Who the tenants are, where their data lives, and a
**pgx** connection already scoped to exactly one of them — failing closed if it
is not.

Concretely: the tenant and pool registry tables and their migrations; tenant →
pool resolution with caching; residency/region attributes; pgx pool and handle
lifecycle; RLS session context; tracing on the connection.

**It must not contain:** Authorization rules, grants, denials or markings
(`iam`). Key material (`keyring`). Schema migrations for anything but its own
registry tables. Query building. Any consumer's domain concepts.

## Why the registry and the connection are one module, not two

They were briefly split (`tenancy` + `pgtenant`) and merged on 2026-10-23,
because they fail the test that justifies a module: *would a consumer plausibly
want one without the other?* No. Nobody wants a tenant registry without scoped
connections, or scoped connections without knowing which tenant. Two modules
used only together are one module with extra version skew.

What the split did usefully surface is an asymmetry this module must handle
explicitly, because getting it wrong is a cross-tenant leak:

- **Control plane.** Reading the registry — resolving tenant → pool — happens
  *before* any tenant scope exists, so it necessarily uses an **unscoped**
  connection against the registry database. This path is small, auditable, and
  must never be reachable with caller-supplied predicates.
- **Data plane.** Every other connection is scoped to one resolved tenant, with
  RLS session context set, and a missing predicate **denies rather than
  leaking**.

Two connection kinds, one module, and the type system should make it impossible
to run a data-plane query on a control-plane handle.

## Why this is shared at all

Not duplication — blast radius. Both the CAS and kgs designs specify Postgres
RLS as a fail-closed backstop behind application-level scoping. That is a
cross-tenant disclosure control, and three independent implementations of a
cross-tenant disclosure control is three chances to fail silently. One
implementation, one conformance suite, one set of adversarial tests: missing
predicate, handle borrowed after close, session context not reset on handle
reuse, partial borrow during pool retirement. CAS has already found and fixed
TOCTOU and partial-borrow bugs in exactly this area, and those regression tests
come with the code.

## Two decisions recorded here, both open to reversal

1. **Migrations are not in scope, beyond this module's own registry tables, and
   should not become a module.** CAS built a bespoke migrator
   (`internal/migrate`, ~499 lines); acre's plans already chose **goose**. The
   resolution is goose everywhere, per the project's standing preference for
   industry standards, with CAS's migrator retired rather than extracted. This
   is the first visible drift between the three projects and it is cheaper to
   settle now than after acre's alpha.
2. **`config` and `obs` are deliberately NOT extracted yet.** CAS has ~1,400
   lines of each, and they are the classic contents of a catch-all shared
   module. The governing rule is that a module is created when a *second*
   consumer needs it, not in anticipation. kgs reaches them in phase 1;
   extract then, as two separate modules, never as one.

## Why this file exists

A shared module with no stated boundary accretes until it is the dependency
every project has and nobody can reason about. Two mechanisms enforce the
boundary rather than merely stating it:

1. **`api.txt`** is the public API as a golden file, diffed in CI. Growing the
   public surface requires a reviewed diff, so a new responsibility cannot slip
   in quietly.
2. **The conformance suite** (`suite.go`, following `cas/internal/blob/suite.go`)
   is the contract. A consumer counts as *adopted* when this suite runs green
   in that consumer's CI against its own wiring — not when someone says so.

Its own test harness (`testdb`) lives here as a subpackage, not as a separate
repo: it exists to test this module's contract.

## Adoption

| Consumer | State |
|---|---|
| cas | extraction pending — `internal/pool` (~1,691 lines), `internal/pg` (~1,026), `internal/domain/{tenant,pool}.go`, all built and tested |
| kgs | pending (phase 0 — required for the per-pool authorization projection, §6.2) |
| acre | pending (no code yet; adopts from birth) |

## Provenance

One of the single-purpose shared modules of
`kgs/docs/superpowers/specs/2026-10-23-knowledge-graph-store-design.md` §6.1,
created instead of a single `platform` module. Scope extended and `pgtenant`
merged in on owner's instruction, 2026-10-23.
