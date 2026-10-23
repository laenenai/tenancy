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

   **Reversed later the same day, 2026-10-23, by evidence rather than by
   argument.** It *did* become a module: `pgmigrate`. Not in anticipation —
   the `iam` and `audit` increments were built in parallel by agents that
   could not see each other's work and produced the same machinery line for
   line, including the same `1`/`300` poll constants, which is the
   second-consumer rule satisfied by duplication that already happened. The
   half of this decision that stands is the engine: it is goose everywhere,
   and CAS's bespoke migrator is retired rather than extracted.

   This module is `pgmigrate`'s first consumer, which is how that module
   earns its confidence. See `internal/migrate`.
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
2. **The conformance suite** is the contract. A consumer counts as *adopted*
   when this suite runs green in that consumer's CI against its own wiring —
   not when someone says so.

   Corrected 2026-10-23 during implementation: it is `tenancytest/suite.go`,
   a sibling package, not a `suite.go` inside the production package
   following `cas/internal/blob/suite.go`. `CONVENTIONS.md` had already
   settled that and this file had not caught up. Both reasons are forced —
   identifiers in `_test.go` files are not importable from another module,
   and a non-`_test.go` file importing `testing` would put `testing` in every
   consumer's production import graph.

Its own test harness (`testdb`) lives here as a subpackage, not as a separate
repo. Corrected 2026-10-23: it is not only "to test this module's contract" —
`CONVENTIONS.md` makes this module the home of the **shared** container
harness, which `cas` and `audit` have a copy of each and will import from here
after the post-alpha swap. That makes it an exported package whose API is
public surface in `api.txt`, not an `internal/` detail; a change to
`testdb.Start`'s signature breaks other modules' test suites.

## Adoption

| Consumer | State |
|---|---|
| cas | **extracted into this module 2026-10-23**; the swap in `cas` is pending. `internal/pool` (~1,691 lines) and `internal/pg` (~1,026) came across with their TOCTOU and partial-borrow regression tests; `cas` keeps its copy until the post-alpha swap, which is the agreed staged migration |
| kgs | pending (phase 0 — required for the per-pool authorization projection, §6.2) |
| acre | pending (no code yet; adopts from birth) |

This module's own CI runs `tenancytest.RunTenancySuite` against
`tenancy/testdb`, so "the suite is green" is true of the reference wiring. No
consumer has run it against its own wiring yet, so by this file's own
definition nothing is adopted.

## Provenance

One of the single-purpose shared modules of
`kgs/docs/superpowers/specs/2026-10-23-knowledge-graph-store-design.md` §6.1,
created instead of a single `platform` module. Scope extended and `pgtenant`
merged in on owner's instruction, 2026-10-23.
