# Go conventions for the laenen-ai shared modules

Derived from `cas` as it actually is on 2026-10-23, not from general Go advice.
`cas` is the reference implementation; when this file and `cas` disagree, `cas`
wins and this file is wrong. Every shared module follows these so that seven
repos read as one codebase.

## Toolchain and gates

- `go 1.25.6`. **`CGO_ENABLED=0`** — every module must build cgo-free and
  cross-compile. No dependency may require cgo.
- `gofumpt` (not plain gofmt) for formatting.
- `golangci-lint` with the committed `.golangci.yml`, unmodified. Enabled:
  `errcheck govet staticcheck revive gosec bodyclose rowserrcheck
  sqlclosecheck contextcheck errorlint noctx gocritic forbidigo depguard`.
- **`forbidigo` forbids `fmt.Print*` and `panic`** outside `cmd/`. Return
  errors; log through the injected logger.
- `mise` tasks, same names and same meanings as `cas`: `fmt`, `fmt-check`,
  `lint`, `test`, `build`, `test-all`, plus `api`, and `check` as the gate —
  it depends on `fmt-check lint build test-all`.
  There is no `api-check` task: the golden file is verified by an ordinary
  test, so `test` and `test-all` already cover it and the check cannot be
  forgotten. `api` only rewrites it.
- **A module's `mise.toml` is not a copy of cas's.** cas's `migrate`, `dev`,
  `up`, `down`, `reset`, `db` and observability tasks reference `./cmd/casd`
  and `deploy/compose/`, and its `generate` runs `sqlc`/`buf`; none of that
  exists in a library module. A task list with dangling entries trains people
  to ignore task lists. A module that later grows migrations or generated code
  adds the task it actually needs, under cas's name for it.

## Testing

- **`mise test` is the inner loop: `go test ./... -short`, no containers, no
  databases.** Tests requiring either **skip at run time** via `testing.Short()`
  — **never behind a build tag.** `mise test-all` runs everything.
- Table-driven tests. `t.Parallel()` where the test allows it.
- **Unit tests of a package live in `*_test.go`**, as ordinary Go.
- **Every port additionally ships a conformance suite**, exported as
  `RunXxxSuite(t *testing.T, newXxx func(t *testing.T) Xxx)`. The factory is
  called **once per subtest with that subtest's own `*testing.T`**, so an
  adapter registers its setup and teardown with `t.Cleanup` inside the factory
  and every subtest gets fresh isolated state.
- **The suite lives in a sibling `<module>test` package** — `keyringtest`,
  `audittest`, `metertest`, `iamtest — not in a `_test.go` file and not in the
  production package. Two reasons, and both are forced:
  - Identifiers in `_test.go` files are **not importable from outside the
    package**, and the suite must be callable from another package *and from
    another module* — CAS's seam runs `iam`'s suite against CAS's own
    authorization code, which is what makes "adopted" testable instead of
    asserted.
  - A non-`_test.go` file that imports `testing` makes `testing` a dependency
    of the **production** package, so every consumer's binary links it and
    inherits its flag registrations. A sibling package keeps it out of the
    production import graph.

  This is the standard library's own pattern: `testing/fstest.TestFS` verifies
  any `fs.FS`, and `httptest` is a sibling of `http` rather than part of it.
  **Note:** `cas/internal/blob/suite.go` puts the suite *in* `package blob`.
  That is tolerable for an `internal/` package nobody imports, and it is the
  one place these conventions deliberately diverge from `cas`. First increments
  that followed the in-package shape get moved; new code uses the sibling
  package.
- **The suite, not the interface, is the authoritative description of the
  contract's edge-case behaviour.** Say so in the package doc.
- Security invariants get their own named subtest in the suite, so every
  adapter is forced to exercise them (`cas`'s `NoPayloadContentLeaksInErrors`
  is the pattern to copy).

## Integration tests and containers

`cas` already settled this and every module follows it rather than inventing a
second approach.

- **`testcontainers-go` is the harness**, not a hand-rolled docker-compose
  dependency in tests. `cas` pins
  `github.com/testcontainers/testcontainers-go/modules/postgres`.
- **The image is `pgvector/pgvector:pg18`, not stock `postgres`** — vector
  columns exist in this system and the stock image lacks the extension, so a
  harness that uses it passes locally and fails where it matters.
- **Each test gets its own uniquely named, isolated database**, created and
  migrated fresh, so tests run in parallel with no shared state and no
  truncation between them. Do not share one database and clean up after.
- **`TEST_DATABASE_URL`, when set, is used instead of starting a container**,
  so CI and a developer with a running stack skip container startup.
- **The harness skips under `testing.Short()`**, which is why `mise test` is a
  genuine no-container inner loop and `mise test-all` is the full suite. Skip at
  run time; never behind a build tag.
- **The shared harness lives in `tenancy`** (see its charter), because tenant
  scoping and RLS are what it exists to test and a second consumer now needs
  it. `cas/internal/testdb` keeps its copy until the post-alpha swap; that is
  the agreed staged migration, not divergence.

**What needs a real integration test, not an in-memory adapter.** An in-memory
adapter proves the *contract*; it cannot prove the *enforcement*. Anything whose
correctness is a property of the database or of an external service must be
exercised against the real thing:

- RLS fail-closed behaviour — the central claim of `tenancy`, and unprovable
  without Postgres.
- Any SQL predicate whose plan matters: assert via `EXPLAIN` that it is an
  index join, because a budget met on 1,000 rows says nothing.
- Transactional semantics, including whether an append can join a caller's
  transaction.
- Migrations, applied forward on a fresh database.
- Every external-service adapter against that service's real image —
  **`openbao/openbao:2.2.1` for `keyring`'s transit adapter**, which `cas`'s
  dev stack already runs.

A module whose only adapter is in-memory is an unfinished module, and its
charter's adoption row should say so.

## When something deserves its own module

Asked about `Clock`, 2026-10-23, and the reasoning is reusable. Two questions,
in order:

**1. Does it have behaviour that can be wrong?** Not "is it duplicated" — Go
makes duplication of a *shape* free. Ask whether a second implementation could
behave differently in a way that matters, and what the blast radius is.

| Thing | Can it be wrong? | Verdict |
|---|---|---|
| RLS fail-closed scoping | yes → cross-tenant disclosure | `tenancy` |
| Authorization evaluation | yes → disclosure | `iam` |
| A canonical encoding / hash chain | yes → previously stored data unreadable, or tamper-evidence lost | `audit` |
| Envelope AAD binding | yes → a relocated value decrypts to the wrong answer | `seal` |
| Threshold key custody | yes → unrecoverable release | `escrow` |
| `Now() time.Time` | **no** — returning the current time is not a thing you get subtly wrong | not a module |

**2. Does sharing reduce risk, or only reduce typing?** Reducing typing is not
worth a `go.mod`, a charter, a CI pipeline, an `api.txt` and a release cadence.
For `Clock` the ceremony would exceed the content roughly thirtyfold.

### So: `Clock` is a convention, not a module

Each module declares it in `internal/domain/clock.go`, with the same shape —
`Clock` with one `Now() time.Time`, a `SystemClock`, and a `FixedClock` with
`Advance`. Go's structural typing means those independently declared interfaces
are interchangeable: a `SystemClock` from anywhere satisfies all of them, at
zero coupling. This is also Go's own idiom — the standard library ships no
`Clock`, because accepting the narrow interface you declare keeps the
dependency graph empty and the interface minimal.

And the failure mode a shared clock module invites is the one this whole
decomposition exists to avoid: today `Now()`, tomorrow `After`, `Sleep`,
`Timer`, `Ticker`, a time-travel fake, eventually a scheduler. That is
`platform` in miniature.

### The one piece of time handling that IS shared logic

**`CanonicalTime`** — truncating to UTC microseconds (see the timestamp
precision rule above) — *can* be wrong: truncate versus round, and the order of
UTC conversion versus truncation both change the result. It is three lines, so
it is still not a module, but it must be **the same three lines with the same
test in every module that digests, keys or compares an instant.** `audit` has
`domain.CanonicalTime`; copy it rather than reinventing it, and copy its test
with it.

## Package layout

- All domain types and value objects live in `internal/domain` and nowhere
  else.
- A root facade file (`<module>.go`) re-exports what a consumer must name, as
  **type aliases** so a value the internals produce and a value the consumer
  holds are the identical type.
- **The facade carries aliases, sentinels, exported constants, AND the module's
  entry points** — its constructor(s) and any free function a consumer must be
  able to call. What it must not carry is *logic*.

  Corrected 2026-10-23: an earlier version said "aliases and sentinel errors
  only", copied from `cas/cas.go`. But that file says in its own doc comment
  that it is aliases-only *because a later task is the one that adds the
  constructor* — it is a staging note, not a permanent rule, and promoting it
  to a convention produced a real defect: in `audit`, `Verify`,
  `VerifyEntries`, `NewMemory` and `BreakKind`'s constants ended up unreachable
  from outside the module, so a consumer could not use it. A facade that hides
  what the module is for is not a facade. Reachability is checked by `api.txt`:
  if a consumer would need to name it, it belongs in the golden file.

### Postgres timestamp precision

**Canonicalize every timestamp to UTC at microsecond precision** before it
enters a digest, an idempotency key, or any equality comparison. Postgres
`timestamptz` holds microseconds; a value carrying nanoseconds round-trips
equal in memory and unequal through the database. Two modules hit this
independently on the same day — `audit`, where a chain committing to
nanoseconds would verify in memory and then report every persisted entry as
tampered, and `meter`, where it would have made a conformance suite pass for
the wrong reason.
- One `Open(ctx, Config)` constructor. Config is a struct, validated, with
  typed errors.
- Adapters behind ports. The core performs no I/O and is unit-testable with
  in-memory adapters.
- **`sqlc` for queries; `goose` for migrations** (decided in `tenancy`'s
  charter); migrations embedded in the binary and applied by the library.

### sqlc is the default, and the objection to it was a misreading

Decided 2026-10-23, after `iam` and `audit` both hand-wrote their SQL.
`iam` documented two reasons; one was a real constraint with a clean answer, and
the other had it backwards.

- **"The SQL is the load-bearing artifact and belongs where it is read and
  reviewed rather than behind a generator."** This argues *for* sqlc, not
  against it. sqlc does not hide SQL — it puts it in `db/queries/*.sql`, where a
  reviewer reads it **as SQL**, with comments, syntax highlighting and a schema
  checked against it at generation time. The alternative is the same statement
  as a Go string literal inside a method, which is strictly less reviewable. A
  reconciliation's insert-then-delete-what-is-absent is *more* visible in a
  query file than inline.

- **"Mapping an opaque domain type through sqlc needs codec methods on the type
  whose point is having no reachable representation."** That constraint is real
  and the answer is not codec methods. Two cases:

  - **A named primitive type** (`TenantID string`, `KEKVersion uint32`) maps
    directly in an sqlc override, as `cas/sqlc.yaml` already does for every id
    column. Typed ids survive to the boundary and a generated layer never hands
    back a bare string.
  - **A deliberately opaque type** — a struct with an unexported field, so that
    no package outside `internal/domain` can forge or convert one, as
    `iam.ClearanceGroupID` is — maps to its **primitive**, and the adapter
    converts through the validating parser (`ParseClearanceGroupID`) at its own
    boundary. One conversion per field, and the invariant is untouched.

  **Never give such a type `sql.Scanner` or `driver.Valuer`.** Those methods are
  exported, so any package could then construct one from an arbitrary string —
  which destroys exactly the unforgeability the type exists for. A storage
  concern must not be solved by widening a security-relevant type's surface.

**The one genuine exception: SQL composed at runtime.** `iam`'s `Predicate`
returns a composable fragment for the consumer to embed in its own statement,
so there is no fixed query to generate. Hand-compose it, state in the package
doc that it is the exception and why, and keep its text in one place rather than
assembled across methods.

Anything else hand-written is a departure that needs a reason in the package
doc — and "the SQL matters here" is not one, because that is the case sqlc
serves best.

**Two limits of sqlc found in practice, recorded so they are not rediscovered:**

- **It cannot generate catalog queries.** sqlc resolves every relation against
  the `schema:` directory, which contains migrations and no `pg_catalog`, so a
  query reading `pg_roles`, `pg_class` or `pg_trigger` fails generation with
  `relation "pg_roles" does not exist`. There is a workaround — adding a fake
  `pg_catalog` schema file — and it should be **declined**: generated code
  would then agree with a fiction that drifts from the real catalog. Privilege
  and enforcement probes stay hand-written for this reason, which is a limit of
  the tool rather than a judgement about the SQL.
- **A fixed-size array cannot be overridden onto a `bytea` column.** pgx has no
  scan plan from `bytea` into `[32]byte`, so an override compiles and then fails
  at run time, and the only way to give pgx a plan is `sql.Scanner` /
  `driver.Valuer` on the type — which, for a digest or any other
  security-relevant value, is the thing the rule above forbids. Map the column
  to `[]byte` and convert through the type's validating constructor, which
  rejects a wrong length instead of truncating.

**And one generator quirk**: sqlc v1.30.0 collapses repeated `sqlc.arg()`
references to a single parameter but does **not** collapse repeated `@name`
ones — `@sequence` used twice generates a params struct with two fields called
`Sequence`, which is not valid Go. Use `sqlc.arg()` where a parameter appears
more than once, so arithmetic like `sequence = arg - 1` can stay in the SQL
rather than moving into Go.

**Pin the generator.** Generated code is committed and its header records the
version that wrote it, so an unpinned `sqlc` makes every developer's
`generate` a diff. The modules pin **1.30.0**, which produced the committed
code; `cas` pins 1.31.1. Converging is a deliberate one-commit bump across
`cas`, `audit` and `iam` together, not a drift to be fixed per repo.

## Errors

- **Sentinel errors declared once**, re-exported from the facade, documented
  where declared. Adapters map their own signals (a missing file, an S3
  `NoSuchKey`, an empty row) onto the module's sentinels so callers never
  branch on adapter-specific shapes.
- Wrap with `%w`. `errorlint` is on. Compare with `errors.Is`/`errors.As`.
- **Never put sensitive payload in an error or a log line.** State the
  invariant in the package doc and test it in the suite.

## Documentation

- Package doc comments explain *why the package exists and what invariant it
  holds*, not what the types are called. `cas/internal/blob/blob.go` is the
  length and tone to match.
- Exported identifiers are documented. Non-obvious decisions get the reasoning
  inline, not a bare restatement of the code.

## The boundary

- `CHARTER.md` is binding. Code that does not fit the charter belongs in a
  different module — raise it rather than widening the charter.
- `api.txt` is the public API as a golden file. Growing the public surface is
  a reviewed diff.
- **It is generated and checked by an ordinary test**, `api_test.go`, with an
  `-update-api` flag to rewrite it — Go's golden-file idiom. Not by a
  `cmd/apilist` main package: that puts a `main` in a library module's public
  tree, and it has to be remembered. A test runs inside `go test`, so `test`
  and `test-all` verify the surface automatically and there is no separate
  `api-check` task to forget. `mise run api` only rewrites.
- **`api.txt` must cover the `internal/` packages the facade aliases**, not
  only the importable ones. Because the facade re-exports internal types as
  aliases, **a change to an internal signature is a change to the public
  surface** even though Go's internal rule keeps the import path private. A
  generator listing only importable packages reports an incomplete surface —
  converting `meter` took its golden file from 76 lines to 261.
