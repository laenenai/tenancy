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
  `lint`, `generate`, `test`, `build`, `test-all`, `check`.
  `check` depends on `fmt-check lint build test-all` and is the gate.

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

## Package layout

- All domain types and value objects live in `internal/domain` and nowhere
  else.
- A root facade file (`<module>.go`) re-exports what a consumer must name, as
  **type aliases** so a value the internals produce and a value the consumer
  holds are the identical type. It declares aliases and sentinel errors only —
  no behaviour, no constructors beyond the single `Open`.
- One `Open(ctx, Config)` constructor. Config is a struct, validated, with
  typed errors.
- Adapters behind ports. The core performs no I/O and is unit-testable with
  in-memory adapters.
- `sqlc` for queries; `goose` for migrations (decided in `tenancy`'s charter);
  migrations embedded in the binary and applied by the library.

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
- `api.txt` is the public API as a golden file, regenerated and diffed in CI.
  Growing the public surface is a reviewed diff.
