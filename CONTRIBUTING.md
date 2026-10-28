# Contributing

## Before you start

- Read `CHARTER.md` for the module boundary and `CONVENTIONS.md` for the Go
  conventions.
- Use `mise` for the toolchain. Do not add an unpinned tool to CI.
- Run `mise run check` before opening a pull request.

## Development loop

```bash
mise install
mise run fmt
mise run test          # no containers, no databases
mise run test-all      # race detector and containers
mise run check         # the gate: fmt-check, lint, build, test-all, sqlc diff, vuln
```

`mise run test` skips database tests; that is intentional, not a reduced
contract. Use `mise run test-all` before calling a change done.

## Tests and public surface

- New behaviour gets a test that failed first. Integration tests that need
  Postgres use `testdb.Start(t, testdb.WithMigrator(...))`.
- If a change adds or alters a public identifier, run `mise run api-diff`.
  It uses `apidiff` against the last root tag and compares the importable
  packages (internal packages are excluded). Breaking changes are reported;
  before 1.0 they are allowed, but they must be in `CHANGELOG.md` and
  `UPGRADING.md`. On a clean release tree, `gorelease` validates the proposed
  version.
- Security invariants get a named conformance subtest, not only a unit test.
- New adoption paths belong in `examples/` as a compile-checked program or a
  focused README, with the relevant best practices. `go build ./...` and
  `mise run check` cover the programs.

## Migrations

Migrations are forward-only in production. Add a new file under
`db/migrations/`; do not edit a released migration. `mise run generate` runs
sqlc against the full migration set. If a rollback is required, write an
explicit forward migration rather than relying on goose's `Down`.

## Releases

`main` is released by tagging it (`vX.Y.Z`). The release workflow runs
`mise run check`, then `gorelease` on the clean tag, and creates a GitHub
release from `CHANGELOG.md`.

The nested `testdb` module is versioned separately as `testdb/vX.Y.Z`. Release
the root module first, update `testdb`'s
`require github.com/laenenai/tenancy` to the new root version, then tag
`testdb/vX.Y.Z`. The testdb release job removes the local-development `replace`
before running `gorelease`; a published module must not depend on a filesystem
path. Update `CHANGELOG.md` and `UPGRADING.md` in the same pull request as a
breaking change.
