# Tenancy Production-Readiness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close every finding in `docs/review/20261028_review.md`, make the public API and documentation adoptable, and leave the repository with a green, reproducible gate and a human-readable changelog.

**Architecture:** Keep the control-plane/data-plane type split and the conformance suite. Make the credential boundary capability-based (`PoolRef`), split control-plane and data-plane roles, make status changes invalidate the resolver cache immediately, make RLS enforcement inspect the policy rather than its name, and make shutdown wait for every background close. Then align the facade, tests, CI, and docs with the resulting API.

**Tech Stack:** Go 1.27.3, pgx/v5, pgxpool, sqlc 1.30.0, goose/pgmigrate, OpenBao HTTP API, testcontainers, mise, golangci-lint 2.15.0, gofumpt 0.12.0.

**Spec:** `docs/review/20261028_review.md` (review and maintainer decisions recorded there).

## Global Constraints

- Go 1.27.3; `CGO_ENABLED=0` for the shipped build; race tests use cgo.
- `mise.toml` is the single source of tool versions. Do not revert the authoritative working-tree edits to `mise.toml`, `go.mod`, or `.github/workflows/ci.yml`.
- Pre-1.0: breaking API changes are allowed and expected. Mark them in `CHANGELOG.md` and `UPGRADING.md`.
- Keep the control-plane/data-plane type separation; do not expose arbitrary SQL on `Control`.
- No commits unless the user explicitly asks; use the working tree and leave it reviewable.
- Every task ends with `gofumpt`, `go vet`, targeted tests, and the relevant package test; final task runs the full gate.
- Do not weaken the existing redaction or conformance tests; update them only when the contract intentionally changes.

## Review Focus

- A tenant resolved while active, then suspended or marked deleting: the next `Scope` must refuse without waiting for TTL.
- A custom `Credentials` implementation holding a token: every `Config`/`Options` rendering must not print it.
- A tenant table with a permissive-only, wrong-predicate, disabled, unFORCEd, or missing-companion policy: coverage and enforcement must report it.
- A request canceled while a pool is being opened: the issued credential must still be released.
- A mixed-case `AppRole` and a `WorkerCapacity` above `math.MaxInt32`: both must fail or store safely, never silently wrap/mismatch.
- `CheckEnforcement` with no table list: must not report fail-closed.

---

### Task 1: Domain foundations and public surface

**Files:**
- Modify: `internal/domain/pool.go`, `internal/domain/errors.go`, `internal/domain/tenant.go`, `internal/domain/credentials.go`
- Delete: `internal/domain/readiness.go`
- Modify: `tenancy.go`
- Test: `internal/domain/domain_test.go`, `tenancytest/suite.go`

**Interfaces:**
- Produces: `domain.PoolRef{ID, Name, Region, BlobConfigRef, WorkerCapacity, CreatedAt}`; `func (Pool) Ref() PoolRef`; `domain.ErrPermission`; `func (TenantStatus) CanTransitionTo(next TenantStatus) bool`; `func (Credential) MarshalText() ([]byte, error)`.
- Removes: `domain.Readiness`, `Readiness*` constants.
- Renames: `registry.NewPool`/`NewTenant` to `PoolSpec`/`TenantSpec` (exported through the facade as `tenancy.PoolSpec`/`tenancy.TenantSpec`).

- [x] **Step 1: Write failing domain tests** for `Pool.Ref`, `CanTransitionTo` (including `deleting → active` false), and `Credential.MarshalText` returning the redacted form.
- [x] **Step 2: Run `go test ./internal/domain` and confirm the new tests fail.**
- [x] **Step 3: Implement `PoolRef`, `Pool.Ref`, `ErrPermission`, `CanTransitionTo`, `MarshalText`; delete `Readiness` and its test/alias.**
- [x] **Step 4: Rename the registry input types and update every reference, including the facade.**
- [x] **Step 5: Run `go test ./internal/domain ./internal/registry`; update `tenancy.go` exports; API compatibility is checked in Task 11.**

### Task 2: Config, lifecycle options, and validation

**Files:**
- Modify: `internal/pool/resolver.go`, `internal/scope/scope.go`, `internal/pg/pool.go`
- Test: `internal/pool/resolver_test.go`, `internal/scope` (new `scope_test.go`), `tenancytest/suite.go`

**Interfaces:**
- Produces: `pool.LifecycleOptions{Credentials domain.Credentials, LongestTransaction time.Duration, Clock domain.Clock, OnCredentialReleaseError func(domain.PoolRef, error)}`; `NewResolver(registry, open, Options, LifecycleOptions)`.
- `scope.Config` gains `LongestTransaction time.Duration`; `Cache` keeps only cache knobs.
- Validation in `scope.Open`: non-negative TTLs, `MaxConns >= MinConns` when both set, credentials require `LongestTransaction`.
- `MaxPools == 0` uses `DefaultMaxPools`; `MaxPools < 0` is explicitly unbounded. `MaxTenants <= 0` uses `DefaultMaxTenants`.

- [x] **Step 1: Add failing tests** for a zero `MaxPools` bounded default, negative TTL rejection, `MinConns > MaxConns` rejection, and `Config` with only `Cache.Credentials` being rejected (no hidden path).
- [x] **Step 2: Implement `LifecycleOptions`, move the fields, and validate in `scope.Open`.**
- [x] **Step 3: Update all callers/tests to the new shape.**
- [x] **Step 4: Run `go test ./internal/pool ./internal/scope ./`.**

### Task 3: Resolver correctness and observability

**Files:**
- Modify: `internal/pool/resolver.go`, `internal/pool/cache.go`
- Test: `internal/pool/resolver_test.go`, `internal/pool/retirement_test.go`, `tenancytest/suite.go`

**Interfaces:**
- Produces: `CachingResolver.InvalidateTenant(domain.TenantID)`; `CachingResolver.Stats() Stats`; `Stats` fields for open pools, retired pending, positive/negative cache sizes, credentials issued/released/release failures.
- `Close` waits for all background closes and releases before returning.
- `openNewPool` releases a credential with a detached timeout on error paths.
- `LifecycleOptions.OnCredentialReleaseError` is called when `Release` fails.

- [x] **Step 1: Add failing tests** for resolve→invalidate→re-resolve, `Close` waiting for a release that blocks until a gate opens, canceled-context release, and stats counts.
- [x] **Step 2: Add `InvalidateTenant`, stats counters, release hook, and the closing-set/wait logic.**
- [x] **Step 3: Ensure all background closes are registered while holding the resolver lock; `Close` waits on a condition until the closing set is empty.**
- [x] **Step 4: Run `go test ./internal/pool -race -count=1`.**

### Task 4: Registry roles, status transitions, and errors

**Files:**
- Modify: `internal/registry/registry.go`, `internal/migrate/migrate.go`, `db/queries/tenants.sql`, `db/migrations/00001_registry.sql`
- Add: `db/migrations/00002_control_role_and_status.sql`
- Test: `internal/migrate/migrate_test.go`, `tenancytest/suite.go`

**Interfaces:**
- `migrate.Config{gains ControlRole string}`; `Up` requires `ControlRole` and `AppRole`; `Status` requires only `DSN`.
- Registry grants go to `ControlRole`; data-plane `AppRole` gets no registry privileges.
- `Control.SetTenantStatusObserver(func(domain.TenantID, domain.TenantStatus))`; `SetTenantStatus` calls it after a successful update.
- `SetTenantStatus` rejects invalid transitions via a trigger and maps the failure to `ErrConflict`.
- `WorkerCapacity` is capped at `math.MaxInt32`; migration adds `CHECK (worker_capacity >= 0)`.
- `mapErr`: `42501 → ErrPermission`; `23514 → ErrInvalidConfig`; unique/FK/trigger remain `ErrConflict`.

- [x] **Step 1: Add failing tests** for `Status` without `AppRole`, control-role-only registry grants, `deleting → active` rejection, and `WorkerCapacity` overflow.
- [x] **Step 2: Implement the role split, observer, status trigger, and bounds.**
- [x] **Step 3: Update `mise exec -- sqlc generate` output and `go test ./internal/migrate ./internal/registry`.**

### Task 5: RLS enforcement, coverage, and predicates

**Files:**
- Modify: `internal/pg/rls.go`, `internal/pg/enforcement.go`, `tenancy.go`
- Test: `internal/pg/pg_test.go`, `internal/pg/rls_integration_test.go`, `tenancytest/suite.go`

**Interfaces:**
- `TableEnforcement` gains `PolicyPresent`, `AccessPolicyPresent`, `PolicyHasCheck`, `PolicyMatchesPredicate`.
- `CheckEnforcement` rejects an empty table list (`ErrInvalidConfig`).
- `Findings` treats `OwnedByRole` as a finding regardless of FORCE.
- `AssertRLSCoverage` requires enabled + forced RLS, a restrictive `tenant_isolation` policy with `WITH CHECK`, the predicate, and a permissive companion.
- `IsInsufficientPrivilege` and `IsRLSPolicyViolation` replace `IsRLSViolation`.
- `RegistryTablesExemptFromRLS()` returns a copy; no mutable exported map.

- [x] **Step 1: Add failing fixtures** for permissive-only, wrong predicate, RLS disabled/unFORCEd, missing companion, owner+FORCE, and empty table list.
- [x] **Step 2: Implement the catalog queries and findings.**
- [x] **Step 3: Update `EnableRLS` docs to describe both policies; re-export `TenantAccessPolicyName` and `Redacted`.**
- [x] **Step 4: Run `go test ./internal/pg -count=1` and the root conformance test.**

### Task 6: Scoped/TenantTx and PoolRef

**Files:**
- Modify: `internal/pg/scoped.go`, `internal/domain/credentials.go`, `internal/domain/pool.go`, `internal/scope/scope.go`, `internal/pool/resolver.go`, `credentials/openbao/openbao.go`
- Test: `internal/pg/pg_test.go`, `redaction_test.go`, `tenancytest/suite.go`

**Interfaces:**
- `Scoped` stores `domain.PoolRef`; `Scoped.Pool() domain.PoolRef`.
- `NewScoped(tenant, poolRef, db, appRole)`.
- `Credentials.Issue(ctx, domain.PoolRef)`; `OpenBao.RoleFor func(domain.PoolRef)`.
- `Opener` keeps the full `domain.Pool` because it needs the DSN.
- `Scoped.scope` maps `SET LOCAL ROLE` failures to `ErrPermission`.

- [x] **Step 1: Add failing tests** that `Scoped.Pool()` cannot expose `MetadataDSN` and that a custom issuer receives only a `PoolRef`.
- [x] **Step 2: Implement `PoolRef` plumbing.**
- [x] **Step 3: Update redaction tests and conformance fixtures.**
- [x] **Step 4: Run the affected packages and root tests.**

### Task 7: OpenBao hardening

**Files:**
- Modify: `credentials/openbao/openbao.go`
- Test: `credentials/openbao/openbao_test.go`, `credentials/openbao/openbao_integration_test.go`

**Interfaces:**
- `Open` rejects URL userinfo/query/fragment; `http` is allowed only for loopback.
- Default client and caller-supplied clients reject cross-host/non-HTTPS redirects.
- `CreationStatements` quotes the application role with `pgx.Identifier`.
- `Issue` starts the lease clock before the request (safe, slightly early); `Release` zeroes the decoded response buffer.
- `Credentials` methods use value receivers; `Config` redacts the address in renderings/errors.

- [x] **Step 1: Add failing tests** for HTTP non-loopback, userinfo, cross-host redirect with `X-Vault-Token`, mixed-case role, and lease timing.
- [x] **Step 2: Implement validation, redirect/TLS policy, quoting, value receivers, and buffer zeroing.**
- [x] **Step 3: Run `go test ./credentials/openbao -short -count=1` and the container suite.**

### Task 8: Test harness and conformance gaps

**Files:**
- Modify: `testdb/testdb.go`, `tenancytest/suite.go`, `tenancytest/credentials.go`, `conformance_test.go`
- Add: `credentials/openbao` transport tests, `internal/pool` close-race test, fuzz tests in relevant packages

**Interfaces:**
- `testdb.ControlRole`; `tenancytest.Deployment.ControlRole`.
- `testdb.Start` docs say "fresh, empty; pass WithMigrator"; default remains `NoMigrations`.
- New conformance subtests: resolve→suspend/delete, invalid transitions, RLS negative fixtures, capacity overflow, mixed-case role, config precedence, empty enforcement check.
- Fuzz targets for tenant/pool IDs, OpenBao mount path, qualified identifiers.

- [x] **Step 1: Add the conformance and fuzz tests; confirm they fail against the current code where applicable.**
- [x] **Step 2: Update the harness and suite fixtures for `ControlRole` and `PoolRef`.**
- [x] **Step 3: Replace fixed sleeps with event hooks/bounded event polling where practical.**
- [x] **Step 4: Run `mise run test-all`.**

### Task 9: Facade, examples, and public docs

**Files:**
- Modify: `tenancy.go`, `README.md`, `CHARTER.md`, `CONVENTIONS.md`, `SECURITY.md`, API docs
- Add: `doc.go`, `example_test.go`, `THREAT_MODEL.md`, `CONTRIBUTING.md`, `CHANGELOG.md`, `UPGRADING.md`
- Modify: `docs/superpowers/spikes/2026-10-23-openbao-db-credentials.md` (historical note)

**Interfaces:**
- Public `Config` doc lists every field, required/optional, and the control/data role model.
- Public `Scoped`/`Tenancy`/`Control` docs list methods.
- README has a compile-checked quickstart, role provisioning, install/version guidance, two-policy RLS, testdb default, `%p`/SQLi limits, and a development section.
- Changelog is human-readable and covers v0.1.0–v0.3.0 plus the current unreleased breaking changes.

- [x] **Step 1: Write the docs and examples; run `go test` to compile examples.**
- [x] **Step 2: Replace the `api.txt` golden file with `apidiff` against the last tag (`scripts/api-diff.sh`, `mise run api-diff`).**
- [x] **Step 3: Verify every README command/file/flag exists.**

### Task 10: Tooling, CI, release, supply chain

**Files:**
- Modify: `mise.toml`, `.github/workflows/ci.yml`
- Add: `.github/workflows/release.yml`, `renovate.json`
- Modify: `SECURITY.md`, `CONVENTIONS.md`

**Interfaces:**
- `mise.toml` pins `govulncheck`; `check` includes `fmt-check`, `lint`, `build`, `test-all`, `generate-check`, `vuln`.
- CI uses mise, not inline gofumpt/golangci pins; runs `mise run check`; publishes coverage.
- Release workflow runs the gate on `v*` tags and creates a GitHub release from `CHANGELOG.md`.
- Renovate covers Go modules, GitHub Actions, and Docker images.
- `SECURITY.md` lists supported versions and the security-response expectations.

- [x] **Step 1: Update `mise.toml` tasks and versions.**
- [x] **Step 2: Replace the CI workflow with the mise-driven gate; add coverage and scheduled vuln scan.**
- [x] **Step 3: Add release workflow and Renovate config.**
- [x] **Step 4: Run `mise run check` locally.**

### Task 11: Final API and generated-code reconciliation

**Files:**
- Modify: `scripts/api-diff.sh`, `internal/registry/gen/*` (if sqlc output changes), `tenancy.go`
- Test: all

- [x] **Step 1: Run `mise exec -- sqlc generate` and `git diff --exit-code -- internal/registry/gen db/queries db/migrations`.**
- [x] **Step 2: Run `mise run api-diff`; document every incompatible change in `CHANGELOG.md` and `UPGRADING.md`.**
- [x] **Step 3: Run `mise run check`, `govulncheck ./...`, `go mod tidy -diff`, and the full test suite.**
- [x] **Step 4: Review `git diff` for accidental changes; confirm the authoritative toolchain edits and the review doc remain.**

### Task 12: Changelog and release notes

**Files:**
- Add/modify: `CHANGELOG.md`, `UPGRADING.md`, `README.md`

- [x] **Step 1: Write a human-readable changelog** with `Unreleased`, `v0.3.0`, `v0.2.0`, `v0.1.0`; call out the breaking changes and migration steps.
- [x] **Step 2: Add an upgrade guide** for `PoolRef`, config/lifecycle fields, control role, removed `Readiness`, error taxonomy, and nested `testdb` (if adopted).
- [x] **Step 3: Verify links and version claims against `git tag`/HEAD.**

---

## Notes for the executor

- Work in the current tree; the authoritative uncommitted toolchain edits must not be reverted. Do not create a worktree unless the user asks.
- Make the smallest change that makes each failing test pass; run targeted tests after every task.
- If a task's API decision conflicts with an existing conformance test, update the test only where the review/decisions explicitly changed the contract.
- No commits unless the user asks. The final deliverable is a reviewable working tree, a green gate, and up-to-date docs.

---

## Execution record (2026-10-28)

All tasks were implemented inline in the working tree. No commits were made
because the user did not ask for one; the changes are reviewable with
`git diff` and `git status`.

- Final gate: `mise run check` passes — fmt-check, golangci-lint (0 issues),
  cgo-free build, race/container tests across every module, sqlc diff,
  govulncheck (no vulnerabilities), and `api-diff` (incompatible changes
  reported for the pre-1.0 release).
- Combined coverage across the root and nested integration modules: 79.5% statements.
- New nested modules: `testdb`, `integration`, `internal/pg/integration`, and
  `credentials/openbao/integration`; the root `go.mod` no longer requires
  testcontainers.
- Changelog and upgrade guide are current through the unreleased breaking
  change set.
- `examples/` contains compile-checked quickstart, RLS, OpenBao, role, and
  testing guides, with an index and best-practice notes.

Residual, non-code items from the review:

- An independent external security review (MNT-03) is still an organizational
  action; this change set cannot supply it.
- ARCH-05 is resolved by replacing the `api.txt` AST snapshot with
  `apidiff`/`gorelease`, which compare importable packages and ignore internal
  packages by default.
- Release artifact attestation/SBOM (MNT-08) was not added. Actions and the
  Postgres/OpenBao images are pinned, and Renovate owns updates.
- `testcontainers` still appears in the module graph via `pgmigrate`'s own
  test-only dependency; the root module no longer requires it directly.
