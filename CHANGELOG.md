# Changelog

All notable changes to `tenancy` are recorded here. The format is
human-readable; versions follow SemVer with the pre-1.0 rule that a minor
release may break the API. See `UPGRADING.md` for the steps.

## Unreleased

## v0.4.0 — 2026-10-28

This is the production-readiness change set from
[`docs/review/20261028_review.md`](docs/review/20261028_review.md).

### Breaking changes

- **Control and data roles are separate.** `MigrateConfig` now requires
  `ControlRole` as well as `AppRole`. Registry grants go to `ControlRole`; the
  data-plane `AppRole` receives none. `Status` no longer requires `AppRole`.
- **`Config` lifecycle fields moved out of `CacheOptions`.** `Credentials`,
  `LongestTransaction`, `Clock` and the new `OnCredentialReleaseError` live on
  `Config`/`pool.LifecycleOptions`. `Cache` now contains only TTL and size
  settings.
- **`api.txt` and `TestAPIGolden` are removed.** API compatibility is now
  checked with `apidiff` against the previous tag (`mise run api-diff`) and
  `gorelease` on a clean release. Internal packages are no longer part of the
  compatibility snapshot.
- **`testdb` moved out of the root module into
  `github.com/laenenai/tenancy/testdb`.** Importers need the nested module (or a
  `replace` until `testdb/vX.Y.Z` is tagged). `apidiff` reports this as a root
  API removal; it is intentional and requires the separate harness release.
- **`PoolRef` replaces the full pool row on the data plane.**
  `Scoped.Pool()` returns `PoolRef` with no `MetadataDSN`, and
  `Credentials.Issue`/`OpenBao.RoleFor` receive `PoolRef`.
- **`NewPool`/`NewTenant` renamed to `PoolSpec`/`TenantSpec`.** The old names
  looked like constructors but were input structs.
- **`Readiness` removed.** It was unused, was not in the charter, and a
  consumer that needs a processing lifecycle should own it.
- **`IsRLSViolation` split into `IsInsufficientPrivilege` and
  `IsRLSPolicyViolation`.** SQLSTATE 42501 covers both a missing grant and an
  RLS refusal; the old predicate conflated them.
- **`ErrPermission` added.** Permanent privilege and role failures no longer
  masquerade as retryable `ErrUnavailable`. `CheckEnforcement` with no tables
  returns `ErrInvalidConfig`.
- **Tenant status transitions are enforced.** `active ↔ suspended`,
  `active/suspended → deleting`, and `deleting` is terminal. The database
  trigger is the backstop.

### Security and correctness

- Positive cache entries are invalidated by `SetTenantStatus`, so suspension
  and deletion take effect on the next `Scope` rather than after TTL.
- `AssertRLSCoverage` and `CheckEnforcement` now inspect the policy predicate,
  `WITH CHECK`, the permissive companion, and ownership. Owner+FORCE is a
  finding: an owner can disable RLS or drop the policy.
- `EnableRLS` documentation now states that it creates two policies, not one.
- `Scoped` maps a failed `SET LOCAL ROLE` to `ErrPermission`; `EnableRLS`
  distinguishes missing schema objects from privilege failures.
- `Close` waits for background closes and releases; release errors are counted
  in `Stats` and can be reported via `OnCredentialReleaseError`.
- Credentials are released with a detached timeout on pool-open error paths.
- `WorkerCapacity` above `int32` is rejected, and the migration adds a
  non-negative check.
- OpenBao requires HTTPS except on loopback, rejects URL userinfo/query/
  fragment, refuses cross-host/downgrade redirects, quotes mixed-case roles,
  starts lease timing before the request, and zeroes the decoded response
  buffer.
- `Config`/`MigrateConfig`/`OpenBao.Config` renderings are safe for custom
  credential sources and addresses with userinfo.
- `Credential` implements `encoding.TextMarshaler`; `openbao.Credentials`
  methods use value receivers so a copied value still redacts.
- `RegistryTablesExemptFromRLS` is a function returning a copy, not a mutable
  exported map.

### Tooling and docs

- `testdb`, the conformance runner, and the OpenBao/Postgres integration tests
  now live in nested modules. The root `go.mod` no longer requires
  testcontainers; `mise run test`/`test-all` run every module.
- `mise.toml` is the single source of tool versions; CI runs `mise run check`
  (fmt, lint, build, race/container tests, sqlc diff, govulncheck, apidiff).
  The release workflow runs `gorelease` on the clean tag.
- Added `govulncheck`, a release workflow, Renovate configuration, coverage
  output, `THREAT_MODEL.md`, `CONTRIBUTING.md`, `UPGRADING.md`, and this
  changelog.
- Added `examples/` with compile-checked quickstart, RLS, OpenBao, role, and
  testing guides. GitHub Actions, the Postgres image and the OpenBao image are
  pinned by commit/digest; Renovate owns the updates.
- README quickstart and package docs are updated for the two-role model,
  `PoolRef`, two-policy RLS, test harness defaults, and the pre-1.0 status.

## v0.3.0 — 2026-10-24

- Added the opt-in OpenBao database-credentials adapter, including lease
  retirement and the conformance suite for dynamic credentials.
- Fixed the redaction test's password-length needle so it depends on the
  secret rather than the clock.

## v0.2.0 — 2026-10-23

- Fixed `Scoped` rendering its pool's `MetadataDSN`; `Scoped` now implements
  all four redaction methods.
- Documented that redaction belongs on the type, not on a logger.

## v0.1.0 — 2026-10-23

- Initial publication standard: registry, migrations, tenant→pool resolution,
  scoped connections, RLS session context, conformance suite, and test harness.
