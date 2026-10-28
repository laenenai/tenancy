# Upgrading

`tenancy` is pre-1.0: a minor release may break the API. This file records the
steps for the breaking changes in the unreleased production-readiness change
set.

## From v0.3.x to the unreleased API

### 1. Split the control role from the data role

Create two `NOLOGIN` grantees and two `LOGIN` identities:

```sql
-- Migrate creates these grantees; shown here so the deployment is explicit.
CREATE ROLE myapp_data NOLOGIN;
CREATE ROLE myapp_control NOLOGIN;

-- The runtime control login inherits the registry grantee's privileges.
CREATE ROLE myapp_control_login LOGIN PASSWORD '...';
GRANT myapp_control TO myapp_control_login;

-- The runtime data login is the role every tenant transaction narrows into.
CREATE ROLE myapp_data_login LOGIN PASSWORD '...';
GRANT myapp_data TO myapp_data_login;
```

Run migrations with `ControlRole: "myapp_control"` and
`AppRole: "myapp_data"`. Configure `Config.RegistryDSN` with the control login,
not the data login. The data role intentionally has no registry privileges.

### 2. Move lifecycle configuration out of `Cache`

```go
// Before
Cache: tenancy.CacheOptions{
    TTL: time.Minute,
    Credentials: source,
    LongestTransaction: 2 * time.Minute,
}

// After
Credentials: source,
LongestTransaction: 2 * time.Minute,
Cache: tenancy.CacheOptions{TTL: time.Minute},
```

`LongestTransaction` is still required whenever `Credentials` is set.

### 3. Replace pool-row access on the data plane

`Scoped.Pool()` now returns `tenancy.PoolRef`. Code that read
`scoped.Pool().MetadataDSN` must move to the control plane; the data plane is
not allowed to open an unscoped connection. A custom `Credentials`
implementation must implement `Issue(ctx, tenancy.PoolRef)` and
`Release(ctx, tenancy.Credential)`.

### 4. Rename input structs

Replace `tenancy.NewPool` with `tenancy.PoolSpec` and `tenancy.NewTenant` with
`tenancy.TenantSpec`. Constructors for IDs remain `NewPoolID`/`NewTenantID`.

### 5. Remove `Readiness`

`tenancy.Readiness` and the four constants are gone. Move the concept to the
consumer that owns the processing lifecycle.

### 6. Split the RLS predicate

Replace `tenancy.IsRLSViolation(err)` with:

- `tenancy.IsRLSPolicyViolation(err)` when the test must prove the policy
  refused the statement;
- `tenancy.IsInsufficientPrivilege(err)` when any 42501 is acceptable.

`CheckEnforcement(ctx)` with no tables now returns `ErrInvalidConfig`; pass at
least one table.

### 7. Expect status errors

`SetTenantStatus` rejects invalid transitions with `ErrConflict`, and
`deleting` is terminal. A caller that previously resurrected a deleting tenant
must create a new tenant instead.

### 8. Update OpenBao configuration

Plain HTTP is accepted only on loopback. Remove URL userinfo, query strings and
fragments from `Address`; use the `Token` field. If you supplied a custom
`HTTPClient`, its redirect policy is wrapped to reject cross-host and
non-HTTPS redirects.

### 9. Update the test harness wiring

`testdb.Start(t)` returns an empty database by default; that was already the
real default, but the docs previously said otherwise. Pass
`testdb.WithMigrator(...)` when a test needs a schema. `Deployment` now requires
`ControlRole`.

The harness is no longer a package in the root module. Add the nested module to
your test module:

```go
require github.com/laenenai/tenancy/testdb v0.1.0
```

Until `testdb/v0.1.0` is tagged, use a `replace` to the checkout. The import
path `github.com/laenenai/tenancy/testdb` is unchanged, but `apidiff` reports
the root package as removed, which is the breaking change this release carries.

### 10. Regenerate generated code and check the API

```bash
mise run generate
mise run api-diff   # apidiff against the last root tag
mise run check
```

`api-diff` reports incompatible changes; pre-1.0 they are allowed, but they
must be documented here and in `CHANGELOG.md`. `gorelease` is the clean-release
check and runs in the release workflow.

## Release policy

- `v0.x.0` may break; `v0.x.y` is a fix.
- Every breaking change gets a changelog entry and an upgrade section.
- `main` is tagged only after `mise run check` passes.
- 1.0 is cut after the P0/P1 items in the review are closed.
