# tenancy

[![ci](https://github.com/laenenai/tenancy/actions/workflows/ci.yml/badge.svg)](https://github.com/laenenai/tenancy/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/laenenai/tenancy.svg)](https://pkg.go.dev/github.com/laenenai/tenancy)

Who the tenants are, where their data lives, and a pgx connection already
scoped to exactly one of them — failing closed if it is not.

> **Status: pre-1.0.** Release `v0.4.0` is the production-readiness change set;
> `main` may be newer. Minor versions may break the API, and the
> [`CHANGELOG`](CHANGELOG.md) plus [`UPGRADING`](UPGRADING.md) say what
> changed. The API is not frozen until 1.0.

## What it does

The tenant and pool registry and its migrations, tenant→pool resolution with
caching, residency attributes, pgx pool and handle lifecycle, RLS session
context, and tracing.

It handles **two kinds of connection**, and conflating them is a cross-tenant
leak:

- **Control plane.** Resolving tenant → pool happens *before* any tenant scope
  exists, so it necessarily runs unscoped against the registry. This path is
  small, auditable, and must never be reachable with caller-supplied
  predicates. Its login role is a member of the registry's **control role**.
- **Data plane.** Every other connection is scoped to one resolved tenant with
  RLS session context set, and a missing predicate **denies rather than
  leaking**. Its login role is a member of the **data role** (`AppRole`), which
  has no registry privileges.

The two roles are deliberately different. `tenancy.Migrate` creates both as
`NOLOGIN` grantees; your deployment creates the `LOGIN` identities and makes
each a member of the appropriate grantee. A runtime control login with
`INHERIT` membership in `ControlRole` can read the registry; the data role
cannot.

A connection string is a credential, so `tenancy.DSN` is its own type rather
than a `string`: it redacts itself through the four interfaces Go's common
renderers consult — `fmt.Stringer`/`fmt.Formatter` (`%v`, `%+v`, `%#v` and every
other verb), `json.Marshaler`, `slog.LogValuer`, and `encoding.TextMarshaler`
for YAML/XML — and reading the actual string requires writing `string(dsn)`,
which is a deliberate act at a boundary rather than the accidental default.
`%p` and bad-verb mismatches bypass those interfaces; the material stays
unexported so reflection does not reach it. `Pool`, `PoolRef`, `Config`,
`MigrateConfig`, `PoolSpec`, `Scoped` and `Credential` carry the same
redaction methods.

## Why it is shared code rather than a convention

Not to avoid duplication — because of blast radius. Postgres RLS here is a
fail-closed backstop behind application-level scoping, which makes it a
cross-tenant disclosure control. Three independent implementations of a
cross-tenant disclosure control are three chances to fail silently.

**RLS threat model.** Application-level scoping is primary; RLS is a backstop
against a forgotten predicate or a bug in application code. It is **not**
containment for SQL injection or for a role that can run DDL: a caller that can
execute arbitrary SQL can reset `app.tenant_id`, and a table owner can disable
RLS or drop the policy. Deploy the data role as a non-owner, no-DDL role, and
do not treat RLS as a substitute for parameterized SQL. See
[`THREAT_MODEL.md`](THREAT_MODEL.md).

## What it does not do

Authorization rules, key material, migrations beyond its own registry tables,
query building, or any consuming system's domain concepts.

## Install and first use

```bash
go get github.com/laenenai/tenancy@latest
```

The quickstart is complete enough to compile and run:

```go
package main

import (
    "context"
    "time"

    "github.com/laenenai/tenancy"
)

func wire(ctx context.Context, migrationDSN, runtimeDSN string) error {
    // Once, on the migration credential. The migration pool never escapes.
    // AppRole is the data-plane grantee; ControlRole is the registry grantee.
    if err := tenancy.Migrate(ctx, tenancy.MigrateConfig{
        DSN:         tenancy.DSN(migrationDSN),
        AppRole:     "myapp_data",
        ControlRole: "myapp_control",
    }); err != nil {
        return err
    }

    // Everything below runs as a LOGIN role that is a member of ControlRole
    // (INHERIT). The data role is never this DSN.
    ten, err := tenancy.Open(ctx, tenancy.Config{
        RegistryDSN: tenancy.DSN(runtimeDSN),
        AppRole:     "myapp_data",
        Cache:       tenancy.CacheOptions{TTL: time.Minute, NegativeTTL: 10 * time.Second},
    })
    if err != nil {
        return err
    }
    defer ten.Close()

    // Control plane: the registry. No method here takes SQL.
    pool, err := ten.Control().CreatePool(ctx, tenancy.PoolSpec{
        Name: "eu-main", Region: "eu-west-1",
        MetadataDSN: tenancy.DSN("postgres://myapp_data:...@pool-a/db"),
        BlobConfigRef: "blob-eu-main", WorkerCapacity: 8,
    })
    if err != nil {
        return err
    }
    tenant, err := ten.Control().CreateTenant(ctx, tenancy.TenantSpec{
        PoolID: pool.ID, Name: "acme", SecurityMode: tenancy.SecurityModeManaged,
    })
    if err != nil {
        return err
    }

    // Data plane: one resolved tenant. Pool() is a PoolRef and cannot leak
    // MetadataDSN.
    scoped, err := ten.Scope(ctx, tenant.ID)
    if err != nil {
        return err // ErrNotAuthorizedOrNotFound, or ErrUnavailable if suspended
    }
    return scoped.Tx(ctx, func(ctx context.Context, tx tenancy.TenantTx) error {
        // tx satisfies sqlc's DBTX, so generated queries run tenant-scoped:
        //     q := gen.New(tx)
        _, err := tx.Exec(ctx,
            "INSERT INTO app.document (id, tenant_id, title) VALUES ($1, $2, $3)",
            "doc-1", tx.Tenant(), "Hello")
        return err
    })
}
```

`ten.Control().SetTenantStatus` invalidates the positive cache for that tenant,
so suspending or deleting an active tenant is visible on the next `Scope`
without waiting for `TTL`. `deleting` is terminal; the schema trigger rejects a
return to `active` or `suspended`.

## RLS: two policies, not one

A restrictive policy alone is not a working tenant policy: it also filters the
registry and any other non-tenant row. `EnableRLS` creates a restrictive
`tenant_isolation` policy **and** a permissive `tenant_access` companion. Both
carry the same `USING`/`WITH CHECK` predicate. A consumer that writes its own
policy must reproduce both.

Call `AssertRLSCoverage` in CI, and `CheckEnforcement` at startup. Coverage
requires enabled and FORCEd RLS, a restrictive tenant policy with a matching
predicate and `WITH CHECK`, and a permissive companion. Ownership is reported
even when FORCE is set, because an owner can still disable RLS or drop the
policy. `CheckEnforcement` now requires at least one table; an empty list is a
configuration error, not a pass.

```go
scoped, err := ten.Scope(ctx, tenantID)
if err != nil {
    return err
}
check, err := scoped.CheckEnforcement(ctx, "app.document")
if err != nil {
    return err
}
if !check.FailClosed() {
    log.Fatalf("tenant enforcement is not real: %v", check.Findings())
}
```

The registry's own tables are the named exception:
`tenancy.RegistryTablesExemptFromRLS()` returns a copy of the exemption map, so
mutating the returned map cannot weaken the sweep.

## Dynamic database credentials, if you want them

By default a pool connects on the credential its registry row's
`MetadataDSN` already carries. `tenancy.StaticDSNCredentials` is that default;
it performs no I/O, and a deployment that wants nothing to change sets nothing.

The alternative is opt-in: `credentials/openbao` issues a credential per pool
from OpenBao's database secrets engine, with a lease.

```go
source, err := openbao.Open(ctx, openbao.Config{
    Address: "https://openbao.internal:8200",
    Token:   baoToken,
    Role:    "myapp-runtime", // or RoleFor, per pool
})
if err != nil {
    return err
}

if check, err := source.CheckRole(ctx, "myapp-runtime"); err != nil {
    return err
} else if !check.Usable() {
    return fmt.Errorf("openbao role is misconfigured: %v", check.Findings())
}

ten, err := tenancy.Open(ctx, tenancy.Config{
    RegistryDSN: tenancy.DSN(runtimeDSN),
    AppRole:     "myapp_data",
    Credentials: source,
    LongestTransaction: 2 * time.Minute, // required with Credentials
    Cache: tenancy.CacheOptions{TTL: time.Minute, NegativeTTL: 10 * time.Second},
})
```

`Open` accepts HTTPS, or plain HTTP only on loopback. URL userinfo, query and
fragment are rejected, and a cross-host or downgrade redirect is not followed,
so the vault token cannot be forwarded to another host. Configure the OpenBao
role's `creation_statements` from `openbao.CreationStatements("myapp_data")`;
mixed-case roles are quoted.

**What changes, and what it costs.** A credential that expires cannot be
swapped underneath a live `*pgxpool.Pool`. Each pool is *retired* one
`LongestTransaction` before its credential expires: it stops being handed to
new callers, the transactions already on it drain, it closes, and a replacement
is built on a fresh credential. A credential with less than twice that left to
live is refused with both numbers named. Release is best-effort and uses a
detached timeout; failed releases are counted and can be observed through
`OnCredentialReleaseError` or `ten.Stats()`.

It applies to tenant pools only. The control-plane pool and the migration pool
keep their static DSNs.

## The test harness

`tenancy/testdb` is the shared container harness the other modules import. It
is a nested module, so the root module does not carry testcontainers; until a
`testdb/vX.Y.Z` tag is published, consume it with a `replace` to the checkout.
`testdb.Start(t)` gives a test its own uniquely named, **empty** database and
skips under `-short`. It does **not** run `tenancy`'s migrations by default; a
consumer that wants them passes `testdb.WithMigrator(...)`. `TEST_DATABASE_URL`
replaces the container.

```go
db := testdb.Start(t, testdb.WithMigrator(func(ctx context.Context, dsn tenancy.DSN) error {
    return tenancy.Migrate(ctx, tenancy.MigrateConfig{
        DSN: dsn, AppRole: "test_data", ControlRole: "test_control",
    })
}))
```

## Development

`mise` is the single source of truth for tool versions and tasks:

```bash
mise install
mise run fmt
mise run test          # no containers
mise run test-all      # race + containers
mise run check         # fmt, lint, build, test-all, sqlc diff, govulncheck, api-diff
```

## Examples

[`examples/`](examples/) contains compile-checked adoption paths:

- [`quickstart`](examples/quickstart/) — migrate, open, resolve, run one scoped statement
- [`rls`](examples/rls/) — apply and verify the two-policy RLS backstop
- [`openbao`](examples/openbao/) — dynamic credentials and lease retirement
- [`roles`](examples/roles/) — control/data role split and least privilege
- [`testing`](examples/testing/) — the shared harness and conformance suites

## Documentation

- [`CHARTER.md`](CHARTER.md) — the boundary and recorded decisions
- [`CONVENTIONS.md`](CONVENTIONS.md) — the shared Go conventions
- [`THREAT_MODEL.md`](THREAT_MODEL.md) — what RLS and the role split do and do not protect
- [`SECURITY.md`](SECURITY.md) — reporting and supported versions
- [`CHANGELOG.md`](CHANGELOG.md), [`UPGRADING.md`](UPGRADING.md) — release history and breaking changes
- [`docs/superpowers/spikes/`](docs/superpowers/spikes/) — measured findings
- `mise run api-diff` — the importable API diff against the last tag

## License

Apache-2.0. See [`LICENSE`](LICENSE).
