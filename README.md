# tenancy

[![ci](https://github.com/laenenai/tenancy/actions/workflows/ci.yml/badge.svg)](https://github.com/laenenai/tenancy/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/laenenai/tenancy.svg)](https://pkg.go.dev/github.com/laenenai/tenancy)

Who the tenants are, where their data lives, and a pgx connection already
scoped to exactly one of them — failing closed if it is not.

> **Status: implemented, unreleased.** The registry, resolution, both
> connection kinds and the conformance suite are here and green against a
> real Postgres. No tag yet, and no consumer has swapped over: `cas` keeps
> its own copy of the extracted code until the post-alpha swap.

## What it does

The tenant and pool registry and its migrations, tenant→pool resolution with
caching, residency attributes, pgx pool and handle lifecycle, RLS session
context, and tracing.

It handles **two kinds of connection**, and conflating them is a cross-tenant
leak:

- **Control plane.** Resolving tenant → pool happens *before* any tenant scope
  exists, so it necessarily runs unscoped against the registry. This path is
  small, auditable, and must never be reachable with caller-supplied
  predicates.
- **Data plane.** Every other connection is scoped to one resolved tenant with
  RLS session context set, and a missing predicate **denies rather than
  leaking**.

The type system should make it impossible to run a data-plane query on a
control-plane handle.

## Why it is shared code rather than a convention

Not to avoid duplication — because of blast radius. Postgres RLS here is a
fail-closed backstop behind application-level scoping, which makes it a
cross-tenant disclosure control. Three independent implementations of a
cross-tenant disclosure control are three chances to fail silently.

## What it does not do

Authorization rules, key material, migrations beyond its own registry tables,
query building, or any consuming system's domain concepts.

## Using it

```go
// Once, at startup, on the migration credential. The handle never escapes.
if err := tenancy.Migrate(ctx, tenancy.MigrateConfig{
    DSN:     migrationDSN,
    AppRole: "myapp",
}); err != nil {
    return err
}

// For the life of the process, on the runtime credential.
ten, err := tenancy.Open(ctx, tenancy.Config{
    RegistryDSN: runtimeDSN,
    AppRole:     "myapp",
    Cache:       tenancy.CacheOptions{TTL: time.Minute, NegativeTTL: 10 * time.Second},
})
if err != nil {
    return err
}
defer ten.Close()

// Control plane: the registry. No method here takes SQL.
pool, err := ten.Control().CreatePool(ctx, tenancy.NewPool{
    Name: "eu-main", Region: "eu-west-1", MetadataDSN: poolDSN,
})

// Data plane: one resolved tenant, with its session context already set.
scoped, err := ten.Scope(ctx, tenantID)
if err != nil {
    return err // ErrNotAuthorizedOrNotFound, or ErrUnavailable if suspended
}
err = scoped.Tx(ctx, func(ctx context.Context, tx tenancy.TenantTx) error {
    // tx satisfies sqlc's generated DBTX, so a consumer's own generated
    // queries run tenant-scoped with no wrapper:
    //     myqueries := gen.New(tx)
    _, err := tx.Exec(ctx,
        "INSERT INTO app.document (id, tenant_id, title) VALUES ($1, $2, $3)",
        docID, tx.Tenant(), title)
    return err
})
```

A consumer's own tenant-scoped tables get the backstop by calling
`tenancy.EnableRLS` from its own migration reconciler, and prove they have it
by wiring `tenancy.AssertRLSCoverage` into a test. `Scoped.CheckEnforcement`
reports whether Postgres will actually refuse a cross-tenant statement on
this deployment's connection — call it at startup and refuse to serve if
`FailClosed` is false, because a superuser connection makes every policy
inert while looking entirely correct from Go.

## The test harness

`tenancy/testdb` is the shared container harness the other modules import
(`CONVENTIONS.md` makes this module its home). `testdb.Start(t)` gives a test
its own uniquely named, migrated database, skips under `-short`, and uses
`TEST_DATABASE_URL` instead of a container when that is set. It is public
surface and listed in `api.txt`.

## Documentation

- [`CHARTER.md`](CHARTER.md) — the boundary, and two recorded decisions open to reversal
- [`SECURITY.md`](SECURITY.md)
- `api.txt` — the public surface as a golden file, diffed in CI

## License

Apache-2.0. See [`LICENSE`](LICENSE).
