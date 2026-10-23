# tenancy

[![ci](https://github.com/laenenai/tenancy/actions/workflows/ci.yml/badge.svg)](https://github.com/laenenai/tenancy/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/laenenai/tenancy.svg)](https://pkg.go.dev/github.com/laenenai/tenancy)

Who the tenants are, where their data lives, and a pgx connection already
scoped to exactly one of them — failing closed if it is not.

> **Status: implemented, unreleased.** The registry, resolution, both
> connection kinds, the credentials port with both its adapters, and the two
> conformance suites are here and green against a real Postgres and a real
> OpenBao. No tag yet, and no consumer has swapped over: `cas` keeps its own
> copy of the extracted code until the post-alpha swap.

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

A connection string is a credential, so `tenancy.DSN` is its own type rather
than a `string`: it redacts itself through every rendering Go offers — `%v`,
`%+v`, `%#v`, every other `fmt` verb, `json.Marshal`, and `slog` under both
standard handlers — and reading the actual string requires writing
`string(dsn)`, which is a deliberate act at a boundary rather than the
accidental default. `Pool`, `Config`, `MigrateConfig`, `NewPool` and `Scoped`
carry the same four methods, because a redacting field type protects a
struct's *exported* fields and nothing reached through an unexported one.

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
    DSN:     tenancy.DSN(migrationDSN),
    AppRole: "myapp",
}); err != nil {
    return err
}

// For the life of the process, on the runtime credential.
ten, err := tenancy.Open(ctx, tenancy.Config{
    RegistryDSN: tenancy.DSN(runtimeDSN),
    AppRole:     "myapp",
    Cache:       tenancy.CacheOptions{TTL: time.Minute, NegativeTTL: 10 * time.Second},
})
if err != nil {
    return err
}
defer ten.Close()

// Control plane: the registry. No method here takes SQL.
pool, err := ten.Control().CreatePool(ctx, tenancy.NewPool{
    Name: "eu-main", Region: "eu-west-1", MetadataDSN: tenancy.DSN(poolDSN),
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

## Dynamic database credentials, if you want them

By default a pool connects on the credential its registry row's
`MetadataDSN` already carries: a long-lived password, shared by every process
that resolves that pool, whose rotation is a fleet-wide event nothing
announces. `tenancy.StaticDSNCredentials` is that default, it performs no
I/O, and a deployment that wants nothing to change sets nothing.

The alternative is opt-in and never required: `credentials/openbao` issues a
credential per pool from OpenBao's database secrets engine, with a lease.

```go
source, err := openbao.Open(ctx, openbao.Config{
    Address: "https://openbao.internal:8200",
    Token:   baoToken,
    Role:    "myapp-runtime", // or RoleFor, per pool
})
if err != nil {
    return err
}

// Worth doing at startup: it reads the role's configuration back and
// reports every way it departs from what this module requires.
if check, err := source.CheckRole(ctx, "myapp-runtime"); err != nil {
    return err
} else if !check.Usable() {
    return fmt.Errorf("openbao role is misconfigured: %v", check.Findings())
}

ten, err := tenancy.Open(ctx, tenancy.Config{
    RegistryDSN: tenancy.DSN(runtimeDSN),
    Credentials: source,
    Cache: tenancy.CacheOptions{
        TTL:         time.Minute,
        NegativeTTL: 10 * time.Second,
        // Required with Credentials, and it is a fact about your slowest
        // query rather than a security preference. See below.
        LongestTransaction: 2 * time.Minute,
    },
})
```

Configure the OpenBao role's `creation_statements` from
`openbao.CreationStatements("myapp")` rather than from a copy of some SQL.
Every clause in it is load-bearing, and three of them are load-bearing in
ways that do not show up until something has already gone wrong.

**What changes, and what it costs.** A credential that expires cannot be
swapped underneath a live `*pgxpool.Pool`: expiry is a privilege removal
rather than a disconnection, so nothing closes, the pool reports itself
healthy, and a transaction that was already running fails mid-statement and
then has its `COMMIT` silently turned into a `ROLLBACK`. So each pool is
*retired* one `LongestTransaction` before its credential expires: it stops
being handed to new callers, the transactions already on it drain, it closes,
and a replacement is built on a fresh credential. That lead time is a drain
window, which is why it is required rather than defaulted, and why a
credential with less than twice that left to live is refused with both
numbers named.

It applies to tenant pools only. The control plane's own pool and the
migration pool keep their static DSNs — neither is reference counted, so
there is no moment at which replacing one is known to be safe.

The measurements behind all of this, including why OpenBao's *static* roles
are refused rather than supported, are in
[`credentials/openbao`](credentials/openbao/openbao.go)'s package doc and in
[the spike](docs/superpowers/spikes/2026-10-23-openbao-db-credentials.md).

## The test harness

`tenancy/testdb` is the shared container harness the other modules import
(`CONVENTIONS.md` makes this module its home). `testdb.Start(t)` gives a test
its own uniquely named, migrated database, skips under `-short`, and uses
`TEST_DATABASE_URL` instead of a container when that is set. It is public
surface and listed in `api.txt`.

## Documentation

- [`CHARTER.md`](CHARTER.md) — the boundary, and the recorded decisions open to reversal
- [`docs/superpowers/spikes/`](docs/superpowers/spikes/) — what was measured rather than assumed
- [`SECURITY.md`](SECURITY.md)
- `api.txt` — the public surface as a golden file, diffed in CI

## License

Apache-2.0. See [`LICENSE`](LICENSE).
