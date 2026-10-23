# tenancy

[![ci](https://github.com/laenenai/tenancy/actions/workflows/ci.yml/badge.svg)](https://github.com/laenenai/tenancy/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/laenenai/tenancy.svg)](https://pkg.go.dev/github.com/laenenai/tenancy)

Who the tenants are, where their data lives, and a pgx connection already
scoped to exactly one of them — failing closed if it is not.

> **Status: design only.** This repository currently contains the charter and
> the boundary. There is no implementation yet, and no release.

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

## Documentation

- [`CHARTER.md`](CHARTER.md) — the boundary, and two recorded decisions open to reversal
- [`SECURITY.md`](SECURITY.md)
- `api.txt` — the public surface as a golden file, diffed in CI

## License

Apache-2.0. See [`LICENSE`](LICENSE).
