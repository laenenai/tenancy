# Quickstart

The smallest complete wiring: migrate, open the control plane, ensure a pool
and tenant, resolve, and run a statement with `app.tenant_id` set.

## Prerequisites

- A Postgres server with three usable identities:
  - **migration**: can run migrations and reconcile roles/grants.
  - **control**: a `LOGIN` role with `INHERIT` membership in `ControlRole`.
  - **data**: a `LOGIN` role that is a member of `AppRole`. It has no registry
    privileges and should own no tables.
- A tenant database reachable by the data login. This example does not create
  application tables.

Run `Migrate` once per deployment, then run this example:

```bash
go run ./examples/quickstart
```

Environment:

| Variable | Required | Meaning |
|---|---|---|
| `TENANCY_MIGRATION_DSN` | yes | migration credential |
| `TENANCY_CONTROL_DSN` | yes | control-plane login |
| `TENANCY_POOL_DSN` | yes | tenant database DSN stored on the pool row |
| `TENANCY_APP_ROLE` | no | data grantee, default `myapp_data` |
| `TENANCY_CONTROL_ROLE` | no | registry grantee, default `myapp_control` |

## What to copy, and what not to

Copy the shape:

- `MigrateConfig{DSN, AppRole, ControlRole}`
- one `Config.RegistryDSN` for the control login
- `Config.AppRole` for the data grantee
- `Scoped.Tx` for every tenant-scoped statement
- `defer ten.Close()`

Do not copy the placeholder names, the `PoolByName`/`TenantByName`
reuse-or-create flow, or the 30-second timeout as production policy. Choose
names, idempotency, and timeouts for your deployment.

`ten.Scope` returns `ErrNotAuthorizedOrNotFound` for unknown/deleting tenants
and `ErrUnavailable` for suspended or unreachable ones. Do not add an existence
oracle to a request handler.
