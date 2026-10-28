# RLS: apply, sweep, and verify

`tenancy` uses two PostgreSQL policies:

- `tenant_isolation` is **restrictive** and carries the tenant predicate.
- `tenant_access` is **permissive** and exists so the restrictive policy does
  not deny every row.

Both are created by `tenancy.EnableRLS`. A restrictive policy alone is not a
working table policy.

## Create the table

The table needs a `tenant_id` column. Run this once with your schema owner:

```sql
CREATE SCHEMA IF NOT EXISTS app;

CREATE TABLE app.document (
    id        text PRIMARY KEY,
    tenant_id text NOT NULL,
    title     text NOT NULL
);
```

Do not make the data role the table owner. An owner can disable RLS or drop the
policy even with `FORCE ROW LEVEL SECURITY`; `CheckEnforcement` reports ownership
as a finding.

## Apply and verify

Run the example with a **DDL credential**, not the data-plane credential:

```bash
TENANCY_DDL_DSN='postgres://schema_owner@127.0.0.1/tenant_db?sslmode=disable' \
TENANCY_CONTROL_DSN='postgres://control@127.0.0.1/tenancy?sslmode=disable' \
TENANCY_TENANT_ID='01ARZ3NDEKTSV4RRFFQ69G5FAV' \
TENANCY_TABLE='app.document' \
TENANCY_SCHEMA='app' \
go run ./examples/rls
```

| Variable | Required | Meaning |
|---|---|---|
| `TENANCY_DDL_DSN` | yes | schema owner / migration credential |
| `TENANCY_CONTROL_DSN` | yes | control-plane login |
| `TENANCY_TENANT_ID` | yes | an existing active tenant |
| `TENANCY_TABLE` | no | default `app.document` |
| `TENANCY_SCHEMA` | no | default `app` |
| `TENANCY_APP_ROLE` | no | default `myapp_data` |

`EnableRLS` is idempotent and is meant to run from a migration reconciler on
every `Up`. It repairs a drifted policy by dropping and recreating both policies
in one transaction.

## CI: sweep the whole schema

`AssertRLSCoverage` returns the tables that are missing the policy pair,
enabled/FORCEd RLS, the predicate, or the permissive companion. Registry tables
are the only named exemptions; `RegistryTablesExemptFromRLS()` returns a copy.

```go
uncovered, err := tenancy.AssertRLSCoverage(ctx, ddl, "app")
if err != nil { /* fail */ }
if len(uncovered) != 0 {
    // fail the build with the table names
}
```

## Startup: prove enforcement

`CheckEnforcement` reads the live catalog through a resolved tenant and asks
Postgres whether the role's statements are actually filtered. It requires at
least one table; an empty call is a configuration error, not a pass.

```go
report, err := scoped.CheckEnforcement(ctx, "app.document")
if err != nil { /* fail */ }
if !report.FailClosed() {
    // refuse to serve; report.Findings() names the reason
}
```

RLS is a backstop against application bugs, not a containment boundary for SQL
injection or a role with DDL/ownership rights. Read
[`THREAT_MODEL.md`](../../THREAT_MODEL.md).
