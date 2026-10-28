# Roles and least privilege

`tenancy` deliberately uses two registry roles:

| Grantee | Created by | Privileges | Used by |
|---|---|---|---|
| `myapp_control` (`ControlRole`) | `tenancy.Migrate` | `SELECT`, `INSERT`, `UPDATE` on `tenancy.pools` and `tenancy.tenants`; `USAGE` on the schema | control-plane login |
| `myapp_data` (`AppRole`) | `tenancy.Migrate` | none on the registry; narrowed into by every tenant transaction | data-plane pool credential |

Do not give the data role `SELECT`, `INSERT`, `UPDATE`, `DELETE`, `TRUNCATE`,
`REFERENCES`, or `TRIGGER` on the registry. `Migrate` revokes the old grant set
from `AppRole` on every run, so an upgrade from the pre-split layout is repaired
rather than left silent.

## Provision the LOGIN identities

`Migrate` creates the grantees as `NOLOGIN`. The deployment creates the login
roles and makes each a member of its grantee:

```sql
-- Grantees may already exist; Migrate creates them idempotently.
CREATE ROLE myapp_control NOLOGIN;
CREATE ROLE myapp_data NOLOGIN;

-- The control plane authenticates here and inherits the registry grants.
CREATE ROLE myapp_control_login LOGIN PASSWORD 'replace-me';
GRANT myapp_control TO myapp_control_login;

-- The data plane authenticates here. It has no registry access.
CREATE ROLE myapp_data_login LOGIN PASSWORD 'replace-me';
GRANT myapp_data TO myapp_data_login;

-- Never make the data role the owner of tenant tables.
-- Use a separate schema owner for DDL.
```

Use `myapp_control_login` for `TENANCY_CONTROL_DSN`. Use a data login, or an
OpenBao-issued member of `myapp_data`, for the pool DSN.

## Verify the split

```sql
-- must be true
SELECT has_table_privilege('myapp_data_login', 'tenancy.tenants', 'SELECT'); -- false
SELECT has_table_privilege('myapp_control_login', 'tenancy.tenants', 'SELECT'); -- true
```

`has_table_privilege` resolves inherited privileges, which is the point: the
control login inherits from `myapp_control`; the data login inherits nothing from
the registry.

## Ownership

A table owner can disable RLS or drop its policy even when
`FORCE ROW LEVEL SECURITY` is set. Never make `myapp_data` or its login the owner
of a tenant table. `CheckEnforcement` reports ownership as a finding, and
`AssertRLSCoverage` requires the policy pair, not just ownership.

## Rotation and configuration

- `metadata_dsn` and `pool_id` are immutable through an ordinary `UPDATE`; a
  repoint is a deliberate migration, not an operator edit.
- Rotate a static pool credential by creating a new pool, moving traffic through
  the control plane, and retiring the old pool; do not `UPDATE` the DSN.
- For dynamic credentials, use OpenBao and `LongestTransaction`; see
  [`../openbao`](../openbao/).
