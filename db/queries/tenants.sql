-- Tenant queries: the control plane's whole interest in tenancy.tenants.
--
-- Read these as SQL rather than as Go, which is the reason they live here
-- and not in a string literal inside a method. Three things are visible at
-- a glance and would not be otherwise:
--
--   * TenantByID is a bare primary-key lookup with no tenant predicate,
--     because there cannot be one — this is the query that *establishes*
--     the tenant context everything downstream is filtered by. It is the
--     control-plane read the charter calls out as necessarily unscoped,
--     and it is why internal/registry.Control exposes no method that takes
--     caller SQL: there is no row security behind this table to catch a
--     mistake.
--
--   * SetTenantStatus never touches security_mode, so the immutability
--     trigger in 00001_registry.sql has nothing to catch on this path.
--     That the one UPDATE in the module cannot reach that column is
--     checkable here, in four lines, rather than by reading a method.
--
--   * There is no DeleteTenant. A tenant is retired by moving its status
--     to 'deleting', which resolution reports indistinguishably from a
--     tenant that never existed. A removable row would make a tenant's
--     pool assignment forgettable.

-- name: CreateTenant :one
INSERT INTO tenancy.tenants (id, pool_id, name, security_mode, status)
VALUES ($1, $2, $3, $4, $5)
RETURNING id, pool_id, name, security_mode, status, created_at, updated_at;

-- name: TenantByID :one
SELECT id, pool_id, name, security_mode, status, created_at, updated_at
FROM tenancy.tenants
WHERE id = $1;

-- name: TenantByName :one
SELECT id, pool_id, name, security_mode, status, created_at, updated_at
FROM tenancy.tenants
WHERE name = $1;

-- name: SetTenantStatus :one
UPDATE tenancy.tenants
SET status = $2, updated_at = now()
WHERE id = $1
RETURNING id, pool_id, name, security_mode, status, created_at, updated_at;
