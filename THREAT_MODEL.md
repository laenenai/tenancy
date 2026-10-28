# Threat model

This document states what `tenancy` protects and what it explicitly does not.
It is narrower than a general security policy; the module is a tenant registry
and a scoped connection, not an authorization system.

## Protected assets

1. **Tenant existence and status.** The resolver must not reveal whether an
   unknown tenant exists versus whether it is being deleted. It returns
   `ErrNotAuthorizedOrNotFound` for both.
2. **Tenant data isolation.** Application-level scoping is the primary control;
   PostgreSQL RLS is a backstop against a forgotten predicate or an application
   bug.
3. **Pool connection material.** `MetadataDSN` is a credential. It is held by
   the control plane and the pool opener, never by a data-plane handle. A
   `Scoped.Pool()` returns a `PoolRef` with no DSN, and every credential source
   receives only a `PoolRef`.
4. **Registry integrity.** The data-plane role has no registry privileges.
   Changing a tenant's `pool_id` or a pool's `metadata_dsn` requires the
   control role, not a tenant query.

## Trust boundaries

- **Control plane / data plane.** Separate roles and DSNs. The control login is
  a member of `ControlRole` (registry `SELECT/INSERT/UPDATE`); the data login is
  a member of `AppRole` and has no registry grants. The migration credential is
  a third, higher-privilege identity and is never the runtime identity.
- **Application SQL / database policy.** `Scoped.Tx` accepts caller SQL. The
  module sets `app.tenant_id` and narrows to `AppRole`, but it cannot prevent
  that SQL from calling `set_config` or issuing DDL if the role is allowed to.
- **Issuer / pool.** Dynamic credentials are issued per pool and released after
  the pool closes. A failed release is best-effort; the credential still expires
  on its lease, and Postgres enforces `VALID UNTIL` independently.

## What RLS does not stop

RLS is **not** a SQL-injection containment boundary. A caller able to execute
arbitrary SQL can reset `app.tenant_id`, disable row security, or drop the
policy. A table owner can do the same even when `FORCE ROW LEVEL SECURITY` is
set. The deployment must therefore:

- run tenant SQL through parameterized queries, never string concatenation;
- give the data role no `CREATE`, `ALTER`, `DROP`, or ownership rights;
- own tenant tables with a separate, non-login role;
- treat `CheckEnforcement` as a startup diagnostic, not a proof that every
  future statement is safe.

`AssertRLSCoverage` and `CheckEnforcement` check the catalog: enabled and FORCEd
RLS, a restrictive `tenant_isolation` policy whose predicate references
`tenant_id` and `current_setting('app.tenant_id', ...)`, a `WITH CHECK`
expression, and a permissive `tenant_access` companion. The predicate check is
textual and is not a proof of equivalence; the conformance suite's behavioural
two-tenant tests are the evidence for enforcement.

## Out of scope

Authorization decisions, key material, encryption at rest, query building,
network policy, Postgres server hardening, OpenBao's own ACL policy, and the
consumer's schema ownership. See `CHARTER.md` for the module boundary.

## Operational assumptions

- TLS is used for OpenBao unless the address is loopback.
- The migration credential is used only for schema migrations and role/grants
  reconciliation.
- Runtime credentials are distinct from the migration credential.
- An operator monitors `Stats()` and the `OnCredentialReleaseError` hook; a
  failed release is not silently treated as a successful revocation.
