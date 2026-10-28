# Examples

Compile-checked examples for the common adoption paths. They use environment
variables rather than embedded credentials, so they are safe to keep in a
repository and can point at a disposable database.

| Example | What it shows |
|---|---|
| [`quickstart`](quickstart/) | Migrate, open the control plane, create/reuse a pool and tenant, resolve, and run one scoped statement. |
| [`rls`](rls/) | Apply `EnableRLS`, sweep `AssertRLSCoverage`, and verify `CheckEnforcement`. |
| [`openbao`](openbao/) | Validate an OpenBao database role and use dynamic credentials with `LongestTransaction`. |
| [`roles`](roles/) | The control/data role split, login identities, and the least-privilege grants. |
| [`testing`](testing/) | The shared `testdb` harness and the conformance suites. |

Build every program:

```bash
go build ./examples/...
```

Run one against a disposable database:

```bash
TENANCY_MIGRATION_DSN='postgres://migration@127.0.0.1/tenancy?sslmode=disable' \
TENANCY_CONTROL_DSN='postgres://control@127.0.0.1/tenancy?sslmode=disable' \
TENANCY_POOL_DSN='postgres://app@127.0.0.1/tenant_db?sslmode=disable' \
go run ./examples/quickstart
```

## Best practices these examples encode

1. **Use three identities.** Migration, control-plane, and data-plane
   credentials are different. The data role has no registry grants.
2. **Treat a DSN as a secret.** Do not log it; `tenancy.DSN` redacts itself.
3. **Use parameterized SQL.** RLS is a backstop against application bugs, not
   containment for SQL injection or DDL-capable roles. See
   [`THREAT_MODEL.md`](../THREAT_MODEL.md).
4. **Call `CheckEnforcement` at startup.** Refuse to serve if `FailClosed()` is
   false. A superuser connection or an owner role can make a policy inert.
5. **Call `AssertRLSCoverage` in CI.** It requires enabled and FORCEd RLS, a
   restrictive tenant policy with `WITH CHECK`, and a permissive companion.
6. **Make status changes through `Control.SetTenantStatus`.** It invalidates the
   resolver cache immediately; `deleting` is terminal.
7. **Set `LongestTransaction` with dynamic credentials.** It is a fact about
   your slowest transaction, not a tunable security preference.
8. **Close the `Tenancy` handle.** It waits for pool closes and best-effort
   credential releases; failed releases are visible through `Stats()` and
   `OnCredentialReleaseError`.
9. **Use `testdb.WithMigrator` explicitly.** `testdb.Start` starts empty; it does
   not silently run this module's migrations.
