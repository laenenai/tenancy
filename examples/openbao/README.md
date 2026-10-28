# OpenBao dynamic credentials

This is the opt-in adapter for per-pool database credentials issued by OpenBao's
database secrets engine. The control-plane and migration DSNs stay static; only
tenant pools are opened on issued credentials.

## Configure the OpenBao role

Use the SQL this module prescribes rather than a copied template:

```go
statements, err := openbao.CreationStatements("myapp_data")
// configure the OpenBao database role's creation_statements with statements
```

The application role must be the same `AppRole` passed to `tenancy.Migrate` and
`tenancy.Open`. Every clause in the generated statement is load-bearing:
`LOGIN`, `PASSWORD`, `VALID UNTIL`, `IN ROLE`, and no `SUPERUSER`, `BYPASSRLS`,
`CREATEDB`, `CREATEROLE`, or object-creation rights.

Then validate the role at startup:

```bash
go run ./examples/openbao
```

Environment:

| Variable | Required | Meaning |
|---|---|---|
| `OPENBAO_ADDR` | yes | HTTPS address, or loopback HTTP in development |
| `OPENBAO_TOKEN` | yes | token with access to the database creds endpoint |
| `OPENBAO_DB_ROLE` | yes | database role name |
| `TENANCY_CONTROL_DSN` | yes | control-plane login |
| `TENANCY_APP_ROLE` | no | data grantee, default `myapp_data` |
| `TENANCY_TENANT_ID` | yes | an existing active tenant |

`openbao.Open` rejects URL userinfo, query strings and fragments, requires HTTPS
except on loopback, and refuses cross-host or downgrade redirects so the token
cannot be forwarded to another host. `source.CheckRole` reads the role back and
reports `SUPERUSER`, `BYPASSRLS`, object-creation rights, static-role shape, and
TTL problems.

## The lease contract

`LongestTransaction` is required whenever `Credentials` is set. A tenant pool is
retired that long before its credential expires, so transactions already running
on it can finish; a credential with less than twice that remaining is refused.
Do not guess this value: it is your slowest transaction.

A credential with a lease longer than the pool's useful life is fine; a
credential shorter than twice `LongestTransaction` is a configuration error.
Release is best-effort and detached from the request context. Failed releases do
not block shutdown forever; they are counted in `ten.Stats()` and can be reported
through `Config.OnCredentialReleaseError`.

Never log the issued password or lease id. `tenancy.Credential` redacts itself;
`tenancy.PoolRef` cannot carry `MetadataDSN` to a data-plane handler.
