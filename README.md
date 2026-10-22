# tenancy

Who the tenants are, where their data lives, and a pgx connection already
scoped to exactly one of them — failing closed if it is not.

Registry tables and migrations, tenant→pool resolution with caching, residency
attributes, pgx pool and handle lifecycle, RLS session context, tracing.

**Not in scope:** authorization rules (`iam`), key material (`keyring`),
migrations beyond its own registry tables, query building, domain concepts.

See [CHARTER.md](CHARTER.md).
