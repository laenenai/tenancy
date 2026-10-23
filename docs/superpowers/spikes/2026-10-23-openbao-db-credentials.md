# Spike: OpenBao database credentials against real Postgres

**Date:** 2026-10-23
**Scripts:** [`2026-10-23-openbao-db-credentials/`](./2026-10-23-openbao-db-credentials/)
**Transcripts:** [`2026-10-23-openbao-db-credentials/transcripts/`](./2026-10-23-openbao-db-credentials/transcripts/)

Three questions the documentation does not answer, measured against a real
OpenBao talking to a real Postgres. Every number below comes from a
transcript in that directory; nothing is inferred from documentation.

## What was tested on

| Component | Version |
|---|---|
| OpenBao | `v2.2.1` (`91733be3109e5a5000b750939e5748433c78cfcf`, built 2025-04-22), dev mode |
| OpenBao image | `openbao/openbao:2.2.1` @ `sha256:62f582f85e405ef00d48f678c19863d096a2bc0c05e0e5a9bbccd676a1c7316c` |
| Database plugin | `postgresql-database-plugin` `v2.2.1+builtin.bao` (builtin) |
| Postgres | `18.6 (Debian 18.6-1.pgdg12+2)` |
| Postgres image | `pgvector/pgvector:pg18` @ `sha256:2358fcba361ed2233a5ed81b5fe4ca779ccb304120ce531a3bf51c0ed7e2bc11` |
| Client | Go 1.25.6, `github.com/jackc/pgx/v5 v5.7.6` |
| Host | macOS 15.5, arm64, Docker Engine 20.10.17 |

OpenBao talks to Postgres over a container network; the Go programs reach the
same server from the host. `log_statement=all` is on, so the exact SQL
OpenBao issues is quoted from the Postgres log rather than from docs.

The fixture is the design as described: a named `app_role` holding
`SELECT`/`INSERT` and explicitly not `UPDATE`/`DELETE`/`TRUNCATE`, a table
with `ENABLE` + `FORCE ROW LEVEL SECURITY`, and a policy written **against
that named role**:

```sql
CREATE POLICY items_tenant_isolation ON items
  TO app_role
  USING      (tenant_id = current_setting('tenancy.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('tenancy.tenant_id', true));
```

Reproduce with `./setup.sh` then the `go run` lines in its header comment.

---

## Q1 — What happens to an already-open connection when its lease expires?

**Short answer: the connection does not die. It keeps its TCP session, its
backend, and its transaction, and simply starts failing every statement with
`SQLSTATE 42501 permission denied` — except on relations the current
transaction already holds a lock on, where it keeps working with full
privileges until the transaction ends.**

### What OpenBao actually does at expiry

The default revocation, read off the Postgres log, is five statements and no
`pg_terminate_backend`:

```sql
REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM "v-token-…";
REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM "v-token-…";
REVOKE USAGE ON SCHEMA public FROM "v-token-…";
REVOKE CONNECT ON DATABASE "spike" FROM "v-token-…";
DROP ROLE IF EXISTS "v-token-…";
```

So expiry is a privilege removal, not a disconnection. Nothing asks the
backend to go away.

### Per-scenario results (`transcripts/q1.txt`, 10s TTL, 2s probe interval)

| Scenario | First failure | Error | Transaction outcome |
|---|---|---|---|
| idle | **t+10.12s** (the expiry itself) | `42501 permission denied for table items` | — |
| open txn that had **already read** `items` | **never** | — | `COMMIT succeeded` at t+20.2s |
| open txn that had **not yet touched** `items` | **t+14.13s** (its first read) | `42501`, then `25P02` | `COMMIT failed: commit unexpectedly resulted in rollback` |
| named prepared statement | **t+10.07s** | `42501 permission denied for table items` | — |
| open txn holding `RowExclusiveLock` (uncommitted `INSERT`) | **never** | — | `COMMIT succeeded` at t+20.2s, **16s after its role was dropped** |

Across every scenario, for the whole 20s watch window after expiry:

```
conn.IsClosed=false    lease_known=false    role_exists=false
```

The role is gone from `pg_roles`, the lease is gone from OpenBao
(`sys/leases/lookup` → `HTTP 400 {"errors":["invalid lease"]}`), and the
connection is still open.

### The idle/prepared case

Privilege loss is effectively instantaneous. The probe that observed
`lease_known=false role_exists=false` is the same probe that got `42501` —
within the 2s probe resolution there is no window where the lease is gone but
the connection still works. A named prepared statement behaves identically to
an ad-hoc query: the plan is cached, the privilege check is not.

### The transaction case — this is the surprising one

The `txn` and `txn-untouched` pair isolates the mechanism. Both open a
transaction before expiry. The only difference is whether `items` was read
*before* the revocation:

- **already read it** → survives the revocation completely and commits
  successfully;
- **had not read it** → its first read after revocation fails `42501`,
  poisons the transaction (`25P02`), and the commit turns into a rollback.

So the stale privilege is **per relation, not per transaction**: a relation
whose lock the transaction already holds keeps its cached ACL for the life of
the transaction, because re-acquiring an already-held lock does not make the
backend accept catalog invalidations. The `locked` scenario is the sharpest
form of this — an uncommitted writer whose role was dropped 16 seconds
earlier committed its row anyway, and the row is in the table:

```
 id | tenant_id |  payload
----+-----------+-----------
  9 | tenant-a  | q1-locked
```

**A long transaction therefore outlives its own credential, with full
privileges, for as long as it runs.**

### Does revocation fail or hang against a live session?

**No — it never blocked.** `sys/leases/revoke` returned in **0.02s** while a
session held `RowExclusiveLock` on `items` from an uncommitted `INSERT`.
`DROP ROLE` succeeds with live sessions as the role; `REVOKE` on tables does
not take a lock that conflicts with readers or writers. There is no
back-pressure from Postgres onto OpenBao here at all.

### But revocation *can* fail permanently (`transcripts/q1own.txt`)

Found by accident, and it matters. Postgres refuses `DROP ROLE` for a role
that owns objects, and the default revocation statements contain no
`REASSIGN OWNED`/`DROP OWNED`:

```
revoke returned after 0.02s err=PUT sys/leases/revoke: HTTP 400:
  {"errors":["failed to revoke entry: … err: ERROR: role "v-token-q1-owner-…"
   cannot be dropped because some objects depend on it (SQLSTATE 2BP01)"]}
  +  0s role_exists_in_pg=true lease=STILL KNOWN to OpenBao
  +  5s role_exists_in_pg=true lease=STILL KNOWN to OpenBao
  + 15s role_exists_in_pg=true lease=STILL KNOWN to OpenBao
leases still listed under this role: {"keys":["wBdUbo7iBqD0W6KmM8IuYrXh"]}
```

The role stays in Postgres, the lease stays in OpenBao, and only manual
`REASSIGN OWNED` / `DROP OWNED` / `DROP ROLE` clears it. A dynamic credential
that can create objects is a credential that can become unrevocable.

### The one backstop that does hold

`VALID UNTIL '{{expiration}}'` in the creation statement is enforced
independently of revocation. With the role still present and the password
still correct, an expired `VALID UNTIL` refuses login:

```
$ PGPASSWORD=vupass psql -h localhost -p 55432 -U vu_test -d spike -c 'select 1'
psql: error: … FATAL:  password authentication failed for user "vu_test"
$ SELECT rolname, rolvaliduntil FROM pg_roles WHERE rolname='vu_test';
vu_test|2020-01-01 00:00:00+00
```

Pushing `VALID UNTIL` to `infinity` makes the same credential work again, so
this is `VALID UNTIL` and not a password problem. Note the error is
`28P01 password authentication failed` — **indistinguishable from a wrong
password**, and identical to what a dropped role produces. A client cannot
tell "my lease expired" from "my password is stale" from "this role never
existed" by the error alone. Also note it gates *login only*: the `txn`
scenarios kept working well past their `VALID UNTIL`.

---

## Q2 — Can a dynamically issued user inherit an existing Postgres role?

**Short answer: yes, both `IN ROLE` and `GRANT … TO` work identically, and
RLS applies to the inheriting member correctly. The policy is matched by
*membership*, not by name, so a policy written against `app_role` is neither
bypassed nor missed by an ephemeral member — and it fails closed.**

### Identity, and why the name mismatch does not matter

`transcripts/q2.txt`, for `q2-inrole` and `q2-grant` (byte-identical results):

```
current_user                                   v-token-q2-inrol-…-1792727407
session_user                                   v-token-q2-inrol-…-1792727407
current_setting('role')                        none
rolinherit                                     true
rolbypassrls                                   false
rolsuper                                       false
pg_has_role(current_user,'app_role','USAGE')   true
pg_has_role(current_user,'app_role','MEMBER')  true
row_security_active('items')                   true
```

This is the distinction the question was aimed at. `current_user` and
`session_user` are **both** the ephemeral `v-token-…` name, and **neither** is
`app_role` — the role the policy names. The policy still applies, because
Postgres resolves a policy's `TO` clause with `pg_has_role(current_user,
<policy role>, 'USAGE')`, which is `true` for an inheriting member.
`row_security_active('items')` is the direct confirmation: `true`.

Privileges are exactly the design's set, and nothing more:

```
has_table_privilege SELECT items               true
has_table_privilege INSERT items               true
has_table_privilege UPDATE items               false
has_table_privilege DELETE items               false
has_table_privilege TRUNCATE items             false
```

### RLS enforcement from the issued credential

```
tenant=(unset)      SELECT count(*) -> 0 rows visible
tenant=tenant-a     SELECT count(*) -> 3 rows visible
tenant=tenant-b     SELECT count(*) -> 1 rows visible
tenant=' OR true -- SELECT count(*) -> 0 rows visible
```

(The absolute counts drift between runs because earlier scenarios insert
rows; what matters is that the three partitions are disjoint and that the
unset and injected cases are zero.)

```
INSERT matching tenant                OK (INSERT 0 1)
INSERT other tenant                   DENIED 42501 new row violates row-level security policy for table "items"
UPDATE                                DENIED 42501 permission denied for table items
DELETE                                DENIED 42501 permission denied for table items
TRUNCATE                              DENIED 42501 permission denied for table items
CREATE TABLE                          DENIED 42501 permission denied for schema public
```

Unset tenant yields zero rows, not all rows: **fail closed**. The injected
value is treated as data, not SQL. `WITH CHECK` blocks the cross-tenant
write. `UPDATE`/`DELETE`/`TRUNCATE` are refused at the privilege layer, so
RLS is a backstop and not the only control. The runtime credential cannot do
DDL.

### Grants the reconciler adds later are picked up live

A table created and granted to `app_role` *after* the dynamic user already
had an open connection:

```
has_table_privilege on the new table           true
SELECT from the new table                      OK (SELECT 1)
```

Membership is evaluated per statement, so the reconciler-on-every-migration
model works without reissuing credentials or reconnecting.

### `NOINHERIT` is the trap, and it fails closed

```
rolinherit                                     false
pg_has_role(current_user,'app_role','USAGE')   false
pg_has_role(current_user,'app_role','MEMBER')  true     <-- still true!
has_table_privilege SELECT items               false
row_security_active('items')                   true
tenant=tenant-a     SELECT count(*) -> ERROR 42501 permission denied for table items
```

Everything is denied — fail closed, which is the right direction — but note
that a membership assertion written with `'MEMBER'` reports `true` while the
session holds nothing. **If `tenancy` ever asserts "this credential inherits
app_role", it must check `pg_has_role(current_user, 'app_role', 'USAGE')`.**
`'MEMBER'` would pass a credential that cannot read a single row.

### `SET ROLE` is still available, and `RESET ROLE` still reverses it

```
SET ROLE app_role                              OK (SET)
after SET ROLE: current_user                   app_role
after SET ROLE: session_user                   v-token-q2-inrol-…
RESET ROLE                                     OK (RESET)
after RESET ROLE: current_user                 v-token-q2-inrol-…
```

Inheritance does not remove `SET ROLE`; a member can always assume the role
it belongs to. This does **not** weaken the inheritance design — the member
already holds those privileges by inheritance, so `SET ROLE` grants nothing
new — but it confirms the decision to reject `SET ROLE` *as the separation
mechanism* was about the right thing: `RESET ROLE` reverses it, and
inheritance is the thing that cannot be reset.

### Where this *can* fail open (`transcripts/q2rls.txt`)

The membership route is sound. The policy route is where it breaks, and it is
worth recording because it is not specific to dynamic users but is made more
likely by them:

```
-- 1. baseline: only the PERMISSIVE tenant policy --
  dynamic user, tenant-a                         5 rows visible

-- 2. a second PERMISSIVE policy is added (TO PUBLIC USING (true)) --
  dynamic user, tenant-a                         6 rows visible
   !! FAIL OPEN: the member now sees all 6 rows; permissive policies OR

-- 3. the tenant predicate is made AS RESTRICTIVE instead --
  dynamic user, tenant-a                         5 rows visible
  dynamic user, tenant UNSET (restrictive, must be 0) 0 rows visible
```

Permissive policies are ORed, so **any** later policy that also matches the
member widens the tenant predicate silently. `AS RESTRICTIVE` is ANDed and
cannot be widened by anything added afterwards. For a cross-tenant disclosure
control, the tenant predicate must be `AS RESTRICTIVE`.

### And the migration credential's relationship to RLS

```
-- 4. root (superuser, table owner) --
  root rolsuper                          true
  root rolbypassrls                      true
  root row_security_active('items')      false
  items relrowsecurity                   true
  items relforcerowsecurity              true
  root sees 6 rows with no tenant set — RLS does not constrain a superuser at all

-- 5. a non-superuser, non-owner role with ALL privileges on items --
  mig_role row_security_active('items')   true
  mig_role, no tenant set                 0 rows visible
  mig_role DDL: ALTER TABLE items …       DENIED 42501 must be owner of table items

-- 6. a migration credential that is a MEMBER OF the owning role --
  mig_role pg_has_role(tbl_owner,'USAGE') true
  mig_role row_security_active('items2')  true
  mig_role DDL on items2                  OK
  mig_role SELECT items2, no tenant set   0 rows visible (items2 holds 2)
```

Two things fall out. First, DDL in Postgres is gated on **ownership**, not on
a grantable privilege — section 5 shows `ALL PRIVILEGES` is still not enough
to `ALTER TABLE` — so a migration credential has to be, or be a member of,
the owning role. Second, and better than expected: section 6 shows that such
a credential is **still fully constrained by RLS** under `FORCE ROW LEVEL
SECURITY`, seeing 0 of 2 rows with no tenant set. A superuser is not (section
4: `row_security_active` is `false` even with `relforcerowsecurity` true).
**The migration credential need not be a cross-tenant read capability, as
long as it is a member of an owning role rather than a superuser.**

---

## Q3 — Does a static role's password rotation break a live pgxpool?

**Short answer: existing pooled connections are untouched and keep working
indefinitely. Every new connection fails immediately with `SQLSTATE 28P01`.
The pool therefore dies silently and gradually, at a rate set by
`MaxConnLifetime` — and `pool.Ping` reports healthy the whole time. There is
a usable pre-rotation signal: the `ttl` field on `database/static-creds/`.**

### Rotation is one statement, and it terminates nothing

From the Postgres log:

```sql
ALTER ROLE "app_runtime" WITH PASSWORD 'SCRAM-SHA-256$4096:…'
```

`rotate-role` returned in **0.009s**. No `pg_terminate_backend`.

### Existing versus new connections (`transcripts/q3.txt`, 4 warmed connections)

```
[t+  0.06s] rotate-role returned after 0.009s err=<nil>
[t+  0.07s] pooled: 4/4 ok pids=[141 143 142 144] | new connection: FAIL SQLSTATE 28P01: password authentication failed for user "app_runtime"
[t+  3.09s] pooled: 4/4 ok pids=[144 141 143 142] | new connection: FAIL SQLSTATE 28P01: …
…
[t+ 24.3s ] pooled: 4/4 ok pids=[…]                | new connection: FAIL SQLSTATE 28P01: …
[t+ 27.3s ] pool.Ping (may reuse an existing connection) -> <nil>

--- summary ---
existing pooled connections, first failure: NONE in the watch window
new connections, first failure:             t+0.07s SQLSTATE 28P01: password authentication failed for user "app_runtime"
a new connection ever succeeded after rotation: false
```

The same four backend PIDs served every query for the whole window. New
connections failed from **70 milliseconds** after rotation, with
`28P01 password authentication failed for user "app_runtime"` — the same
error a plain wrong password gives, carrying no hint that a rotation is the
cause.

Two details that make this worse than it looks:

- **`pool.Ping` returned `nil`.** The obvious health check is served by an
  already-open connection and says nothing about whether the pool can still
  grow. A pool in this state passes its own health check.
- **`Stat().NewConnsCount()` kept climbing** (5 → 13) while every single
  attempt failed. pgxpool counts attempts, not successes, and does not mark
  itself unhealthy.

### How fast the pool actually dies (`transcripts/q3-lifetime.txt`)

With `pool_max_conn_lifetime=10s`, the pool went from fully healthy to
completely dead in one step:

```
[t+  9.14s] pooled: 4/4 ok pids=[156 158 157 155] | new connection: FAIL 28P01 | stat{total=4 …}
[t+ 12.18s] pooled: 0/4 ok pids=[]                | new connection: FAIL 28P01 | stat{total=0 idle=0 acquired=0 new=10}
[t+ 12.18s] POOL IS DEAD: every connection recycled, none replaceable
[t+ 12.19s] pool.Ping -> … FATAL: password authentication failed … (SQLSTATE 28P01)
```

The pool's remaining working life after a rotation is **`MaxConnLifetime`**
(plus pgxpool's jitter), because pgxpool retires healthy connections on
schedule and then cannot replace them. pgx v5.7.6 defaults
(`pgxpool/pool.go`) are `MaxConnLifetime = 1h`, `MaxConnIdleTime = 30m`,
`HealthCheckPeriod = 1m`, `MaxConns = 4`, `MinConns = 0`. So with defaults a
rotation produces a pool that works for up to an hour and then fails
hard — and the failure is attributed to a password, an hour after the event
that caused it.

### Is there a pre-rotation signal?

**Yes.** `GET database/static-creds/<role>` carries the countdown:

```json
{"last_vault_rotation":"2026-10-23T03:57:07.271889384Z",
 "password":"ega2Pkg3BchnsjZGOkt-",
 "rotation_period":600,
 "ttl":261,
 "username":"app_runtime"}
```

`ttl` is seconds until the next scheduled rotation (261 of a 600s period
here), and it counts down; after the rotation it reset to `600` and
`last_vault_rotation` advanced. So a client **does not** have to track the
rotation period itself: it can poll `static-creds` and know how long it has.

Three caveats:

- `lease_id` is empty and `lease_duration` is `0`. Static credentials are
  **not leases** — there is no renew, no revoke, and no lease-expiry
  machinery to hang a callback on. Polling is the only mechanism.
- `ttl` describes the *scheduled* rotation only. The manual `rotate-role`
  measured above arrives with **zero** notice, and nothing in the API
  announces it. Any client design must handle an unannounced rotation.
- There is no push. No event, no watch, no webhook was found on this version.

---

## What this means for the design

### Can a credential lease drive pool retirement?

**It can be the trigger, but it cannot be the deadline, and the pool needs
lead time measured in transaction length, not in seconds.**

Three findings constrain this:

1. **Expiry is not a disconnect.** The pool will not notice anything. No
   connection closes, `conn.IsClosed()` stays `false`, and pgx surfaces
   nothing. Lease expiry is invisible from the pool's side; it has to be
   driven from the credential side.
2. **Expiry is also not a clean cut-off.** The `txn` and `locked` scenarios
   held full privileges for 10 and 16 seconds past revocation respectively,
   and both committed. A transaction open at expiry finishes with the
   privileges it had — so a lease is not a security boundary on in-flight
   work, only on new work.
3. **The failure mode on the other side is abrupt and unhelpful.** The
   `txn-untouched` scenario shows what a caller gets if retirement is late:
   `42501` mid-transaction, then `25P02`, then a commit that silently becomes
   a rollback. That is a write the application believes succeeded.

This maps cleanly onto `cas`'s `poolEntry` reference counting, and is a
strong argument that the same mechanism belongs in `tenancy`: **retire on
lease age, close on refcount zero.** Mark the entry retired at some fraction
of the lease TTL, stop handing it to new callers, let outstanding borrows
drain, and build the replacement pool on a fresh credential. The refcount is
what prevents the `txn-untouched` outcome, exactly as its doc comment
describes for eviction. The lead time has to exceed the longest transaction
the pool will serve, so the TTL floor is set by the slowest query, not by a
security preference — a 10s TTL like this spike's is unusable for anything
real.

Two further consequences:

- **Never let a runtime credential own objects.** The `q1own` result is a
  credential that cannot be revoked at all, leaving a role in Postgres and a
  lease in OpenBao that only manual `REASSIGN OWNED` clears. The runtime
  credential's inability to do DDL (`permission denied for schema public`) is
  therefore not just least-privilege hygiene; it is what keeps revocation
  working.
- **`VALID UNTIL` is the backstop worth relying on**, because it is enforced
  by Postgres independently of whether OpenBao's revocation succeeded. Keep
  it in every `creation_statements`.

### Dynamic or static for the runtime pool?

**Dynamic, with per-pool credentials and lease-driven retirement.**

Static looked like the safer choice for a long-lived pool and measured worse:

| | Dynamic | Static |
|---|---|---|
| Pool learns of the change | Lease TTL is known at issue time | Only by polling `static-creds.ttl` |
| Unannounced change possible | No — the TTL is the contract | **Yes** — manual `rotate-role`, zero notice |
| Failure if the pool misses it | `42501` on new statements | `28P01` on new *connections*, up to `MaxConnLifetime` later |
| Health check detects it | — | **No** — `pool.Ping` returns `nil` |
| Blast radius of one credential | One pool | Every pool and every process sharing the role |

The decisive one is the row about `pool.Ping`. A static rotation produces a
pool that is **already broken and still reports healthy**, and whose
connections die up to an hour later with an error that names a password. A
dynamic lease at least has a known expiry the pool can schedule against, and
the error arrives at the moment of the event. Static also shares one password
across every consumer of `app_runtime`, so a rotation is a fleet-wide event
rather than a per-pool one.

If static is used anyway, the pool must set `MaxConnLifetime` well below the
`rotation_period`, poll `static-creds` and rebuild on a `last_vault_rotation`
change, and must not treat `Ping` as a liveness signal.

### Are per-pool dynamic credentials safe with RLS?

**Yes — with two conditions, both of which are things `tenancy` controls.**

The core worry is answered: a policy written against `app_role` is matched by
membership (`pg_has_role(current_user, …, 'USAGE')`), not by name, so the
ephemeral `v-token-…` user is fully covered. `row_security_active('items')`
is `true`, an unset tenant yields zero rows, cross-tenant writes are refused
by `WITH CHECK`, and privileges granted to `app_role` later are picked up
without reconnecting. Nothing silently fails open through the name mismatch
between `current_user` and the policy's role.

The two conditions:

1. **Write the tenant predicate `AS RESTRICTIVE`.** Section 2 of
   `q2rls.txt` is a measured fail-open: one later permissive policy that also
   matches the member and the tenant predicate is ORed away. Restrictive
   policies are ANDed and cannot be widened. For a cross-tenant disclosure
   control this is not a preference.
2. **Create the user with inheritance and assert `'USAGE'`, never
   `'MEMBER'`.** `NOINHERIT` fails closed, so it is not a leak — but
   `pg_has_role(…, 'MEMBER')` returns `true` for a credential that holds no
   privileges at all, so a conformance check written against `'MEMBER'` would
   pass a completely non-functional credential. The suite should assert
   `pg_has_role(current_user, <app role>, 'USAGE')` and
   `row_security_active(<table>)` from the issued credential, as positive
   checks that the backstop is actually armed.

`IN ROLE app_role` and a separate `GRANT app_role TO "{{name}}"` produced
byte-identical results, so either form works; `IN ROLE` is one statement
fewer and cannot half-succeed.

A third note, not a condition but worth recording in the charter's terms: the
**control plane** connection is the one place this falls down. Section 4
shows a superuser is not constrained by RLS even with
`FORCE ROW LEVEL SECURITY` on the table. Section 6 shows a non-superuser that
is merely a *member of the owning role* can do DDL and is still fully subject
to RLS. So the migration credential — and the unscoped control-plane
credential — should be members of an owning role, never superusers, which
keeps even the control plane inside the fail-closed backstop.

---

## Things that surprised me

1. **An open transaction keeps revoked privileges, per relation.** A
   transaction that had already read a table kept reading it and committed
   successfully 10–16 seconds after its role was dropped. A transaction that
   had *not* yet touched it failed on first access. The boundary is the
   relation lock, not the transaction.
2. **A dropped role can commit a write.** The `locked` scenario's row is in
   the table, inserted by a role that had not existed for 16 seconds.
3. **Revocation never blocks, but it can fail forever.** Sub-30ms against a
   live uncommitted writer; a hard `2BP01` failure and a permanently stuck
   lease if the role owns anything.
4. **`pool.Ping` returns `nil` on a pool that cannot open a single new
   connection.** The pool is dead and passes its own health check.
5. **`NewConnsCount` counts failures.** It climbed 5 → 13 while every attempt
   was rejected.
6. **Every one of these failures reports as `28P01 password authentication
   failed`** — lease expired, role dropped, `VALID UNTIL` passed, static
   password rotated. All indistinguishable from a typo.
7. **`ALL PRIVILEGES` is not enough to run a migration.** DDL needs ownership
   (`must be owner of table items`), which changes what a migration
   credential has to be.
8. **`FORCE ROW LEVEL SECURITY` reaches a member of the owning role but not a
   superuser** — which is better news than expected, and makes a
   fail-closed migration credential actually achievable.
