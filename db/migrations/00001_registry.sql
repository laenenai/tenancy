-- 00001_registry.sql is the whole of this module's versioned schema: the
-- registry. tenancy.pools holds one row per physical Postgres database
-- hosting tenant metadata; tenancy.tenants holds one row per tenant,
-- pointing at the pool that hosts it.
--
-- What is NOT in this file, and why, because each omission is a decision:
--
--   * The schema's own creation is pgmigrate's (it creates the schema
--     before goose runs, because the version table lives inside it). The
--     CREATE SCHEMA IF NOT EXISTS below is therefore redundant at run time
--     and kept anyway, because sqlc resolves every relation in db/queries
--     against this directory and nothing else: without it, generation
--     fails with `schema "tenancy" does not exist`.
--
--   * The application role and its grants are NOT here. They are
--     declarative state, asserted on every Up by internal/migrate's
--     reconcilers. Putting a GRANT in a versioned migration is the trap
--     pgmigrate exists to close: the migration records itself as applied,
--     so a deployment that later renames its application role comes up
--     with no privilege separation at all while the migrator reports
--     everything applied.
--
--   * No row-level-security policy is created on either table, and this is
--     the single most important comment in this file.
--
-- # NEITHER REGISTRY TABLE CARRIES AN RLS POLICY, DELIBERATELY
--
-- Every tenant-scoped table in every *consumer* of this module carries a
-- tenant_id column and a policy keyed on current_setting('app.tenant_id')
-- — that is the fail-closed backstop this module exists to provide, and
-- internal/pg.EnableRLS is the one implementation of it.
--
-- These two tables are the exception, and the reason is an ordering fact
-- rather than a judgement call. Resolution — turning an incoming tenant id
-- into "which physical database, and may this tenant be served at all" —
-- must read this exact tenancy.tenants row BEFORE any app.tenant_id
-- session variable exists to satisfy a policy. It is what *establishes*
-- that context for everything downstream, not a consumer of it. A policy
-- here keyed on app.tenant_id would make the resolver unable to read the
-- very row it needs in order to start a tenant's session: a deadlock in
-- the design, not a security gap. Nothing in either table is tenant
-- *content*; they are the registry.
--
-- This is the control-plane half of the asymmetry the charter names, and
-- it is why the control-plane handle must never be reachable with
-- caller-supplied predicates — there is no row security behind it to catch
-- a mistake. internal/registry.Control therefore exposes no method that
-- takes SQL.
--
-- internal/pg.RegistryTablesExemptFromRLS names both tables so that
-- AssertRLSCoverage's sweep reports a genuinely missing policy without
-- ever reporting these. That is an explicit, named exemption rather than
-- an implicit rule like "tables without a tenant_id column", so this
-- reasoning stays visible at the point where someone might otherwise
-- "fix" the apparent gap.

-- +goose Up
CREATE SCHEMA IF NOT EXISTS tenancy;

-- Every id column in this schema is tenancy.ulid: a Crockford base32 ULID
-- string, exactly 26 characters, which is what internal/domain's id types
-- encode to. There are no UUIDs anywhere in this system, which is also why
-- the row-level-security predicate in internal/pg carries no cast — see
-- its doc comment.
--
-- The CHECK is what turns a malformed id into a database-level error
-- instead of a silently stored bad value, so the typed ids' invariant
-- survives a hand-run statement and not only a call through this module.
CREATE DOMAIN tenancy.ulid AS text
    CHECK (VALUE ~ '^[0-9A-HJKMNP-TV-Z]{26}$');

CREATE TABLE tenancy.pools (
    id               tenancy.ulid PRIMARY KEY,
    name             text NOT NULL UNIQUE,
    region           text NOT NULL,
    metadata_dsn     text NOT NULL,
    blob_config_ref  text NOT NULL,
    worker_capacity  integer NOT NULL,
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE tenancy.tenants (
    id             tenancy.ulid PRIMARY KEY,
    pool_id        tenancy.ulid NOT NULL REFERENCES tenancy.pools (id),
    name           text NOT NULL UNIQUE,
    security_mode  text NOT NULL CHECK (security_mode IN ('managed', 'tenant-key', 'vault')),
    status         text NOT NULL CHECK (status IN ('active', 'suspended', 'deleting')),
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now()
);

-- Resolution reads tenants by id on every request, and pools by id on
-- every cold cache. Both are primary-key lookups, so no index is added
-- here; the one access path that is not a primary key is "which tenants
-- live in this pool", which an operator asks and a tenant-to-pool
-- migration job will ask, so it gets an index.
CREATE INDEX tenants_pool_id_idx ON tenancy.tenants (pool_id);

-- security_mode is immutable after a tenant's first write: there is no
-- path in this system to migrate already-stored content from one mode's
-- key hierarchy to another, so a mid-flight change would silently orphan
-- ciphertext under the wrong assumption.
--
-- internal/registry offers no method that could update it, but that is an
-- application-layer guarantee only: it does not stop a later increment
-- adding an update that touches the wrong column, or a hand-run statement
-- in an incident. This trigger makes the immutability a property of the
-- table itself, enforced no matter what writes it.
-- +goose StatementBegin
CREATE FUNCTION tenancy.tenants_security_mode_immutable() RETURNS trigger AS $$
BEGIN
    IF NEW.security_mode IS DISTINCT FROM OLD.security_mode THEN
        RAISE EXCEPTION 'tenancy.tenants.security_mode is immutable after creation (tenant %)', OLD.id;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

CREATE TRIGGER tenants_security_mode_immutable
    BEFORE UPDATE ON tenancy.tenants
    FOR EACH ROW
    EXECUTE FUNCTION tenancy.tenants_security_mode_immutable();

-- +goose Down
DROP TRIGGER IF EXISTS tenants_security_mode_immutable ON tenancy.tenants;

DROP FUNCTION IF EXISTS tenancy.tenants_security_mode_immutable();

DROP TABLE IF EXISTS tenancy.tenants;

DROP TABLE IF EXISTS tenancy.pools;

DROP DOMAIN IF EXISTS tenancy.ulid;
