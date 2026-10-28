-- 00003_registry_immutability.sql makes the two columns that decide where a
-- tenant's data lives immutable through normal UPDATEs. A control-plane
-- mistake or an injected statement that repoints pool_id or metadata_dsn is a
-- data-location change, not an ordinary row edit; it needs a deliberate
-- migration with its own review, not an UPDATE.

-- +goose Up
-- +goose StatementBegin
CREATE FUNCTION tenancy.protect_registry_location() RETURNS trigger AS $$
BEGIN
    IF TG_TABLE_NAME = 'tenants' AND NEW.pool_id IS DISTINCT FROM OLD.pool_id THEN
        RAISE EXCEPTION 'tenancy.tenants.pool_id is immutable; create a new tenant or run an explicit migration';
    END IF;
    IF TG_TABLE_NAME = 'pools' AND NEW.metadata_dsn IS DISTINCT FROM OLD.metadata_dsn THEN
        RAISE EXCEPTION 'tenancy.pools.metadata_dsn is immutable; rotate credentials through a new pool';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

CREATE TRIGGER tenants_pool_id_immutable
    BEFORE UPDATE OF pool_id ON tenancy.tenants
    FOR EACH ROW
    EXECUTE FUNCTION tenancy.protect_registry_location();

CREATE TRIGGER pools_metadata_dsn_immutable
    BEFORE UPDATE OF metadata_dsn ON tenancy.pools
    FOR EACH ROW
    EXECUTE FUNCTION tenancy.protect_registry_location();

-- +goose Down
DROP TRIGGER IF EXISTS tenants_pool_id_immutable ON tenancy.tenants;
DROP TRIGGER IF EXISTS pools_metadata_dsn_immutable ON tenancy.pools;
DROP FUNCTION IF EXISTS tenancy.protect_registry_location();
