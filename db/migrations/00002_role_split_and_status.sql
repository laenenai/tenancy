-- 00002_role_split_and_status.sql adds the invariants that the role split and
-- lifecycle work depend on, without rewriting the released registry migration.
--
-- The worker_capacity CHECK is the database backstop for the Go-side upper
-- bound: the column is a PostgreSQL integer, and a value that wrapped through
-- int32 would otherwise be stored as a negative capacity.
--
-- The status trigger makes the lifecycle a property of the table rather than
-- of one method. deleting is terminal: moving a deleting tenant back to active
-- could resurrect a tenant whose data is already being erased. The same rule
-- is exposed in Go as TenantStatus.CanTransitionTo.

-- +goose Up
ALTER TABLE tenancy.pools
    ADD CONSTRAINT pools_worker_capacity_nonnegative CHECK (worker_capacity >= 0);

-- +goose StatementBegin
CREATE FUNCTION tenancy.tenants_status_transition() RETURNS trigger AS $$
BEGIN
    IF NEW.status IS DISTINCT FROM OLD.status THEN
        IF OLD.status = 'deleting' THEN
            RAISE EXCEPTION 'tenancy.tenants.status is terminal: tenant % cannot leave deleting', OLD.id;
        END IF;
        IF OLD.status NOT IN ('active', 'suspended')
           OR NEW.status NOT IN ('active', 'suspended', 'deleting') THEN
            RAISE EXCEPTION 'tenancy.tenants.status: invalid transition % -> %', OLD.status, NEW.status;
        END IF;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

CREATE TRIGGER tenants_status_transition
    BEFORE UPDATE OF status ON tenancy.tenants
    FOR EACH ROW
    EXECUTE FUNCTION tenancy.tenants_status_transition();

-- +goose Down
DROP TRIGGER IF EXISTS tenants_status_transition ON tenancy.tenants;
DROP FUNCTION IF EXISTS tenancy.tenants_status_transition();
ALTER TABLE tenancy.pools DROP CONSTRAINT IF EXISTS pools_worker_capacity_nonnegative;
