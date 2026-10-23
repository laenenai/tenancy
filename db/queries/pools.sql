-- Pool queries: the control plane's whole interest in tenancy.pools.
--
-- There is no DeletePool and no UpdatePool. A pool row records where a
-- tenant's data physically lives, so a row that could be removed or
-- repointed would make the location of stored data forgettable, and
-- changing it under a running deployment would move a tenant's data
-- without moving the data. Moving a tenant between pools is an explicit,
-- resumable migration job with a read-only window (CAS §14.1) and is out
-- of this module's charter.
--
-- There is also no ListPools. Operator reporting aggregates per pool
-- rather than across pools, by design; a cross-pool listing is the first
-- step towards a cross-pool query, which §14.1 says does not exist.

-- name: CreatePool :one
INSERT INTO tenancy.pools (id, name, region, metadata_dsn, blob_config_ref, worker_capacity)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING id, name, region, metadata_dsn, blob_config_ref, worker_capacity, created_at, updated_at;

-- name: PoolByID :one
SELECT id, name, region, metadata_dsn, blob_config_ref, worker_capacity, created_at, updated_at
FROM tenancy.pools
WHERE id = $1;

-- name: PoolByName :one
SELECT id, name, region, metadata_dsn, blob_config_ref, worker_capacity, created_at, updated_at
FROM tenancy.pools
WHERE name = $1;
