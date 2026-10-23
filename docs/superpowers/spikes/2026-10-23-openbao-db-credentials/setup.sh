#!/usr/bin/env bash
# Brings up the exact stack the 2026-10-23 OpenBao/Postgres credential spike
# was measured against, and configures OpenBao's database secrets engine
# against it. Idempotent: it removes and recreates both containers.
#
#   ./setup.sh                      # start and configure
#   go run ./q1                     # Q1: lease expiry vs an open connection
#   go run ./q2                     # Q2: inherited privileges and RLS
#   go run ./q2rls                  # Q2: the RLS fail-open vectors
#   go run ./q3 -watch 25s          # Q3: static rotation vs a live pgxpool
#   go run ./q3 -watch 40s -lifetime 10s   # Q3: how fast a rotated-out pool dies
#   go run ./q1own                  # the unrevocable-lease failure mode
#   ./setup.sh down                 # tear down
#
# Ports are deliberately non-default (55432/58200) so this never collides
# with a dev stack already holding 5432/8200.
set -euo pipefail

NET=baospike
PG=baospike-pg
BAO=baospike-bao
PG_PORT=55432
BAO_PORT=58200
BAO_TOKEN=spike-root
PG_IMAGE=pgvector/pgvector:pg18
BAO_IMAGE=openbao/openbao:2.2.1

if [[ "${1:-up}" == "down" ]]; then
  docker rm -f "$PG" "$BAO" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  echo "torn down"
  exit 0
fi

docker network create "$NET" >/dev/null 2>&1 || true
docker rm -f "$PG" "$BAO" >/dev/null 2>&1 || true

# log_statement=all is what let the spike report the exact SQL OpenBao runs
# on revocation and rotation, rather than quoting the documentation.
docker run -d --name "$PG" --network "$NET" \
  -e POSTGRES_USER=root -e POSTGRES_PASSWORD=rootpass -e POSTGRES_DB=spike \
  -p "${PG_PORT}:5432" "$PG_IMAGE" \
  postgres -c max_connections=200 -c log_statement=all -c log_connections=on -c log_disconnections=on >/dev/null

docker run -d --name "$BAO" --network "$NET" \
  -e BAO_DEV_ROOT_TOKEN_ID="$BAO_TOKEN" -e BAO_DEV_LISTEN_ADDRESS=0.0.0.0:8200 \
  --cap-add IPC_LOCK -p "${BAO_PORT}:8200" "$BAO_IMAGE" server -dev >/dev/null

for _ in $(seq 1 60); do docker exec "$PG" pg_isready -U root -q && break; sleep 1; done
for _ in $(seq 1 60); do curl -sf "http://localhost:${BAO_PORT}/v1/sys/health" >/dev/null && break; sleep 1; done

# ---------------------------------------------------------------- schema
# The reconciler's output, as the tenancy design describes it: a named
# app_role with INSERT/SELECT and explicitly no UPDATE/DELETE/TRUNCATE, and
# an RLS policy written against that NAMED role.
docker exec -i "$PG" psql -U root -d spike -v ON_ERROR_STOP=1 >/dev/null <<'SQL'
CREATE ROLE app_role NOLOGIN;

CREATE TABLE items (
  id        bigserial PRIMARY KEY,
  tenant_id text NOT NULL,
  payload   text NOT NULL
);

GRANT USAGE ON SCHEMA public TO app_role;
GRANT SELECT, INSERT ON items TO app_role;
GRANT USAGE, SELECT ON SEQUENCE items_id_seq TO app_role;

ALTER TABLE items ENABLE ROW LEVEL SECURITY;
ALTER TABLE items FORCE ROW LEVEL SECURITY;

CREATE POLICY items_tenant_isolation ON items
  TO app_role
  USING      (tenant_id = current_setting('tenancy.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('tenancy.tenant_id', true));

INSERT INTO items (tenant_id, payload) VALUES
  ('tenant-a','a-1'), ('tenant-a','a-2'), ('tenant-b','b-1');

-- The named, long-lived login a static role rotates (Q3).
CREATE ROLE app_runtime WITH LOGIN PASSWORD 'initial-placeholder' IN ROLE app_role;
SQL

# ------------------------------------------------------- OpenBao database engine
bao() { curl -sf -H "X-Vault-Token: ${BAO_TOKEN}" "$@"; }

bao -X POST -d '{"type":"database"}' "http://localhost:${BAO_PORT}/v1/sys/mounts/database" >/dev/null

# OpenBao reaches Postgres over the container network, while the Go programs
# reach the same server from the host on $PG_PORT.
bao -X POST "http://localhost:${BAO_PORT}/v1/database/config/spike-pg" -d "$(cat <<JSON
{
  "plugin_name": "postgresql-database-plugin",
  "allowed_roles": "*",
  "connection_url": "postgresql://{{username}}:{{password}}@${PG}:5432/spike?sslmode=disable",
  "username": "root",
  "password": "rootpass",
  "password_authentication": "scram-sha-256"
}
JSON
)" >/dev/null

role() { bao -X POST "http://localhost:${BAO_PORT}/v1/database/roles/$1" -d "$2" >/dev/null; }

# Q1: a plain dynamic user with direct grants, short TTL.
role q1-short '{
  "db_name": "spike-pg",
  "creation_statements": [
    "CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '"'"'{{password}}'"'"' VALID UNTIL '"'"'{{expiration}}'"'"';",
    "GRANT USAGE ON SCHEMA public TO \"{{name}}\";",
    "GRANT SELECT, INSERT ON items TO \"{{name}}\";",
    "GRANT USAGE, SELECT ON SEQUENCE items_id_seq TO \"{{name}}\";"
  ],
  "default_ttl": "10s", "max_ttl": "30s"
}'

# Q1 locked scenario: must be able to INSERT, which under FORCE RLS needs a
# role the policy applies to.
role q1-short-inrole '{
  "db_name": "spike-pg",
  "creation_statements": [
    "CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '"'"'{{password}}'"'"' VALID UNTIL '"'"'{{expiration}}'"'"' IN ROLE app_role;"
  ],
  "default_ttl": "10s", "max_ttl": "30s"
}'

# Q2: the three inheritance shapes.
role q2-inrole '{
  "db_name": "spike-pg",
  "creation_statements": [
    "CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '"'"'{{password}}'"'"' VALID UNTIL '"'"'{{expiration}}'"'"' IN ROLE app_role;"
  ],
  "default_ttl": "10m", "max_ttl": "1h"
}'
role q2-grant '{
  "db_name": "spike-pg",
  "creation_statements": [
    "CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '"'"'{{password}}'"'"' VALID UNTIL '"'"'{{expiration}}'"'"';",
    "GRANT app_role TO \"{{name}}\";"
  ],
  "default_ttl": "10m", "max_ttl": "1h"
}'
role q2-noinherit '{
  "db_name": "spike-pg",
  "creation_statements": [
    "CREATE ROLE \"{{name}}\" WITH LOGIN NOINHERIT PASSWORD '"'"'{{password}}'"'"' VALID UNTIL '"'"'{{expiration}}'"'"' IN ROLE app_role;"
  ],
  "default_ttl": "10m", "max_ttl": "1h"
}'

# Q3: the static role over the named login.
bao -X POST "http://localhost:${BAO_PORT}/v1/database/static-roles/app-runtime" \
  -d '{"db_name":"spike-pg","username":"app_runtime","rotation_period":"600s"}' >/dev/null

cat <<EOF
ready.
  postgres  localhost:${PG_PORT}  (root/rootpass, db spike)
  openbao   http://localhost:${BAO_PORT}  (token ${BAO_TOKEN})
  dynamic roles: q1-short q1-short-inrole q2-inrole q2-grant q2-noinherit
  static role:   app-runtime  (over the app_runtime login)
EOF
