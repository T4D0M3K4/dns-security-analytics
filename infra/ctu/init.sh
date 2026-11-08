#!/bin/sh
set -eu
test "$POSTGRES_DB" = dns_ctu
test "$POSTGRES_USER" = dns_ctu_owner
for migration in /project-migrations/*.sql; do
    psql -X -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" -f "$migration"
done
psql -X -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" <<'SQL'
COMMENT ON DATABASE dns_ctu IS 'dns-security-analytics:ctu-only:v1';
SQL
