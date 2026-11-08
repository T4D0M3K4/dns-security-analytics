#!/usr/bin/env bash
set -euo pipefail
project_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
set -a
source "$project_root/.env.ctu"
set +a
: "${SUPERSET_ANALYTICS_USER:?Export SUPERSET_ANALYTICS_USER from your trusted .env}"
: "${SUPERSET_ANALYTICS_PASSWORD:?Export SUPERSET_ANALYTICS_PASSWORD from your trusted .env}"
docker compose --env-file "$project_root/.env.ctu" --project-name dns-ctu --project-directory "$project_root" -f "$project_root/compose.yaml" exec -T \
    -e SUPERSET_ANALYTICS_USER -e SUPERSET_ANALYTICS_PASSWORD postgres \
    sh -c 'psql -X -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB"' \
    < "$project_root/sql/superset/configure_reader.sql"
