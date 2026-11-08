# Apache Superset — active CTU application

Superset **6.1.0**, pinned by image digest in infra/superset/Dockerfile, adds pinned psycopg2 support. A single `compose.yaml` / project `dns-ctu` uses analytics service `postgres` plus isolated metadata service `superset-db`, persistent named volumes and loopback web port8089. Use only this project and its explicit environment file.

## Start and first login

Complete `.env.ctu`, data pipeline, reporting migration and reader provisioning in [reproduction_guide.md](reproduction_guide.md). Required variables are documented in `.env.example`. Metadata/admin/reader passwords and SECRET_KEY are separate private secrets.

```bash
docker compose --env-file .env.ctu -f compose.yaml build superset-init
docker compose --env-file .env.ctu -f compose.yaml up -d superset-db
docker compose --env-file .env.ctu -f compose.yaml run --rm superset-init
docker compose --env-file .env.ctu -f compose.yaml up -d superset
curl --fail http://localhost:8089/health
```

Login at http://localhost:8089 with SUPERSET_ADMIN_USER / SUPERSET_ADMIN_PASSWORD from the private file. `initialize.py` uses Superset's supported application configuration to create admin and saved connection. Analytics connection is named **DNS Security Analytics (read-only)**, PostgreSQL host `postgres`,port5432,database dns_ctu, role dns_ctu_reader; metadata uses `superset-db`, never localhost. Actual passwords are passed only at runtime. `verify.py` reads metadata through the application and checks real PostgreSQL ACL denials; no direct metadata writes are used for assets.

## Reproduce assets with REST

The REST lifecycle client inspects the live6.1.0 OpenAPI schema, uses stable CTU UUIDs and upserts without duplicate charts/datasets. Execute from repository root. Import uses the committed sanitized export; create regenerates from Python definitions. Both require initialized saved connection and live reporting views.

```bash
# Import in a fresh Superset, substituting the private runtime database password.
docker compose --env-file .env.ctu -f compose.yaml run --rm --no-deps \
  -v "$PWD/infra/superset:/app/dashboard-setup:ro" \
  -v "$PWD/infra/superset/assets:/assets:ro" \
  superset-init python /app/dashboard-setup/dashboard_assets.py import
# Alternative: regenerate from version-controlled definitions.
docker compose --env-file .env.ctu -f compose.yaml run --rm --no-deps \
  -v "$PWD/infra/superset:/app/dashboard-setup:ro" \
  superset-init python /app/dashboard-setup/dashboard_assets.py create
# Execute every chart query and inspect layout/filter metadata.
docker compose --env-file .env.ctu -f compose.yaml run --rm --no-deps \
  -v "$PWD/infra/superset:/app/dashboard-setup:ro" \
  superset-init python /app/dashboard-setup/dashboard_assets.py verify
# Check metadata isolation, authentication and read-only database ACLs.
docker compose --env-file .env.ctu -f compose.yaml run --rm --no-deps \
  superset-init python /app/project/verify.py
# Refresh sanitized assets after an intentional UI/definition change.
docker compose --env-file .env.ctu -f compose.yaml run --rm --no-deps \
  -v "$PWD/infra/superset:/app/dashboard-setup:ro" \
  -v "$PWD/infra/superset/assets:/assets" \
  superset-init python /app/dashboard-setup/dashboard_assets.py export
```

Export contains32 YAML files:3 dashboards,21 charts,6 datasets,1 database placeholder and1 metadata file. Database URI is deliberately `postgresql+psycopg2://READER:XXXXXXXXXX@postgres:5432/ANALYTICS_DB`. Never hand-import an unredacted connection export. Import injects private credentials in-memory, preserves UUIDs and overwrites matching assets, then verify checks all queries. See release_audit.md for current verification, including any fresh-instance import checks.

## Datasets and aggregation

All six physical datasets use schema `reporting`; no synthetic evaluation tables or ground-truth joins exist in this database. They are automatically registered by create or asset import. For manual registration choose the read-only connection → schema reporting → exact view name, then preserve metrics from definitions.

| View | Grain and use |
| --- | --- |
| vw_dns_event_analysis | one event_id; timestamps, endpoints, query/types/codes and optional lexical data; COUNT(*) is events |
| vw_dns_window_analysis | source_ip + UTC minute; behavioral values, aggregated alert_count and alert_types; COUNT(*) is windows |
| vw_dns_alert_analysis | one alert_id; type/severity/JSON evidence/configuration; COUNT(*) is alert records |
| vw_ctu_capture_sources | capture + source_ip; additive event/window/NXDOMAIN/alert counts and distinct alerting-window counts |
| vw_ctu_detector_sources | capture + source_ip + detector; includes zero counts, total window denominator and alerting windows |
| vw_ctu_feature_samples | one window + feature; six actual sample values, used for min/median/p95/max/mean |

No event/window join multiplies rows by alert type. Activation percent = `100 * SUM(alerting_windows) / SUM(total_windows)` within a **single detector**. Alert overlaps are legitimate, so summing types does not count unique windows. Feature averages and percentile summaries are calculated from actual sample rows; ratios use appropriate event/window denominators. PostgreSQL percentile_cont is linear interpolation at `(n-1)*p`. Missing responses are Unknown, not NOERROR. Timestamps are UTC; recorded1970 malware values are kept. Views derive capture from accepted log SHA-256/registry, not date inference.

## Published dashboards

| Dashboard | URL | Charts |
| --- | --- | ---: |
| DNS Traffic Overview | http://localhost:8089/superset/dashboard/dns-traffic-overview/ |8|
| DNS Security & Anomaly Analysis | http://localhost:8089/superset/dashboard/dns-security-anomaly-analysis/ |8|
| CTU Security Comparison | http://localhost:8089/superset/dashboard/ctu-security-comparison/ |5|

Capture and Source IP filters apply across compatible datasets. Security Alert type affects alert charts only, not behavioral scatterplots. Comparison Detector affects activation/count charts only. Percent charts retain zeros. Categorical activity distribution avoids an artificial continuous timeline between1970 malware and2015 normal. Every dashboard states label limitations and historical threshold origin. Only these three CTU dashboards belong to the application.

Read-only inspection examples:

```sql
SELECT capture_name,sum(dns_events),sum(total_windows),sum(alert_records)
FROM reporting.vw_ctu_capture_sources GROUP BY capture_name;
SELECT capture_name,detector,sum(alerting_windows),sum(total_windows),
 100.0*sum(alerting_windows)/nullif(sum(total_windows),0) AS activation_pct
FROM reporting.vw_ctu_detector_sources GROUP BY capture_name,detector;
SELECT capture_name,alert_type,metrics_evidence,threshold_evidence,config_sha256
FROM reporting.vw_dns_alert_analysis LIMIT 5;
```

If charts are missing, verify migration → reader → initialization → import/create sequence. On startup errors inspect Compose health and logs privately; stable SECRET_KEY and persisted metadata must agree. For container database access use service networking. For shutdown use `docker compose --env-file .env.ctu -f compose.yaml stop`; do not delete volumes. See release_audit.md for verified scope and remaining release decisions.
