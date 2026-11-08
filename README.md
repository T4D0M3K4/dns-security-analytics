# DNS Security Analytics

**Analiza DNS saobraćaja i detekcija bezbjednosnih anomalija primjenom Data Engineering tehnika**

An academic offline DNS analysis application for the course *Zaštita komunikacija i protokoli*. It investigates high query frequency, NXDOMAIN concentration, DGA-like names and tunneling-like naming patterns using two public CTU captures. Alerts retain observed values and satisfied thresholds for inspection; they do not prove malicious intent.

```text
CTU Normal PCAP + CTU Malware PCAP
  → Docker Zeek → JSON dns.log → Python ingestion → PostgreSQL
  → lexical + UTC minute features → four rules → explainable alerts
  → provenance-based reporting views → Apache Superset
```

## Stack and prerequisites

Python **>=3.11**, psycopg 3, PostgreSQL 17, digest-pinned official Zeek 9.0.1 and Apache Superset 6.1.0 images, Docker Compose v2, pytest and Git. Use Linux/WSL with Docker access, Python venv and curl. Reserve loopback **55434** (analytics) and **8089** (Superset); allow several GB for container images. Superset metadata has its own PostgreSQL volume and no published database port.

## Data sources

- [CTU-Normal-4-only-DNS](https://mcfp.felk.cvut.cz/publicDatasets/CTU-Normal-4-only-DNS/): `2015-03-24_capture1-only-dns.pcap`.
- [CTU-Malware-Capture-Botnet-25-3](https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-25-3/): `2014-02-07_capture-win3.pcap`.

Publisher: Stratosphere Laboratory, CTU in Prague / Malware Capture Facility Project. PCAPs are downloaded separately, never committed. [Provenance and findings](docs/public_dns_dataset_analysis.md) provide recorded SHA-256 values, attribution and label limitations. No local capture or generated traffic is needed.

## Quick start

From a clone of this repository:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
cp -n .env.example .env.ctu
```

Fill all blank secrets and the admin username using the non-printing recipe in the [reproduction guide](docs/reproduction_guide.md). Keep endpoint/database/owner values from the template. Always use the explicit `.env.ctu`; never commit it.

Download only the allowlisted PCAP/README/capinfos files and process the captures independently:

```bash
mkdir -p data/processed/ctu
cp docs/public_datasets/provenance.json data/processed/ctu/download-provenance.json
.venv/bin/python -m dns_security_analytics.analysis.public_datasets download \
  --manifest data/processed/ctu/download-provenance.json
./scripts/process_pcap.sh data/raw/pcap/public/normal/2015-03-24_capture1-only-dns.pcap
./scripts/process_pcap.sh data/raw/pcap/public/malware/2014-02-07_capture-win3.pcap
```

Each Zeek invocation prints a new log directory. Follow the guide's extraction-manifest recipe to record these actual directories and SHA-256 values in `data/processed/ctu/extraction.json`. Zeek UIDs/log hashes change across fresh extractions. On a fresh database:

```bash
docker compose --env-file .env.ctu -f compose.yaml config --quiet
docker compose --env-file .env.ctu -f compose.yaml up -d postgres
.venv/bin/python -m dns_security_analytics.analysis.ctu --env-file .env.ctu \
  --extraction data/processed/ctu/extraction.json
```

The guarded runner verifies cluster identity, accepted PCAP/log hashes and cross-capture minute isolation before delegating to existing ingestion/features/detection. It runs the pipeline twice and checks persisted-row idempotency. Source SHA-256 plus line number supplies provenance and deduplication, never timestamp-based capture labels. Reuse the same extraction for replay. Only developers with the retained accepted logs may omit `--extraction` and use the committed reference manifest.

## Detection rules

All comparisons are inclusive and operate per source IP / UTC minute. Multiple types may match one window.

| Type | Conditions | Severity |
|---|---|---|
| HIGH_DNS_FREQUENCY | query_count >=100 | MEDIUM |
| HIGH_NXDOMAIN_RATIO | query_count >=20; nxdomain_ratio >=0.50 | MEDIUM |
| DGA_LIKE | query_count >=20; unique_domain_count >=20; nxdomain_ratio >=0.50; avg_entropy >=4.0 | HIGH |
| TUNNEL_LIKE | query_count >=20; unique_domain_count >=20; avg_domain_length >=60; avg_entropy >=4.0 | HIGH |

Versioned configuration: [default_rules.json](src/dns_security_analytics/detection/default_rules.json). Thresholds originated in an earlier controlled synthetic calibration and were held fixed for CTU. That historical experiment is not part of the current application. Features, evidence, configuration hashing and stale-alert synchronization are described in the [project summary](docs/project_summary.md).

## Superset

Apply live views and provision the read-only analytics role before starting the UI:

```bash
docker compose --env-file .env.ctu -f compose.yaml exec -T postgres \
  sh -c 'psql -X -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB"' \
  < sql/reporting/001_ctu_views.sql
./scripts/configure_superset_reader.sh
docker compose --env-file .env.ctu -f compose.yaml build superset-init
docker compose --env-file .env.ctu -f compose.yaml up -d superset-db
docker compose --env-file .env.ctu -f compose.yaml run --rm superset-init
docker compose --env-file .env.ctu -f compose.yaml up -d superset
docker compose --env-file .env.ctu -f compose.yaml run --rm --no-deps \
  -v "$PWD/infra/superset:/app/dashboard-setup:ro" \
  -v "$PWD/infra/superset/assets:/assets:ro" \
  superset-init python /app/dashboard-setup/dashboard_assets.py import
```

Login at [localhost:8089](http://localhost:8089) with your private admin credentials. Three dashboards use **21 charts and 6 datasets**:

- [DNS Traffic Overview](http://localhost:8089/superset/dashboard/dns-traffic-overview/): capture volumes, response/query types, queried names, sources and activity distribution.
- [DNS Security & Anomaly Analysis](http://localhost:8089/superset/dashboard/dns-security-anomaly-analysis/): overlapping alerts, source/capture comparisons and explainable evidence.
- [CTU Security Comparison](http://localhost:8089/superset/dashboard/ctu-security-comparison/): descriptive activation rates and actual feature distributions.

[Superset documentation](docs/superset.md) covers registration, native filters, reusable metrics, sanitized export/import, health checks and troubleshooting. Analytical connections use Docker service networking and a read-only PostgreSQL role; metadata is separate from facts.

## Dashboard previews

Screenshot placeholders for the public README (no screenshots or captured query data are included yet):

| Dashboard | Preview to add after sanitization |
|---|---|
| DNS Traffic Overview | Capture comparison, response codes and activity distribution |
| DNS Security & Anomaly Analysis | Alert types and explainable evidence, with private UI details removed |
| CTU Security Comparison | Descriptive detector activation and feature summaries |

## Verified reference results

| Capture | DNS events / lexical rows | Source-minute windows | Frequency alerts | NXDOMAIN alerts | DGA-like alerts | Tunnel-like alerts |
|---|---:|---:|---:|---:|---:|---:|
| CTU Normal |3029|110|4|0|0|0|
| CTU Malware |2680|73|0|67|64|0|
| Total |5709|183|4|67|64|0|

**5,709 CTU DNS events, 183 source-minute windows, 135 alert records, and 71 distinct alerting windows** across **3 Superset dashboards**. DGA_LIKE activated in **64 of 73 CTU Malware windows (87.67%)**. This is a descriptive activation rate, not confirmed precision, recall or F1; 64 windows have overlapping NXDOMAIN/DGA-like alerts. These observations are not hardcoded acceptance targets. See the [release audit](docs/release_audit.md) for actual verification and test results.

```bash
.venv/bin/python -m pytest -q
.venv/bin/python scripts/test_isolated.py --extraction data/processed/ctu/extraction.json
docker compose --env-file .env.ctu -f compose.yaml exec -T postgres \
  sh -c 'psql -X -U "$POSTGRES_USER" -d "$POSTGRES_DB"' < scripts/verify_ctu.sql
curl --fail http://localhost:8089/health
```

Mutating integration tests use a newly named test database; CTU fact checks are read-only. Ordinary shutdown preserves volumes:

```bash
docker compose --env-file .env.ctu -f compose.yaml stop
```

## Limitations and security

- Publisher capture/tuple labels are insufficient for verified event/window truth. Results are **descriptive detector activation**, not CTU precision/recall/F1 or confirmed true/false positives.
- Preserve the malware capture's recorded **1970 timestamps**. Their actual calendar meaning is unknown; do not correct them from filenames or merge them into a misleading continuous timeline with 2015 traffic.
- High entropy/NXDOMAIN/frequency alone does not prove an attack. Small captures and fixed historical thresholds limit generalization.
- Never resolve captured domains, contact captured endpoints, or execute captured content. Zeek runs offline with networking disabled and raw input read-only.
- Secrets, PCAP/log bytes, generated reports, caches and backups stay outside Git. This loopback-only academic deployment is not a hardened Internet-facing service. Do not delete data or volumes as part of routine setup/shutdown.

## License and attribution

Original project source code is licensed under the [MIT License](LICENSE), copyright (c) 2026 **Luka Šućur**. Dependencies, container images and CTU datasets retain their own terms; see [third-party notices](THIRD_PARTY_NOTICES.md). MIT does **not** grant redistribution rights for CTU PCAPs. Preserve Stratosphere attribution, consult publisher terms, and download datasets separately.

Detailed guides: [reproduction](docs/reproduction_guide.md), [technical summary](docs/project_summary.md), [CTU findings/provenance](docs/public_dns_dataset_analysis.md), [Superset](docs/superset.md), [presentation](docs/demo_guide.md), [release audit](docs/release_audit.md).
