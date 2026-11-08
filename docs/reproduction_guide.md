# CTU-only reproduction guide

Run commands from the repository root. Only the two public CTU captures are required. For a history-free source export, initialize a new Git repository and make the initial source commit before running the primary CTU CLI: its provenance guard compares core files with `HEAD`. Follow the publication checklist; do not import the old repository history. Verification scope and release limitations are documented in [release_audit.md](release_audit.md).

## Prerequisites and environment

Git, Docker Desktop/Engine with Compose v2, Python >=3.11 with venv, curl, and sufficient disk for images (several GB) are required. Reserve loopback port 55434 for guarded analytics and 8089 for Superset; PostgreSQL metadata has no host port. Approximately 4 GB Docker memory is a reasonable starting point, not a benchmark. Linux/WSL paths and Docker access must work (`docker info`).

```bash
git clone <your-repository-url> dns-security-analytics
cd dns-security-analytics
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
cp -n .env.example .env.ctu
```

Fill blank secrets once, without displaying them:

```bash
.venv/bin/python - <<'PYENV'
from pathlib import Path
import secrets
p=Path('.env.ctu')
s=p.read_text()
for key in ('CTU_PASSWORD','SUPERSET_METADATA_PASSWORD','SUPERSET_SECRET_KEY','SUPERSET_ANALYTICS_PASSWORD','SUPERSET_ADMIN_PASSWORD'):
    s=s.replace(key+'=\n',key+'='+secrets.token_hex(32)+'\n')
s=s.replace('SUPERSET_ADMIN_USER=\n','SUPERSET_ADMIN_USER=ctu_admin\n')
p.write_text(s)
p.chmod(0o600)
PYENV
```

Keep `.env.ctu` private. Always pass it explicitly to Compose. CTU endpoint/database/owner are intentionally fixed by the guard; choose another free host environment rather than bypassing it. SUPERSET_PORT is configurable. Changing passwords in a file does not rotate credentials inside existing volumes; review rotation separately. Unset PG* libpq overrides before running the CTU CLI.

## Public captures and Zeek

Sources and attribution: [CTU Normal](https://mcfp.felk.cvut.cz/publicDatasets/CTU-Normal-4-only-DNS/) and [CTU Malware](https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-25-3/). See public_dns_dataset_analysis.md for accepted hashes, labels and usage limitations. Download only the allowlisted PCAP/README/capinfos files:

```bash
mkdir -p data/processed/ctu
cp docs/public_datasets/provenance.json data/processed/ctu/download-provenance.json
.venv/bin/python -m dns_security_analytics.analysis.public_datasets download \
  --manifest data/processed/ctu/download-provenance.json
./scripts/process_pcap.sh data/raw/pcap/public/normal/2015-03-24_capture1-only-dns.pcap
./scripts/process_pcap.sh data/raw/pcap/public/malware/2014-02-07_capture-win3.pcap
```

Zeek uses the official digest-pinned 9.0.1 image, input mounted read-only, `--network none`, JSON logging, independent `data/zeek/run-*` directories and host UID/GID. No host Zeek installation. Do not resolve extracted names. No binaries are downloaded or executed.

Existing accepted logs can use docs/public_datasets/extraction.json unchanged. New Zeek runs have new directories and UIDs, hence different log hashes. On a **fresh** CTU database, accept their actual identity in a generated manifest using the two printed output directories (replace NORMAL_DIRECTORY / MALWARE_DIRECTORY below):

```bash
.venv/bin/python - <<'PYMANIFEST'
import hashlib,json
from pathlib import Path
p=Path('docs/public_datasets/extraction.json')
doc=json.loads(p.read_text())
for name,directory in [('normal','NORMAL_DIRECTORY'),('malware','MALWARE_DIRECTORY')]:
    log=Path(directory)/'dns.log'
    doc['datasets'][name]['zeek_output_directory']=str(log.parent.relative_to(Path.cwd())) if log.is_absolute() else str(log.parent)
    doc['datasets'][name]['dns_log_sha256']=hashlib.sha256(log.read_bytes()).hexdigest()
Path('data/processed/ctu/extraction.json').write_text(json.dumps(doc,indent=2)+'\n')
PYMANIFEST
```

The runner independently verifies PCAP bytes against committed provenance and every JSON line. Do not substitute a fresh extraction into an already populated registry: it intentionally refuses a changed capture identity. Reuse the same logs for idempotent replay; retain both PCAP and extraction manifest. No timestamps are corrected.

## PostgreSQL and guarded pipeline

```bash
docker compose --env-file .env.ctu -f compose.yaml config --quiet
docker compose --env-file .env.ctu -f compose.yaml up -d postgres
docker compose --env-file .env.ctu -f compose.yaml ps
.venv/bin/python -m dns_security_analytics.analysis.ctu --env-file .env.ctu \
  --extraction data/processed/ctu/extraction.json
```

For the retained accepted logs omit `--extraction`. Initialization applies sql/init/001 through 006 in filename order on a fresh volume only. The existing ingestion, lexical, SQL minute aggregation and detector implementations run twice; full persisted-row fingerprints must agree. Source SHA-256 plus one-based line identity deduplicates events. Registry/FK exclude unknown captures. Preflight rejects any cross-capture `(source_ip, UTC minute)` collision before insertion. Shared IPs in disjoint minutes are allowed; current sources have no ambiguous windows. The guard checks project, port, named volume, database marker and PostgreSQL system identifier. Output is ignored data/processed/ctu/summary.json, including actual counts, configuration and source hashes, completeness, replay statistics and per-window evidence.

Use the guarded CTU runner for normal operation. It delegates to the existing ingestion/feature/detection functions; no historical datasets, ground truth or experiment reports are required.

## Reporting and Superset

```bash
docker compose --env-file .env.ctu -f compose.yaml exec -T postgres \
  sh -c 'psql -X -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB"' \
  < sql/reporting/001_ctu_views.sql
./scripts/configure_superset_reader.sh
docker compose --env-file .env.ctu -f compose.yaml build superset-init
docker compose --env-file .env.ctu -f compose.yaml up -d superset-db
docker compose --env-file .env.ctu -f compose.yaml run --rm superset-init
docker compose --env-file .env.ctu -f compose.yaml up -d superset
```

The read-only reader role and owner use different secrets. Metadata PostgreSQL and volume are isolated from analytics. Superset metadata upgrades, permissions, admin and saved connection initialize reproducibly. `up superset` also runs its idempotent init dependency. Initialization does not import dashboards automatically.

Use the lifecycle commands in docs/superset.md to import sanitized assets (or regenerate from definitions) and verify every query. Login at http://localhost:8089 with the private `.env.ctu` admin. No connection password belongs in an export.

## Verification

```bash
.venv/bin/python -m pytest -q
.venv/bin/python scripts/test_isolated.py --extraction data/processed/ctu/extraction.json
# Repeat the same guarded pipeline command above; compare first/second summaries.
docker compose --env-file .env.ctu -f compose.yaml exec -T postgres \
  sh -c 'psql -X -U "$POSTGRES_USER" -d "$POSTGRES_DB"' < scripts/verify_ctu.sql
curl --fail http://localhost:8089/health
```

The integration runner creates `dns_ctu_tests_<random>` in the guarded cluster, applies unchanged core 001–005 for isolated fixtures, and never mutates active analytics. CTU provenance/view checks are read-only. Pass the same `--extraction` manifest used by the pipeline so read-only checks do not require another machine's reference log directories. Omit it only when using the retained reference extraction. Extra pytest options, such as `--tb=short`, are forwarded. Test databases are retained for explicit cleanup. Generic test modules must never receive credentials for an analytical database.

Referential integrity, provenance, alert overlaps, row grains and per-detector denominators are inspected in scripts/verify_ctu.sql. Superset verify.py tests ACL denial even after disabling the role's default read-only flag; dataset tests inspect all six view privileges. Expected observed totals: 5709/5709/183/135, not hardcoded acceptance logic. CTU has no formal evaluation artifact or metrics. Check metadata, 3 dashboards, 21 charts and 6 datasets through the REST lifecycle verify and browser, not internal metadata writes.

## Troubleshooting and shutdown

- Docker unavailable: start Desktop, check WSL integration/context and `docker info`.
- Port conflict: inspect existing projects; do not stop/delete another project's resources implicitly. The guarded DB requires 55434; web port is configurable.
- Connection errors: wait for `postgres` health, verify explicit `.env.ctu`; no `localhost` in container database URIs (use `postgres` / `superset-db`).
- Missing Python dependency: activate/use `.venv`, install `-e '.[dev]'`; Superset requests/YAML/psycopg2 run inside its image.
- Env error: fill every blank required field; use literal safe random secrets, do not print `compose config` with secrets (use `--quiet`).
- Zeek permission problem: keep PCAP under data/raw/pcap, readable by your UID; create output on a Linux filesystem writable by that UID.
- Missing logs: inspect Zeek stderr and actual newly printed directory; do not guess a run-* path.
- Superset startup: inspect `docker compose --env-file .env.ctu -f compose.yaml logs --tail=80 superset`; review logs privately. Run init successfully before web.
- Missing datasets/charts: apply views, reader provision, metadata initialization, then asset import and query verification in that order.
- Changed accepted hashes/foreign data: stop and investigate; never clear a database or bypass the guard to make a run pass.

Ordinary shutdown, preserving all volumes:

```bash
docker compose --env-file .env.ctu -f compose.yaml stop
# Restart using the documented up commands.
```

`down` removes project containers/network but retains named volumes when used without volume deletion. Never use volume deletion as routine shutdown. No volume or dataset deletion is part of these commands. Back up private configuration and volumes independently; do not publish backups. See release_audit.md for what was actually verified.
