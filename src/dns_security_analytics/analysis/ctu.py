"""Active guarded CTU pipeline. Never accepts legacy connection settings."""

import argparse
from collections import Counter
from dataclasses import asdict
from datetime import datetime
import json
import os
from pathlib import Path
import re
import subprocess
from typing import Any

import psycopg
from psycopg.rows import dict_row

from dns_security_analytics.detection.config import load_config
from dns_security_analytics.detection.database import detect
from dns_security_analytics.detection.rules import METRICS, evaluate_window
from dns_security_analytics.features.database import compute_features
from dns_security_analytics.features.windows import compute_window_features
from dns_security_analytics.ingestion.dns import ingest
from .database_fingerprint import fingerprint
from .public_datasets import distribution, sha256, write_json
from dns_security_analytics.transformation.dns import parse_dns_line

ROOT = Path(__file__).resolve().parents[3]
PROJECT = "dns-ctu"
MARKER = "dns-security-analytics:ctu-only:v1"
CAPTURES = ("normal", "malware")
PIPELINE = ["ingestion/dns.py", "transformation/dns.py", "features/lexical.py", "features/database.py",
            "features/windows.py", "detection/config.py", "detection/rules.py", "detection/database.py",
            "detection/default_rules.json"]


def read_environment(path: Path) -> dict[str, str]:
    """Explicit literal env file; no shell evaluation, expansion or demo fallback."""
    values = {}
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if not separator or key in values or not re.fullmatch(r"[A-Z_]+", key):
            raise ValueError("Invalid/duplicate CTU environment entry")
        values[key] = value
    return values


def ctu_settings(values: dict[str, str]) -> dict[str, str]:
    fixed = {"CTU_HOST": "127.0.0.1", "CTU_PORT": "55434",
             "CTU_DB": "dns_ctu", "CTU_USER": "dns_ctu_owner"}
    if not {*fixed, "CTU_PASSWORD"} <= set(values) or any(not k.startswith(("CTU_", "SUPERSET_")) for k in values) or any(values.get(k) != v for k, v in fixed.items()):
        raise ValueError("Refusing endpoint/name override: use only the dedicated CTU environment")
    password = values["CTU_PASSWORD"]
    if not re.fullmatch(r"[A-Za-z0-9_-]{32,}", password) or password.startswith("REPLACE"):
        raise ValueError("Set a distinct random CTU password (32+ literal safe characters)")
    # libpq environment indirection must not influence new pipeline connections.
    if any(key.startswith("PG") for key in os.environ):
        raise ValueError("Unset PG* environment overrides before CTU processing")
    return {"host": fixed["CTU_HOST"], "hostaddr": "127.0.0.1", "port": fixed["CTU_PORT"],
            "dbname": fixed["CTU_DB"], "user": fixed["CTU_USER"], "password": password,
            "options": "-c timezone=UTC"}


def check_container(document: dict) -> str:
    labels = document["Config"].get("Labels", {})
    if labels.get("com.docker.compose.project") != PROJECT or labels.get("com.docker.compose.service") != "postgres":
        raise ValueError("Refusing container outside isolated Compose project")
    mounts = document["Mounts"]
    if not any(m.get("Name") == PROJECT + "_postgres_data" and
               m["Destination"] == "/var/lib/postgresql/data" for m in mounts):
        raise ValueError("Refusing unexpected PostgreSQL data volume")
    if document["NetworkSettings"]["Ports"].get("5432/tcp") != [{"HostIp": "127.0.0.1", "HostPort": "55434"}]:
        raise ValueError("Refusing unexpected published database endpoint")
    return document["Id"]


def guard(settings: dict[str, str], env_file: Path) -> dict:
    """Tie host connection to this Docker cluster before any pipeline mutation."""
    command = ["docker", "compose", "--project-name", PROJECT, "--env-file", str(env_file),
               "-f", str(ROOT / "compose.yaml"), "ps", "-q", "postgres"]
    container = subprocess.check_output(command, text=True).strip()
    if not container or "\n" in container:
        raise ValueError("Exactly one running CTU container is required")
    document = json.loads(subprocess.check_output(["docker", "inspect", container], text=True))[0]
    identifier = check_container(document)
    cluster = subprocess.check_output([
        "docker", "exec", identifier, "psql", "-XAt", "-U", "dns_ctu_owner", "-d", "dns_ctu",
        "-c", "SELECT system_identifier::text FROM pg_control_system()",
    ], text=True).strip()
    with psycopg.connect(**settings, connect_timeout=10) as c:
        c.execute("SET TRANSACTION READ ONLY")
        database, user, actual, marker = c.execute("""
            SELECT current_database(), current_user,
                   (SELECT system_identifier::text FROM pg_control_system()),
                   shobj_description(oid,'pg_database') FROM pg_database WHERE datname=current_database()
        """).fetchone()
        if (database, user, actual, marker) != ("dns_ctu", "dns_ctu_owner", cluster, MARKER):
            raise ValueError("Isolation identity mismatch; pipeline refused")
    return {"compose_project": PROJECT, "container_id": identifier, "cluster_identifier": cluster,
            "database": database, "user": user, "host": "127.0.0.1", "port": 55434, "marker": marker}


def source_identity() -> dict:
    """Require committed core behavior; fingerprint active infrastructure."""
    result = {}
    for relative in PIPELINE:
        name = "src/dns_security_analytics/" + relative
        path = ROOT / name
        committed = subprocess.check_output(["git", "show", "HEAD:" + name], cwd=ROOT)
        if path.read_bytes() != committed:
            raise ValueError("Uncommitted pipeline/configuration change: " + name)
        result[name] = sha256(path)
    infrastructure = [Path(__file__).resolve(), ROOT / "compose.yaml", ROOT / "infra/ctu/init.sh",
                      ROOT / "infra/superset/dashboard_assets.py", ROOT / "infra/superset/dashboard_definitions.py"]
    infrastructure += sorted((ROOT / "sql/init").glob("*.sql"))
    infrastructure += sorted((ROOT / "sql/reporting").glob("*.sql"))
    result.update({str(p.relative_to(ROOT)): sha256(p) for p in infrastructure})
    return {"git_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
            "files_sha256": result}


def inputs(extraction_path: Path = ROOT / "docs/public_datasets/extraction.json") -> dict[str, dict]:
    extraction = json.loads(extraction_path.read_text())
    provenance = json.loads((ROOT / "docs/public_datasets/provenance.json").read_text())
    pcaps = {item["path"]: item for item in provenance["files"] if item["path"].endswith(".pcap")}
    result = {}
    for capture in CAPTURES:
        item = extraction["datasets"][capture]
        log = ROOT / item["zeek_output_directory"] / "dns.log"
        pcap = ROOT / item["pcap"]
        with log.open("rb") as stream:
            lines = sum(1 for _ in stream)
        if sha256(log) != item["dns_log_sha256"] or sha256(pcap) != pcaps[item["pcap"]]["sha256"]:
            raise ValueError("Source differs from accepted extraction: " + capture)
        result[capture] = {"log_path": str(log.relative_to(ROOT)), "source_sha256": sha256(log),
                           "pcap_path": item["pcap"], "pcap_sha256": sha256(pcap), "events_expected": lines}
    return result


def capture_for_window(hashes: list[str], sources: dict[str, dict]) -> str | None:
    if len(hashes) != 1:
        return None
    return next((name for name, item in sources.items() if item["source_sha256"] == hashes[0]), None)


def preflight(sources: dict) -> None:
    owners = {}
    for capture, item in sources.items():
        with (ROOT / item["log_path"]).open() as stream:
            for line in stream:
                event = parse_dns_line(line)
                key = (event.source_ip, event.event_timestamp.replace(second=0, microsecond=0))
                if key in owners and owners[key] != capture:
                    raise ValueError("Cross-capture source/minute collision; no data inserted")
                owners[key] = capture


def pipeline(settings: dict[str, str], sources: dict, env_file: Path) -> dict:
    guard(settings, env_file)
    with psycopg.connect(**settings) as c:
        c.execute("SET TRANSACTION READ ONLY")
        known = {item["source_sha256"] for item in sources.values()}
        observed = {row[0] for row in c.execute("SELECT DISTINCT source_sha256 FROM public.dns_events")}
        if not observed <= known:
            raise ValueError("Foreign or fixture data in CTU database; refusing pipeline")
    return {"ingestion": {name: asdict(ingest(ROOT / item["log_path"], settings)) for name, item in sources.items()},
            "lexical": asdict(compute_features(settings)), "windows": asdict(compute_window_features(settings)),
            "detection": asdict(detect(settings, load_config()))}


def describe(rows: list[dict], event_count: int, config) -> dict:
    counts = Counter(alert["alert_type"] for row in rows for alert in row["alerts"])
    dga = next(rule for rule in config.rules if rule.alert_type == "DGA_LIKE")
    for row in rows:
        row["dga_condition_evidence"] = [{"metric": key, "operator": ">=", "threshold": threshold,
            "observed": row[key], "satisfied": row[key] is not None and row[key] >= threshold}
            for key, threshold in dga.conditions]
        # Reporting cross-check delegates all alert decisions to the existing evaluator.
        if {a.alert_type for a in evaluate_window(row, config)} != {a["alert_type"] for a in row["alerts"]}:
            raise ValueError("Persisted alerts differ from existing rule evaluator")
    failing = Counter(item["metric"] for row in rows for item in row["dga_condition_evidence"] if not item["satisfied"])
    return {"events": event_count, "windows": len(rows), "alerts": sum(counts.values()),
        "alerts_by_type": {rule.alert_type: {"alert_count": counts[rule.alert_type],
            "windows": counts[rule.alert_type], "percentage_of_windows": 100 * counts[rule.alert_type] / len(rows) if rows else 0.0}
            for rule in config.rules},
        "multi_alert_windows": sum(len(row["alerts"]) > 1 for row in rows),
        "dga_failed_condition_windows": dict(failing),
        "distributions": {key: distribution([row[key] for row in rows if row[key] is not None]) for key in METRICS},
        "windows_detail": rows}


def analyze(settings: dict[str, str], sources: dict) -> dict:
    config = load_config()
    captures = {name: [] for name in sources}
    ambiguous = []
    with psycopg.connect(**settings, row_factory=dict_row) as c:
        c.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        rows = c.execute("""
            WITH membership AS (
                SELECT source_ip, date_trunc('minute',event_timestamp,'UTC') AS window_start,
                       array_agg(DISTINCT source_sha256) AS hashes, count(*) AS event_count
                FROM public.dns_events GROUP BY source_ip,date_trunc('minute',event_timestamp,'UTC')
            ) SELECT host(w.source_ip) AS source_ip, w.window_start, w.window_end,
                     m.hashes,m.event_count,""" + ",".join("w." + key for key in METRICS) + """
                FROM public.dns_window_features w JOIN membership m USING(source_ip,window_start)
                ORDER BY w.source_ip,w.window_start
        """).fetchall()
        alerts = c.execute("SELECT host(source_ip) AS source_ip,window_start,alert_type,severity,reasons,observed_metrics,config_sha256 FROM public.dns_alerts").fetchall()
        for row in rows:
            if row["query_count"] != row["event_count"]:
                raise ValueError("Window event count differs from raw source membership")
            row["alerts"] = [a for a in alerts if (a["source_ip"], a["window_start"]) == (row["source_ip"], row["window_start"])]
            capture = capture_for_window(row["hashes"], sources)
            (captures[capture] if capture else ambiguous).append(row)
        result = {"ambiguous_or_unknown_windows": ambiguous, "captures": {}}
        for name, data in captures.items():
            identity = sources[name]
            completeness = c.execute("""
                SELECT count(*) AS events,count(DISTINCT source_line) AS distinct_lines,
                       min(source_line) AS first_line,max(source_line) AS last_line,
                       min(event_timestamp) AS first_timestamp,max(event_timestamp) AS last_timestamp
                FROM public.dns_events WHERE source_sha256=%s
            """, (identity["source_sha256"],)).fetchone()
            if (completeness["events"], completeness["distinct_lines"], completeness["first_line"], completeness["last_line"]) != (
                    identity["events_expected"], identity["events_expected"], 1, identity["events_expected"]):
                raise ValueError("Source line coverage is incomplete or inconsistent")
            if c.execute("""
                SELECT 1 FROM public.dns_events e LEFT JOIN public.dns_event_features f ON f.dns_event_id=e.id
                WHERE source_sha256=%s AND e.query IS NOT NULL AND f.dns_event_id IS NULL LIMIT 1
            """, (identity["source_sha256"],)).fetchone():
                raise ValueError("Missing lexical rows")
            summary = describe(data, completeness["events"], config)
            summary["completeness"] = completeness
            summary["sources"] = {}
            for source in sorted({row["source_ip"] for row in data}):
                selected = [row for row in data if row["source_ip"] == source]
                summary["sources"][source] = describe(selected, sum(row["event_count"] for row in selected), config)
            result["captures"][name] = summary
        return result


def json_ready(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, dict):
        return {key: json_ready(item) for key, item in value.items()}
    if isinstance(value, list):
        return [json_ready(item) for item in value]
    return value


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env-file", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=Path("data/processed/ctu/summary.json"))
    parser.add_argument("--extraction", type=Path, default=ROOT / "docs/public_datasets/extraction.json",
                        help="Accepted extraction manifest; use a generated copy for a fresh Zeek run")
    args = parser.parse_args()
    if not args.output.resolve().is_relative_to(ROOT / "data/processed/ctu"):
        parser.error("--output must be under data/processed/ctu")
    settings = ctu_settings(read_environment(args.env_file))
    config, code, sources = load_config(), source_identity(), inputs(args.extraction)
    preflight(sources)
    identity = guard(settings, args.env_file)
    with psycopg.connect(**settings) as connection:
        for capture, item in sources.items():
            existing = connection.execute("SELECT source_sha256,pcap_sha256 FROM public.ctu_captures WHERE capture=%s", (capture,)).fetchone()
            if existing and existing != (item["source_sha256"],item["pcap_sha256"]):
                raise ValueError("A capture already has another accepted extraction; use reviewed migration")
            connection.execute("INSERT INTO public.ctu_captures(capture,source_sha256,pcap_sha256) VALUES (%s,%s,%s) ON CONFLICT DO NOTHING", (capture,item["source_sha256"],item["pcap_sha256"]))
    first = pipeline(settings, sources, args.env_file)
    before = fingerprint(settings)
    second = pipeline(settings, sources, args.env_file)
    after = fingerprint(settings)
    if before != after:
        raise ValueError("Replay changed persisted event/feature/alert rows")
    if inputs(args.extraction) != sources or source_identity() != code:
        raise ValueError("Source or pipeline changed during CTU processing")
    report = {"format_version": 1, "purpose": "CTU descriptive detector activation; no verified window intent labels",
              "isolation": identity, "source_code": code, "sources": sources,
              "configuration": {"sha256": config.sha256, "snapshot": config.snapshot},
              "first_run": first, "second_run": second, "fingerprints_first": before,
              "fingerprints_second": after, "idempotent_rows": before == after, **analyze(settings, sources)}
    write_json(args.output, json_ready(report))
    print(json.dumps({name: {key: value for key, value in capture.items() if key in
        ("events", "windows", "alerts", "alerts_by_type", "multi_alert_windows", "dga_failed_condition_windows")}
        for name, capture in report["captures"].items()}, indent=2))


if __name__ == "__main__":
    main()
