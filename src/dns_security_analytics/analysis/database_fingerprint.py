"""Read-only preservation check, separate from the CTU pipeline runner."""

import argparse
import json
from pathlib import Path

import psycopg

from dns_security_analytics.ingestion.dns import connection_settings

TABLES = {"public.dns_events": "id", "public.dns_event_features": "dns_event_id",
          "public.dns_window_features": "source_ip,window_start", "public.dns_alerts": "id"}


def fingerprint(settings: dict[str, str]) -> dict:
    """Force read-only on connection startup, including every SQL statement."""
    result = {}
    readonly = {**settings, "options": "-c default_transaction_read_only=on -c timezone=UTC"}
    with psycopg.connect(**readonly, connect_timeout=10) as c:
        c.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        for table, key in TABLES.items():
            if c.execute("SELECT to_regclass(%s)", (table,)).fetchone()[0] is None:
                continue
            count, digest = c.execute(
                f"SELECT count(*),md5(string_agg(row_to_json(t)::text,E'\\n' ORDER BY {key})) FROM {table} t"
            ).fetchone()
            result[table] = {"rows": count, "full_row_md5": digest}
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--compare", type=Path)
    args = parser.parse_args()
    result = fingerprint(connection_settings())
    if args.compare and result != json.loads(args.compare.read_text()):
        parser.exit(1, "Database fingerprints differ; no repair/reset attempted.\n")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
