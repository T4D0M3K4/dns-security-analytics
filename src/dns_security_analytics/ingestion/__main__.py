"""Run with python -m dns_security_analytics.ingestion."""

import argparse
from dataclasses import asdict
import json
import logging
from pathlib import Path

import psycopg

from .dns import connection_settings, ingest


def main() -> int:
    parser = argparse.ArgumentParser(description="Ingest a Zeek JSON dns.log into PostgreSQL")
    parser.add_argument("source", type=Path, help="explicit path to newline-delimited JSON dns.log")
    parser.add_argument("--batch-size", type=int, default=500, help="records per batch (default: 500)")
    args = parser.parse_args()
    if args.batch_size < 1:
        parser.error("--batch-size must be positive")
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")
    try:
        summary = ingest(args.source, connection_settings(), args.batch_size)
    except (OSError, ValueError, psycopg.Error) as exc:
        # Do not expose connection strings, passwords, or database row contents.
        logging.error("Ingestion failed (%s); no rows from this invocation were committed", type(exc).__name__)
        if isinstance(exc, ValueError):
            logging.error("%s", exc)
        return 1
    print(json.dumps(asdict(summary)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
