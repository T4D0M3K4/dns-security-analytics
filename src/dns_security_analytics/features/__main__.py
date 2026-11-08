"""Run with python -m dns_security_analytics.features."""

import argparse
from dataclasses import asdict
import json
import logging

import psycopg

from dns_security_analytics.ingestion.dns import connection_settings
from .database import compute_features


def main() -> int:
    parser = argparse.ArgumentParser(description="Compute missing per-event DNS lexical features")
    parser.add_argument("--batch-size", type=int, default=500, help="events per batch (default: 500)")
    args = parser.parse_args()
    if args.batch_size < 1:
        parser.error("--batch-size must be positive")
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")
    try:
        summary = compute_features(connection_settings(), args.batch_size)
    except (ValueError, psycopg.Error) as exc:
        logging.error("Feature computation failed (%s); no feature rows from this run were committed", type(exc).__name__)
        if isinstance(exc, ValueError):
            logging.error("%s", exc)
        return 1
    print(json.dumps(asdict(summary)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
