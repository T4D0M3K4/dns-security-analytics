"""Run with python -m dns_security_analytics.detection."""

import argparse
from dataclasses import asdict
import json
from pathlib import Path
import sys

import psycopg

from dns_security_analytics.ingestion.dns import connection_settings
from .config import load_config
from .database import detect


def main() -> int:
    parser = argparse.ArgumentParser(description="Synchronize explainable DNS alerts using configured rules")
    parser.add_argument("--config", type=Path, help="JSON rules (default: packaged seed42-initial-v1)")
    parser.add_argument("--batch-size", type=int, default=500)
    args = parser.parse_args()
    if args.batch_size < 1:
        parser.error("--batch-size must be positive")
    try:
        summary = detect(connection_settings(), load_config(args.config), args.batch_size)
    except (OSError, ValueError, TypeError, psycopg.Error) as exc:
        print(f"Detection failed ({type(exc).__name__}); alert synchronization rolled back", file=sys.stderr)
        if isinstance(exc, ValueError):
            print(str(exc), file=sys.stderr)
        return 1
    print(json.dumps(asdict(summary)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
