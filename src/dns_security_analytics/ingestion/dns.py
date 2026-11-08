"""Stream Zeek DNS records into PostgreSQL in bounded batches."""

from dataclasses import dataclass
import hashlib
import logging
import os
from pathlib import Path
from time import perf_counter
from typing import Any

import psycopg

from dns_security_analytics.transformation.dns import parse_dns_line

LOGGER = logging.getLogger(__name__)
INSERT = """
INSERT INTO public.dns_events (
    event_timestamp, zeek_uid, source_ip, source_port, destination_ip,
    destination_port, transport_protocol, query, query_class, query_type,
    response_code, rejected, answers, ttls, source_sha256, source_line
) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
ON CONFLICT (source_sha256, source_line) DO NOTHING
"""


def connection_settings() -> dict[str, str]:
    """Require the project's POSTGRES_* environment variables explicitly."""
    mapping = {"host": "POSTGRES_HOST", "port": "POSTGRES_PORT",
               "dbname": "POSTGRES_DB", "user": "POSTGRES_USER",
               "password": "POSTGRES_PASSWORD"}
    missing = [name for name in mapping.values() if not os.environ.get(name)]
    if missing:
        raise ValueError("Missing environment variables: " + ", ".join(missing))
    return {key: os.environ[name] for key, name in mapping.items()}


@dataclass
class IngestionSummary:
    source_file: str
    records_read: int = 0
    records_inserted: int = 0
    records_rejected: int = 0
    records_skipped: int = 0
    elapsed_seconds: float = 0.0


def ingest(path: Path, settings: dict[str, str], batch_size: int = 500) -> IngestionSummary:
    """Commit a complete file atomically; malformed lines are warned and skipped."""
    if batch_size < 1:
        raise ValueError("batch size must be positive")
    started = perf_counter()
    summary = IngestionSummary(str(path.resolve()))
    with path.open("rb") as source:
        digest = hashlib.file_digest(source, "sha256").hexdigest()
        source.seek(0)
        observed = hashlib.sha256()
        with psycopg.connect(**settings, connect_timeout=10) as connection:
            with connection.cursor() as cursor:
                batch: list[tuple[Any, ...]] = []

                def flush() -> None:
                    if batch:
                        cursor.executemany(INSERT, batch)
                        summary.records_inserted += cursor.rowcount
                        summary.records_skipped += len(batch) - cursor.rowcount
                        batch.clear()

                for line_number, raw in enumerate(source, start=1):
                    observed.update(raw)
                    summary.records_read += 1
                    try:
                        event = parse_dns_line(raw.decode("utf-8"))
                    except (ValueError, RecursionError) as exc:
                        summary.records_rejected += 1
                        LOGGER.warning("%s:%d rejected: %s", path, line_number, exc)
                        continue
                    batch.append((*event.values(), digest, line_number))
                    if len(batch) >= batch_size:
                        flush()
                flush()
                if observed.hexdigest() != digest:
                    raise ValueError("Source file changed during ingestion; transaction rolled back")
    summary.elapsed_seconds = round(perf_counter() - started, 6)
    return summary
