"""Set-based one-minute DNS aggregation and its dedicated CLI."""

import argparse
from dataclasses import asdict, dataclass
import json
import logging
from time import perf_counter

import psycopg

from dns_security_analytics.ingestion.dns import connection_settings
from .lexical import normalize_query


# Only fixed, developer-controlled identifiers are interpolated into SQL.
METRICS = ("window_end", "query_count", "unique_domain_count", "nxdomain_count",
           "nxdomain_ratio", "avg_domain_length", "avg_digit_ratio", "avg_entropy", "max_entropy")
COLUMNS = ", ".join(("source_ip", "window_start", *METRICS))
CHANGED = "ROW(" + ", ".join(f"w.{name}" for name in METRICS) + ") IS DISTINCT FROM ROW(" + ", ".join(f"s.{name}" for name in METRICS) + ")"

AGGREGATE = """
CREATE TEMP TABLE window_stage ON COMMIT DROP AS
WITH events AS (
    SELECT *, date_trunc(%s, event_timestamp, %s) AS window_start
    FROM public.dns_events
)
SELECT e.source_ip,
       e.window_start,
       e.window_start + interval '1 minute' AS window_end,
       count(*) AS query_count,
       count(DISTINCT n.normalized_query COLLATE "C") AS unique_domain_count,
       count(*) FILTER (WHERE e.response_code = 3) AS nxdomain_count,
       COALESCE((count(*) FILTER (WHERE e.response_code = 3))::double precision
                / NULLIF(count(*), 0), 0.0) AS nxdomain_ratio,
       avg(f.domain_length)::double precision AS avg_domain_length,
       avg(f.digit_ratio::text::numeric)::double precision AS avg_digit_ratio,
       avg(f.entropy::text::numeric)::double precision AS avg_entropy,
       max(f.entropy) AS max_entropy
FROM events AS e
LEFT JOIN normalized_queries AS n ON e.query COLLATE "C" = n.query
LEFT JOIN public.dns_event_features AS f ON f.dns_event_id = e.id
GROUP BY e.source_ip, e.window_start
"""


@dataclass
class WindowSummary:
    raw_events_considered: int = 0
    windows_calculated: int = 0
    rows_inserted: int = 0
    rows_updated: int = 0
    rows_skipped: int = 0
    elapsed_seconds: float = 0.0


def compute_window_features(settings: dict[str, str], batch_size: int = 500) -> WindowSummary:
    """Refresh populated windows atomically from one consistent source snapshot."""
    if batch_size < 1:
        raise ValueError("batch size must be positive")
    started = perf_counter()
    summary = WindowSummary()
    with psycopg.connect(**settings, connect_timeout=10) as connection:
        with connection.cursor() as target:
            target.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            # Preserve float round-trip precision before exact decimal accumulation.
            target.execute("SET LOCAL extra_float_digits = 1")
            # Serialize window writers, without blocking raw event/lexical ingestion.
            target.execute("LOCK TABLE public.dns_window_features IN SHARE ROW EXCLUSIVE MODE")
            target.execute('CREATE TEMP TABLE normalized_queries (query text COLLATE "C", normalized_query text COLLATE "C") ON COMMIT DROP')
            with connection.cursor(name="distinct_window_queries") as source:
                source.execute('SELECT DISTINCT query COLLATE "C" FROM public.dns_events WHERE query IS NOT NULL')
                while rows := source.fetchmany(batch_size):
                    with target.copy("COPY normalized_queries (query, normalized_query) FROM STDIN") as copy:
                        for (query,) in rows:
                            copy.write_row((query, normalize_query(query)))
            target.execute("ANALYZE normalized_queries")
            target.execute(AGGREGATE, ("minute", "UTC"))
            target.execute(f"""
                SELECT COALESCE(sum(s.query_count), 0), count(*),
                       count(*) FILTER (WHERE w.source_ip IS NULL),
                       count(*) FILTER (WHERE w.source_ip IS NOT NULL AND {CHANGED})
                FROM window_stage AS s
                LEFT JOIN public.dns_window_features AS w USING (source_ip, window_start)
            """)
            considered, windows, inserted, updated = target.fetchone()
            summary.raw_events_considered = int(considered)
            summary.windows_calculated = windows
            summary.rows_inserted = inserted
            summary.rows_updated = updated
            summary.rows_skipped = windows - inserted - updated
            assignments = ", ".join(f"{name} = EXCLUDED.{name}" for name in METRICS)
            changed = CHANGED.replace("s.", "EXCLUDED.")
            target.execute(f"""
                INSERT INTO public.dns_window_features AS w ({COLUMNS})
                SELECT {COLUMNS} FROM window_stage
                ORDER BY source_ip, window_start
                ON CONFLICT (source_ip, window_start) DO UPDATE
                SET {assignments}, calculated_at = CURRENT_TIMESTAMP
                WHERE {changed}
            """)
    summary.elapsed_seconds = round(perf_counter() - started, 6)
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description="Compute one-minute per-source DNS window features")
    parser.add_argument("--batch-size", type=int, default=500, help="distinct queries fetched per batch (default: 500)")
    args = parser.parse_args()
    if args.batch_size < 1:
        parser.error("--batch-size must be positive")
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")
    try:
        summary = compute_window_features(connection_settings(), args.batch_size)
    except (ValueError, psycopg.Error) as exc:
        logging.error("Window computation failed (%s); no window rows from this run were committed", type(exc).__name__)
        if isinstance(exc, ValueError):
            logging.error("%s", exc)
        return 1
    print(json.dumps(asdict(summary)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
