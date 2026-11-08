"""Stream raw events and persist missing lexical feature rows."""

from dataclasses import dataclass
from time import perf_counter

import psycopg

from .lexical import calculate_features

SELECT_EVENTS = """
SELECT e.id, e.query, f.dns_event_id IS NOT NULL
FROM public.dns_events AS e
LEFT JOIN public.dns_event_features AS f ON f.dns_event_id = e.id
WHERE e.query IS NOT NULL
ORDER BY e.id
"""
INSERT_FEATURES = """
INSERT INTO public.dns_event_features
    (dns_event_id, domain_length, digit_count, digit_ratio, entropy)
VALUES (%s, %s, %s, %s, %s)
ON CONFLICT (dns_event_id) DO NOTHING
"""


@dataclass
class FeatureSummary:
    events_considered: int = 0
    rows_calculated: int = 0
    rows_inserted: int = 0
    rows_skipped: int = 0
    elapsed_seconds: float = 0.0


def compute_features(settings: dict[str, str], batch_size: int = 500) -> FeatureSummary:
    """Insert missing rows atomically, using a server-side cursor for bounded reads."""
    if batch_size < 1:
        raise ValueError("batch size must be positive")
    started = perf_counter()
    summary = FeatureSummary()
    with psycopg.connect(**settings, connect_timeout=10) as connection:
        with connection.cursor(name="dns_lexical_events") as source, connection.cursor() as target:
            source.execute(SELECT_EVENTS)
            while rows := source.fetchmany(batch_size):
                summary.events_considered += len(rows)
                batch = []
                for event_id, query, exists in rows:
                    if exists:
                        summary.rows_skipped += 1
                        continue
                    features = calculate_features(query)
                    batch.append((event_id, features.domain_length, features.digit_count,
                                  features.digit_ratio, features.entropy))
                summary.rows_calculated += len(batch)
                if batch:
                    target.executemany(INSERT_FEATURES, batch)
                    summary.rows_inserted += target.rowcount
                    summary.rows_skipped += len(batch) - target.rowcount
    summary.elapsed_seconds = round(perf_counter() - started, 6)
    return summary
