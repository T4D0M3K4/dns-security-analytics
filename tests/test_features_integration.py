"""Opt-in coverage against the existing local PostgreSQL service."""

import os
from uuid import uuid4

import psycopg
import pytest

from dns_security_analytics.features.database import compute_features
from dns_security_analytics.ingestion.dns import connection_settings


@pytest.mark.skipif(os.environ.get("RUN_DB_TESTS") != "1", reason="set RUN_DB_TESTS=1 for local PostgreSQL")
def test_feature_creation_and_replay() -> None:
    settings = connection_settings()
    uid = f"pytest-features-{uuid4()}"
    ids = []
    try:
        with psycopg.connect(**settings) as connection:
            for query in ("ChatGPT.COM.", "", None):
                event_id = connection.execute(
                    "INSERT INTO public.dns_events (event_timestamp, zeek_uid, source_ip, source_port, "
                    "destination_ip, destination_port, transport_protocol, query) "
                    "VALUES (now(), %s, '192.0.2.1', 123, '192.0.2.53', 53, 'udp', %s) RETURNING id",
                    (uid, query),
                ).fetchone()[0]
                ids.append(event_id)
        first = compute_features(settings, batch_size=1)
        assert first.rows_inserted >= 2
        with psycopg.connect(**settings) as connection:
            before = connection.execute(
                "SELECT dns_event_id, domain_length, digit_count, digit_ratio, entropy, calculated_at "
                "FROM public.dns_event_features WHERE dns_event_id = ANY(%s) ORDER BY dns_event_id", (ids,)
            ).fetchall()
            assert len(before) == 2
            assert before[0][0:4] == (ids[0], 11, 0, 0.0)
            assert before[0][4] == pytest.approx(3.095795255000934)
            assert before[1][0:5] == (ids[1], 0, 0, 0.0, 0.0)
            assert connection.execute("SELECT query FROM public.dns_events WHERE id = %s", (ids[0],)).fetchone()[0] == "ChatGPT.COM."
        second = compute_features(settings, batch_size=2)
        assert second.rows_inserted == second.rows_calculated == 0
        assert second.rows_skipped == second.events_considered
        with psycopg.connect(**settings) as connection:
            after = connection.execute(
                "SELECT dns_event_id, domain_length, digit_count, digit_ratio, entropy, calculated_at "
                "FROM public.dns_event_features WHERE dns_event_id = ANY(%s) ORDER BY dns_event_id", (ids,)
            ).fetchall()
            assert after == before
            with pytest.raises(psycopg.errors.UniqueViolation):
                with connection.transaction():
                    connection.execute(
                        "INSERT INTO public.dns_event_features (dns_event_id, domain_length, digit_count, digit_ratio, entropy) "
                        "VALUES (%s, 0, 0, 0, 0)", (ids[0],)
                    )
            with pytest.raises(psycopg.errors.ForeignKeyViolation):
                with connection.transaction():
                    connection.execute(
                        "INSERT INTO public.dns_event_features (dns_event_id, domain_length, digit_count, digit_ratio, entropy) "
                        "VALUES (%s, 0, 0, 0, 0)", (-1,)
                    )
    finally:
        with psycopg.connect(**settings) as connection:
            connection.execute("DELETE FROM public.dns_events WHERE zeek_uid = %s", (uid,))
