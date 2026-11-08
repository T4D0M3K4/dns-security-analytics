"""Window grouping is tested in PostgreSQL, where the aggregation executes."""

from datetime import datetime, timezone
import os
from uuid import uuid4

import psycopg
import pytest

from dns_security_analytics.features.lexical import calculate_features
from dns_security_analytics.features.windows import compute_window_features
from dns_security_analytics.ingestion.dns import connection_settings


def test_invalid_batch_size() -> None:
    with pytest.raises(ValueError, match="batch size must be positive"):
        compute_window_features({}, batch_size=0)


@pytest.mark.skipif(os.environ.get("RUN_DB_TESTS") != "1", reason="set RUN_DB_TESTS=1 for local PostgreSQL")
def test_windows_metrics_boundaries_and_refresh() -> None:
    settings = connection_settings()
    # A non-UTC session with a 45-minute offset catches accidental local bucketing.
    settings = {**settings, "options": "-c timezone=Asia/Kathmandu"}
    uid = f"pytest-windows-{uuid4()}"
    # Use valid hextets and unique documentation-only IPv6 addresses.
    suffix = uuid4().hex
    ip1 = "2001:db8:" + ":".join(suffix[i:i + 4] for i in range(0, 24, 4))
    ip2 = "2001:db8:" + ":".join(suffix[i:i + 4] for i in range(8, 32, 4))
    minute1 = datetime(2020, 1, 1, 10, 15, tzinfo=timezone.utc)
    minute2 = datetime(2020, 1, 1, 10, 16, tzinfo=timezone.utc)
    queries = ["ChatGPT.COM.", "chatgpt.com", "a1.test", None, "missing.test", "", ".", "a..", "a.", "İ.TEST", "i\u0307.test", "ΟΣ", "ος"]
    ids = []

    def add_event(connection: psycopg.Connection, ip: str, timestamp: str,
                  query: str | None, rcode: int | None, lexical: bool) -> int:
        event_id = connection.execute(
            "INSERT INTO public.dns_events (event_timestamp, zeek_uid, source_ip, source_port, "
            "destination_ip, destination_port, transport_protocol, query, response_code) "
            "VALUES (%s, %s, %s, 123, '192.0.2.53', 53, 'udp', %s, %s) RETURNING id",
            (timestamp, uid, ip, query, rcode),
        ).fetchone()[0]
        if lexical:
            f = calculate_features(query)
            connection.execute(
                "INSERT INTO public.dns_event_features (dns_event_id, domain_length, digit_count, digit_ratio, entropy) "
                "VALUES (%s, %s, %s, %s, %s)",
                (event_id, f.domain_length, f.digit_count, f.digit_ratio, f.entropy),
            )
        return event_id

    def fetch() -> list[tuple]:
        with psycopg.connect(**settings) as connection:
            return connection.execute(
                "SELECT source_ip::text, window_start, window_end, query_count, unique_domain_count, "
                "nxdomain_count, nxdomain_ratio, avg_domain_length, avg_digit_ratio, avg_entropy, max_entropy, calculated_at "
                "FROM public.dns_window_features WHERE source_ip IN (%s::inet, %s::inet) ORDER BY source_ip, window_start",
                (ip1, ip2),
            ).fetchall()

    try:
        with psycopg.connect(**settings) as connection:
            for index, query in enumerate(queries):
                ids.append(add_event(connection, ip1, "2020-01-01T10:15:59.999Z", query,
                                     3 if index < 2 else None, index < 3))
            add_event(connection, ip1, "2020-01-01T10:16:00.000Z", "later.test", 0, False)
            add_event(connection, ip2, "2020-01-01T10:15:00.000Z", "other.test", 0, False)
        first = compute_window_features(settings, batch_size=2)
        assert first.rows_inserted >= 3
        rows = fetch()
        assert len(rows) == 3
        row = next(row for row in rows if row[1] == minute1 and row[3] == len(queries))
        assert row[2].astimezone(timezone.utc) == minute2
        # Empty query and root dot coalesce; two trailing dots remove only one.
        assert row[4] == 8
        assert row[5:7] == (2, 2 / len(queries))
        lexical = [calculate_features(query) for query in queries[:3]]
        assert row[7] == pytest.approx(sum(f.domain_length for f in lexical) / 3)
        assert row[8] == pytest.approx(sum(f.digit_ratio for f in lexical) / 3)
        assert row[9] == pytest.approx(sum(f.entropy for f in lexical) / 3)
        assert row[10] == max(f.entropy for f in lexical)
        for other in (value for value in rows if value is not row):
            assert other[3:7] == (1, 1, 0, 0.0)
            assert other[7:11] == (None, None, None, None)
        assert {row[1].astimezone(timezone.utc) for row in rows} == {minute1, minute2}
        second = compute_window_features(settings, batch_size=1)
        assert second.rows_inserted == second.rows_updated == 0
        assert second.rows_skipped == second.windows_calculated
        assert fetch() == rows
        # Late event and later lexical availability must refresh the existing window.
        with psycopg.connect(**settings) as connection:
            add_event(connection, ip1, "2020-01-01T10:15:10Z", "late.test", 3, True)
        refreshed = compute_window_features(settings)
        assert refreshed.rows_inserted == 0
        assert refreshed.rows_updated == 1
        changed = next(row for row in fetch() if row[1] == minute1 and row[3] == len(queries) + 1)
        assert changed[5:7] == (3, 3 / (len(queries) + 1))
        assert len(fetch()) == 3
        with psycopg.connect(**settings) as connection:
            f = calculate_features("missing.test")
            connection.execute(
                "INSERT INTO public.dns_event_features (dns_event_id, domain_length, digit_count, digit_ratio, entropy) "
                "VALUES (%s, %s, %s, %s, %s)", (ids[4], f.domain_length, f.digit_count, f.digit_ratio, f.entropy),
            )
        assert compute_window_features(settings).rows_updated == 1
    finally:
        with psycopg.connect(**settings) as connection:
            connection.execute("DELETE FROM public.dns_window_features WHERE source_ip IN (%s::inet, %s::inet)", (ip1, ip2))
            connection.execute("DELETE FROM public.dns_events WHERE zeek_uid = %s", (uid,))
