"""Current-alert synchronization against the configured local database."""

from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
from typing import Iterator
from uuid import uuid4

import psycopg
from psycopg.types.json import Jsonb
import pytest

from dns_security_analytics.detection.config import load_config
from dns_security_analytics.detection.database import detect
from dns_security_analytics.ingestion.dns import connection_settings


@pytest.fixture
def windows() -> Iterator[tuple[dict, str, datetime]]:
    if os.environ.get("RUN_DB_TESTS") != "1":
        pytest.skip("set RUN_DB_TESTS=1 for local PostgreSQL")
    settings = connection_settings()
    suffix = uuid4().hex
    ip = "2001:db8:" + ":".join(suffix[i:i + 4] for i in range(0, 24, 4))
    minute = datetime(2095, 1, 1, tzinfo=timezone.utc)
    try:
        with psycopg.connect(**settings) as connection:
            for offset in (0, 1):
                connection.execute(
                    "INSERT INTO public.dns_window_features (source_ip, window_start, window_end, "
                    "query_count, unique_domain_count, nxdomain_count, nxdomain_ratio, "
                    "avg_domain_length, avg_digit_ratio, avg_entropy, max_entropy) "
                    "VALUES (%s, %s, %s, %s, 20, %s, %s, 60, 0.2, 4, 4.8)",
                    (ip, minute + timedelta(minutes=offset), minute + timedelta(minutes=offset + 1),
                     100 if offset == 0 else 20, 50 if offset == 0 else 0, 0.5 if offset == 0 else 0.0),
                )
                # Second window is benign despite the other fields.
                if offset:
                    connection.execute("UPDATE public.dns_window_features SET unique_domain_count=10, "
                                       "avg_domain_length=16, avg_entropy=3.3 WHERE source_ip=%s AND window_start=%s",
                                       (ip, minute + timedelta(minutes=offset)))
        yield settings, ip, minute
    finally:
        with psycopg.connect(**settings) as connection:
            connection.execute("DELETE FROM public.dns_window_features WHERE source_ip=%s", (ip,))
        # Restore the documented default as the active configuration after config tests.
        detect(settings, load_config())


def fetch(settings: dict, ip: str) -> list[tuple]:
    with psycopg.connect(**settings) as connection:
        return connection.execute("SELECT alert_type, reasons, observed_metrics, detected_at, updated_at "
                                  "FROM public.dns_alerts WHERE source_ip=%s ORDER BY alert_type", (ip,)).fetchall()


def test_idempotency_updates_and_stale_alerts(windows: tuple) -> None:
    settings, ip, minute = windows
    first = detect(settings, load_config(), batch_size=1)
    initial = fetch(settings, ip)
    assert len(initial) == 4
    assert first.alerts_inserted >= 4
    again = detect(settings, load_config(), batch_size=2)
    assert again.alerts_inserted == again.alerts_updated == again.stale_alerts_removed == 0
    assert again.alerts_unchanged == again.alerts_generated
    assert fetch(settings, ip) == initial
    with psycopg.connect(**settings) as connection:
        connection.execute("UPDATE public.dns_window_features SET query_count=20, nxdomain_count=10 "
                           "WHERE source_ip=%s AND window_start=%s", (ip, minute))
    changed = detect(settings, load_config())
    assert changed.alerts_updated == 3 and changed.stale_alerts_removed == 1
    current = fetch(settings, ip)
    assert all(row[2]["query_count"] == 20 for row in current)
    old_times = {row[0]: row[3] for row in initial}
    assert all(row[3] == old_times[row[0]] and row[4] > row[3] for row in current)
    with psycopg.connect(**settings) as connection:
        connection.execute("UPDATE public.dns_window_features SET avg_entropy=NULL WHERE source_ip=%s AND window_start=%s", (ip, minute))
    assert detect(settings, load_config()).stale_alerts_removed == 2
    assert [row[0] for row in fetch(settings, ip)] == ["HIGH_NXDOMAIN_RATIO"]
    with psycopg.connect(**settings) as connection:
        connection.execute("UPDATE public.dns_window_features SET nxdomain_count=0, nxdomain_ratio=0 "
                           "WHERE source_ip=%s AND window_start=%s", (ip, minute))
    assert detect(settings, load_config()).stale_alerts_removed == 1
    assert fetch(settings, ip) == []


def test_configuration_snapshot_changes(windows: tuple, tmp_path: Path) -> None:
    settings, ip, _ = windows
    default = load_config()
    detect(settings, default)
    document = json.loads(json.dumps(default.snapshot))
    document["name"] = "same-thresholds-test"
    path = tmp_path / "rules.json"
    path.write_text(json.dumps(document))
    config = load_config(path)
    changed = detect(settings, config)
    assert changed.alerts_updated == changed.alerts_generated
    with psycopg.connect(**settings) as connection:
        rows = connection.execute("SELECT config_sha256, threshold_config, detector_version FROM public.dns_alerts WHERE source_ip=%s", (ip,)).fetchall()
        assert len(rows) == 4
        assert all(row == (config.sha256, config.snapshot, "1") for row in rows)


def test_database_constraints_and_window_deletion(windows: tuple) -> None:
    settings, ip, minute = windows
    config = load_config()
    detect(settings, config)
    sql = ("INSERT INTO public.dns_alerts (source_ip, window_start, alert_type, severity, reasons, "
           "observed_metrics, config_sha256, threshold_config, detector_version) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)")
    base = [ip, minute, "DGA_LIKE", "HIGH", Jsonb([{"metric": "query_count"}]),
            Jsonb({"query_count": 100}), config.sha256, Jsonb(config.snapshot), "1"]
    with psycopg.connect(**settings) as connection:
        with pytest.raises(psycopg.errors.UniqueViolation):
            with connection.transaction():
                connection.execute(sql, base)
        for index, value in ((2, "INVALID"), (3, "INVALID"), (4, Jsonb([])), (5, Jsonb([])), (6, "bad-hash")):
            bad = base.copy()
            bad[index] = value
            with pytest.raises(psycopg.errors.CheckViolation):
                with connection.transaction():
                    connection.execute(sql, bad)
        absent = base.copy()
        absent[1] = minute + timedelta(minutes=2)
        with pytest.raises(psycopg.errors.ForeignKeyViolation):
            with connection.transaction():
                connection.execute(sql, absent)
        connection.execute("DELETE FROM public.dns_window_features WHERE source_ip=%s AND window_start=%s", (ip, minute))
        assert connection.execute("SELECT count(*) FROM public.dns_alerts WHERE source_ip=%s", (ip,)).fetchone()[0] == 0
