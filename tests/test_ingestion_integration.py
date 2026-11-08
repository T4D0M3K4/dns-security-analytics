"""Opt-in test against the configured local PostgreSQL service."""

import hashlib
import json
import os
from pathlib import Path
from uuid import uuid4

import psycopg
import pytest

from dns_security_analytics.ingestion.dns import connection_settings, ingest
from dns_security_analytics.ingestion import dns as ingestion_module
from dns_security_analytics.transformation.dns import DNSEvent


@pytest.mark.skipif(os.environ.get("RUN_DB_TESTS") != "1", reason="set RUN_DB_TESTS=1 for local PostgreSQL")
def test_batches_rejections_and_replay(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    record = {"ts": 1793526679.533648, "uid": f"pytest-{uuid4()}",
              "id.orig_h": "2001:db8::1", "id.orig_p": 65535,
              "id.resp_h": "192.0.2.53", "id.resp_p": 53, "proto": "udp",
              "query": "example.test", "qtype": 28,
              "answers": ["2001:db8::2"], "TTLs": [60.5]}
    line = json.dumps(record)
    path = tmp_path / "dns.log"
    path.write_bytes((line + '\n{broken}\n' + line + '\n').encode() + b'\xff\n')
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    settings = connection_settings()
    try:
        first = ingest(path, settings, batch_size=1)
        assert (first.records_read, first.records_inserted, first.records_rejected, first.records_skipped) == (4, 2, 2, 0)
        copied = tmp_path / "copied.log"
        copied.write_bytes(path.read_bytes())
        second = ingest(copied, settings, batch_size=2)
        assert (second.records_read, second.records_inserted, second.records_rejected, second.records_skipped) == (4, 0, 2, 2)
        assert "dns.log:2 rejected" in caplog.text
        with psycopg.connect(**settings) as connection:
            rows = connection.execute(
                "SELECT source_line, query_type, answers, ttls, ingested_at IS NOT NULL "
                "FROM public.dns_events WHERE source_sha256 = %s ORDER BY source_line", (digest,)
            ).fetchall()
            assert rows == [(1, 28, ["2001:db8::2"], [60.5], True), (3, 28, ["2001:db8::2"], [60.5], True)]
    finally:
        with psycopg.connect(**settings) as connection:
            connection.execute("DELETE FROM public.dns_events WHERE source_sha256 = %s", (digest,))


@pytest.mark.skipif(os.environ.get("RUN_DB_TESTS") != "1", reason="set RUN_DB_TESTS=1 for local PostgreSQL")
def test_changed_source_rolls_back(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "changing.log"
    record = {"ts": 1, "uid": f"pytest-{uuid4()}", "id.orig_h": "192.0.2.1",
              "id.orig_p": 123, "id.resp_h": "192.0.2.53", "id.resp_p": 53, "proto": "udp"}
    path.write_text(json.dumps(record) + "\n")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    original = ingestion_module.parse_dns_line

    def change_during_parse(line: str) -> DNSEvent:
        event = original(line)
        with path.open("a") as source:
            source.write("\n")
        return event

    monkeypatch.setattr(ingestion_module, "parse_dns_line", change_during_parse)
    settings = connection_settings()
    with pytest.raises(ValueError, match="Source file changed"):
        ingest(path, settings, batch_size=1)
    with psycopg.connect(**settings) as connection:
        assert connection.execute(
            "SELECT count(*) FROM public.dns_events WHERE source_sha256 = %s", (digest,)
        ).fetchone()[0] == 0
