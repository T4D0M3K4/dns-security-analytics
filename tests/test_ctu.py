"""Fail-closed isolation checks and opt-in read-only checks of the CTU experiment."""

import json
import os
from pathlib import Path

import psycopg
import pytest

from dns_security_analytics.analysis import ctu as validation
from dns_security_analytics.analysis import database_fingerprint as preservation
from dns_security_analytics.analysis.public_datasets import inspect_log
from dns_security_analytics.transformation.dns import parse_dns_line


@pytest.fixture
def environment(monkeypatch) -> dict:
    for key in os.environ:
        if key.startswith("PG"):
            monkeypatch.delenv(key)
    return {"CTU_HOST": "127.0.0.1", "CTU_PORT": "55434",
            "CTU_DB": "dns_ctu", "CTU_USER": "dns_ctu_owner",
            "CTU_PASSWORD": "a" * 64}


@pytest.mark.parametrize("key,value", [("CTU_HOST", "postgres"), ("CTU_PORT", "5432"),
    ("CTU_DB", "dns_security_analytics"), ("CTU_USER", "postgres"), ("CTU_PASSWORD", "")])
def test_demo_or_invalid_configuration_refused(environment: dict, key: str, value: str) -> None:
    with pytest.raises(ValueError):
        validation.ctu_settings({**environment, key: value})


def test_no_libpq_or_demo_secret_fallback(environment: dict, monkeypatch) -> None:
    monkeypatch.setenv("POSTGRES_PASSWORD", environment["CTU_PASSWORD"])
    assert validation.ctu_settings(environment)["dbname"] == "dns_ctu"
    monkeypatch.delenv("POSTGRES_PASSWORD")
    monkeypatch.setenv("PGSERVICE", "demo")
    with pytest.raises(ValueError, match="PG"):
        validation.ctu_settings(environment)


def container() -> dict:
    return {"Id": "test-container", "Config": {"Labels": {"com.docker.compose.project": validation.PROJECT,
            "com.docker.compose.service": "postgres"}},
            "Mounts": [{"Name": validation.PROJECT + "_postgres_data", "Destination": "/var/lib/postgresql/data"}],
            "NetworkSettings": {"Ports": {"5432/tcp": [{"HostIp": "127.0.0.1", "HostPort": "55434"}]}}}


@pytest.mark.parametrize("field", ["project", "volume", "port"])
def test_wrong_docker_identity_refused(field: str) -> None:
    document = container()
    assert validation.check_container(document) == "test-container"
    if field == "project":
        document["Config"]["Labels"]["com.docker.compose.project"] = "demo"
    elif field == "volume":
        document["Mounts"][0]["Name"] = "demo_postgres_data"
    else:
        document["NetworkSettings"]["Ports"]["5432/tcp"][0]["HostPort"] = "5432"
    with pytest.raises(ValueError):
        validation.check_container(document)


def test_same_named_database_on_wrong_cluster_refused(environment: dict, monkeypatch, tmp_path: Path) -> None:
    def command(args: list, **kwargs) -> str:
        return json.dumps([container()]) if args[1] == "inspect" else "test-container" if args[1] == "compose" else "isolated-cluster"

    class ReadOnlyConnection:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def execute(self, statement):
            assert statement.startswith(("SET TRANSACTION READ ONLY", "\n            SELECT"))
            return self

        def fetchone(self):
            return ("dns_ctu", "dns_ctu_owner", "wrong-cluster", validation.MARKER)

    monkeypatch.setattr(validation.subprocess, "check_output", command)
    monkeypatch.setattr(validation.psycopg, "connect", lambda **kwargs: ReadOnlyConnection())
    with pytest.raises(ValueError, match="identity mismatch"):
        validation.guard(validation.ctu_settings(environment), tmp_path / "environment")


def test_capture_membership_requires_single_known_source_hash() -> None:
    sources = {"normal": {"source_sha256": "aaa"}, "malware": {"source_sha256": "bbb"}}
    assert validation.capture_for_window(["aaa"], sources) == "normal"
    assert validation.capture_for_window(["aaa", "bbb"], sources) is None
    assert validation.capture_for_window(["unknown"], sources) is None


def test_cross_capture_minute_collision_is_refused_before_ingestion(tmp_path: Path) -> None:
    row = {"ts": 60, "uid": "unit", "id.orig_h": "192.0.2.1", "id.orig_p": 123,
           "id.resp_h": "192.0.2.53", "id.resp_p": 53, "proto": "udp", "query": "example.test"}
    a, b = tmp_path / "a.log", tmp_path / "b.log"
    a.write_text(json.dumps(row) + "\n")
    b.write_text(json.dumps(row) + "\n")
    sources = {"normal": {"log_path": str(a)}, "malware": {"log_path": str(b)}}
    with pytest.raises(ValueError, match="collision"):
        validation.preflight(sources)
    row["ts"] = 120
    b.write_text(json.dumps(row) + "\n")
    validation.preflight(sources)  # Shared IP alone does not imply a collision.


def test_historical_packages_are_not_active() -> None:
    import importlib.util
    for package in ("synthetic", "evaluation", "analysis.calibration"):
        assert importlib.util.find_spec("dns_security_analytics." + package) is None


def test_changed_pipeline_or_configuration_refused(monkeypatch) -> None:
    monkeypatch.setattr(validation.subprocess, "check_output", lambda *args, **kwargs: b"changed committed contents")
    with pytest.raises(ValueError, match="Uncommitted"):
        validation.source_identity()


def test_preservation_checker_forces_read_only_startup(monkeypatch) -> None:
    class Connection:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def execute(self, statement):
            assert statement.endswith("READ ONLY")

    def connect(**kwargs):
        assert "default_transaction_read_only=on" in kwargs["options"]
        return Connection()

    monkeypatch.setattr(preservation.psycopg, "connect", connect)
    monkeypatch.setattr(preservation, "TABLES", {})
    assert preservation.fingerprint({"options": "-c default_transaction_read_only=off"}) == {}


@pytest.mark.skipif(os.environ.get("RUN_CTU_TESTS") != "1", reason="requires guarded isolated CTU experiment")
def test_ctu_completeness_timestamp_preservation_and_epoch_boundaries() -> None:
    env_file = validation.ROOT / ".env.ctu"
    settings = validation.ctu_settings(validation.read_environment(env_file))
    validation.guard(settings, env_file)
    sources = validation.inputs(Path(os.environ.get("CTU_EXTRACTION", validation.ROOT / "docs/public_datasets/extraction.json")))
    with psycopg.connect(**settings) as c:
        c.execute("SET TRANSACTION READ ONLY")
        assert c.execute("SELECT count(*) FROM public.dns_events").fetchone()[0] == sum(v["events_expected"] for v in sources.values())
        assert c.execute("SELECT count(*) FROM public.dns_event_features").fetchone()[0] == sum(v["events_expected"] for v in sources.values())
        assert c.execute("SELECT count(*) FROM public.dns_window_features").fetchone()[0] == sum(inspect_log(validation.ROOT/v["log_path"])["window_count"] for v in sources.values())
        for capture, source in sources.items():
            stored = {line: (ts, minute) for line, ts, minute in c.execute("""
                SELECT source_line,event_timestamp,date_trunc('minute',event_timestamp,'UTC')
                FROM public.dns_events WHERE source_sha256=%s
            """, (source["source_sha256"],))}
            with (validation.ROOT / source["log_path"]).open() as stream:
                for line, raw in enumerate(stream, 1):
                    event = parse_dns_line(raw)
                    assert stored[line] == (event.event_timestamp, event.event_timestamp.replace(second=0, microsecond=0))
            assert len(stored) == source["events_expected"]
        c.execute("SET LOCAL timezone='Asia/Kathmandu'")
        values = c.execute("""
            SELECT extract(epoch FROM date_trunc('minute',ts,'UTC'))::integer
            FROM (VALUES ('1970-01-01T00:00:59.999Z'::timestamptz),
                         ('1970-01-01T00:01:00Z'::timestamptz)) s(ts)
        """).fetchall()
        assert values == [(0,), (60,)]


@pytest.mark.skipif(os.environ.get("RUN_CTU_TESTS") != "1", reason="requires guarded isolated CTU experiment")
def test_persisted_windows_match_independent_offline_exploration() -> None:
    env_file = validation.ROOT / ".env.ctu"
    settings = validation.ctu_settings(validation.read_environment(env_file))
    validation.guard(settings, env_file)
    sources = validation.inputs(Path(os.environ.get("CTU_EXTRACTION", validation.ROOT / "docs/public_datasets/extraction.json")))
    report = validation.analyze(settings, sources)
    assert report["ambiguous_or_unknown_windows"] == []
    for capture, source in sources.items():
        offline = inspect_log(validation.ROOT / source["log_path"])
        stored = {(row["source_ip"], row["window_start"].isoformat()): row
                  for row in report["captures"][capture]["windows_detail"]}
        assert len(stored) == offline["window_count"]
        for row in offline["windows"]:
            actual = stored[row["source_ip"], row["window_start"]]
            for key in validation.METRICS:
                assert actual[key] == pytest.approx(row[key])
