"""CTU view grain, provenance, ACLs and sanitized dashboard lifecycle contracts."""
import importlib.util
import os
from pathlib import Path

import psycopg
import pytest

from dns_security_analytics.analysis.ctu import ROOT, ctu_settings, guard, read_environment


def definitions():
    spec = importlib.util.spec_from_file_location("ctu_definitions", ROOT / "infra/superset/dashboard_definitions.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_dashboard_grains_and_reproducible_ids():
    d = definitions()
    assert len(d.DASHBOARDS) == 3
    assert len(d.datasets()) == 6
    charts = d.charts()
    keys = {c["key"] for c in charts}
    assert len(keys) == len(charts)
    placed = [key for dashboard in d.DASHBOARDS for row in dashboard["rows"] for key, _, _ in row]
    assert set(placed) == keys and len(placed) == len(keys)
    assert len({d.uid("chart/" + key) for key in keys}) == len(keys)
    assert d.uid("chart/traffic-events") == definitions().uid("chart/traffic-events")
    expression = next(m["expression"] for m in d.datasets()["detectors"]["metrics"] if m["metric_name"] == "Activation rate (%)")
    assert "SUM(alerting_windows)/NULLIF(SUM(total_windows),0)" in expression
    assert all(c["dataset"] in d.datasets() for c in charts)


def test_sanitized_assets_have_no_credentials():
    directory = ROOT / "infra/superset/assets"
    assert len(list((directory / "dashboards").glob("*.yaml"))) == len(definitions().DASHBOARDS)
    assert len(list((directory / "charts").glob("*.yaml"))) == len(definitions().charts())
    assert len(list((directory / "datasets").rglob("*.yaml"))) == len(definitions().datasets())
    for path in directory.rglob("*.yaml"):
        text = path.read_text()
        assert "access_token:" not in text and "SECRET_KEY" not in text
        if path.parent.name == "databases":
            assert "READER:XXXXXXXXXX@postgres:5432/ANALYTICS_DB" in text


@pytest.mark.skipif(os.environ.get("RUN_CTU_TESTS") != "1", reason="requires guarded CTU read-only inspection")
def test_reporting_grain_provenance_and_reader_permissions():
    env = read_environment(ROOT / ".env.ctu")
    settings = ctu_settings(env)
    guard(settings, ROOT / ".env.ctu")
    with psycopg.connect(**settings) as c:
        c.execute("SET TRANSACTION READ ONLY")
        for view, table, key in [("vw_dns_event_analysis", "dns_events", "event_id"),
                                  ("vw_dns_window_analysis", "dns_window_features", "(source_ip,window_start)"),
                                  ("vw_dns_alert_analysis", "dns_alerts", "alert_id")]:
            total, distinct = c.execute(f"SELECT count(*),count(DISTINCT {key}) FROM reporting.{view}").fetchone()
            assert total == distinct == c.execute(f"SELECT count(*) FROM public.{table}").fetchone()[0]
        assert c.execute("SELECT count(*) FROM reporting.vw_dns_window_analysis WHERE capture_count<>1").fetchone()[0] == 0
        assert c.execute("SELECT count(*) FROM information_schema.tables WHERE table_schema='reporting' AND table_name LIKE '%evaluation%'").fetchone()[0] == 0
        assert c.execute("SELECT count(*) FROM public.dns_events WHERE source_sha256 IS NULL OR source_line IS NULL").fetchone()[0] == 0
        assert c.execute("SELECT sum(dns_events) FROM reporting.vw_ctu_capture_sources").fetchone()[0] == c.execute("SELECT count(*) FROM public.dns_events").fetchone()[0]
        assert c.execute("SELECT sum(alert_records) FROM reporting.vw_ctu_capture_sources").fetchone()[0] == c.execute("SELECT count(*) FROM public.dns_alerts").fetchone()[0]
        assert c.execute("SELECT count(*) FROM reporting.vw_ctu_feature_samples").fetchone()[0] == 6*c.execute("SELECT count(*) FROM public.dns_window_features").fetchone()[0]
    reader = {**settings, "user": env["SUPERSET_ANALYTICS_USER"], "password": env["SUPERSET_ANALYTICS_PASSWORD"]}
    with psycopg.connect(**reader) as c:
        for data in definitions().datasets().values():
            table = "reporting." + data["table_name"]
            assert c.execute(f"SELECT count(*) FROM {table}").fetchone()[0] > 0
            for operation in ("INSERT", "UPDATE", "DELETE"):
                assert not c.execute("SELECT has_table_privilege(current_user,%s,%s)", (table, operation)).fetchone()[0]
