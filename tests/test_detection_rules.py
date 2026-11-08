import json
from pathlib import Path

import pytest

from dns_security_analytics.detection.config import load_config
from dns_security_analytics.detection.rules import evaluate_window


@pytest.fixture
def metrics() -> dict:
    return {"query_count": 20, "unique_domain_count": 20, "nxdomain_count": 10,
            "nxdomain_ratio": 0.5, "avg_domain_length": 60.0,
            "avg_digit_ratio": 0.2, "avg_entropy": 4.0, "max_entropy": 4.8}


def types(metrics: dict) -> set[str]:
    return {alert.alert_type for alert in evaluate_window(metrics, load_config())}


def test_exact_selected_configuration() -> None:
    config = load_config()
    assert {rule.alert_type: dict(rule.conditions) for rule in config.rules} == {
        "HIGH_DNS_FREQUENCY": {"query_count": 100},
        "HIGH_NXDOMAIN_RATIO": {"query_count": 20, "nxdomain_ratio": 0.5},
        "DGA_LIKE": {"query_count": 20, "unique_domain_count": 20, "nxdomain_ratio": 0.5, "avg_entropy": 4.0},
        "TUNNEL_LIKE": {"query_count": 20, "unique_domain_count": 20, "avg_domain_length": 60, "avg_entropy": 4.0},
    }


@pytest.mark.parametrize("count,expected", [(99, False), (100, True), (101, True)])
def test_frequency_boundary(metrics: dict, count: int, expected: bool) -> None:
    metrics["query_count"] = count
    assert ("HIGH_DNS_FREQUENCY" in types(metrics)) == expected


@pytest.mark.parametrize("count,ratio,expected", [(19, 1.0, False), (20, 0.499999, False),
                                                 (20, 0.5, True), (20, 0.500001, True)])
def test_nxdomain_guard_and_boundary(metrics: dict, count: int, ratio: float, expected: bool) -> None:
    metrics.update(query_count=count, nxdomain_ratio=ratio)
    assert ("HIGH_NXDOMAIN_RATIO" in types(metrics)) == expected


@pytest.mark.parametrize("alert_type", ["DGA_LIKE", "TUNNEL_LIKE"])
def test_exact_joint_boundaries(metrics: dict, alert_type: str) -> None:
    assert alert_type in types(metrics)


@pytest.mark.parametrize("metric,value", [("query_count", 19), ("unique_domain_count", 19),
                                          ("nxdomain_ratio", 0.499999), ("avg_entropy", 3.999999),
                                          ("avg_entropy", None)])
def test_dga_each_condition_fails(metrics: dict, metric: str, value: object) -> None:
    metrics[metric] = value
    assert "DGA_LIKE" not in types(metrics)


@pytest.mark.parametrize("metric,value", [("query_count", 19), ("unique_domain_count", 19),
                                          ("avg_domain_length", 59.999999), ("avg_entropy", 3.999999),
                                          ("avg_domain_length", None), ("avg_entropy", None)])
def test_tunnel_each_condition_fails(metrics: dict, metric: str, value: object) -> None:
    metrics[metric] = value
    assert "TUNNEL_LIKE" not in types(metrics)


def test_tunnel_allows_zero_nxdomain(metrics: dict) -> None:
    metrics.update(nxdomain_count=0, nxdomain_ratio=0.0)
    assert "TUNNEL_LIKE" in types(metrics)


def test_normal_window_no_alert(metrics: dict) -> None:
    metrics.update(query_count=20, unique_domain_count=9, nxdomain_count=0, nxdomain_ratio=0.0,
                   avg_domain_length=16, avg_entropy=3.3)
    assert evaluate_window(metrics, load_config()) == []


def test_overlaps_severity_and_evidence(metrics: dict) -> None:
    metrics["query_count"] = 100
    config = load_config()
    alerts = evaluate_window(metrics, config)
    assert len(alerts) == 4
    expected_severity = {"HIGH_DNS_FREQUENCY": "MEDIUM", "HIGH_NXDOMAIN_RATIO": "MEDIUM",
                         "DGA_LIKE": "HIGH", "TUNNEL_LIKE": "HIGH"}
    for alert in alerts:
        assert alert.severity == expected_severity[alert.alert_type]
        assert alert.observed_metrics == metrics
        expected = dict(next(rule.conditions for rule in config.rules if rule.alert_type == alert.alert_type))
        assert {reason["metric"] for reason in alert.reasons} == set(expected)
        for reason in alert.reasons:
            assert reason == {"metric": reason["metric"], "operator": ">=", "satisfied": True,
                              "observed": metrics[reason["metric"]], "threshold": expected[reason["metric"]]}


def test_configuration_identity_and_packaged_default(tmp_path: Path) -> None:
    original = load_config()
    path = tmp_path / "rules.json"
    path.write_text(json.dumps(original.snapshot, sort_keys=True))
    assert load_config(path) == original
    document = json.loads(path.read_text())
    document["name"] = "explicit-experiment"
    path.write_text(json.dumps(document))
    assert load_config(path).sha256 != original.sha256


@pytest.mark.parametrize("mutation", ["missing_rule", "missing_condition", "unknown_condition",
                                     "negative", "nonfinite", "boolean", "ratio", "severity"])
def test_invalid_configuration(tmp_path: Path, mutation: str) -> None:
    document = load_config().snapshot
    rule = document["rules"]["DGA_LIKE"]
    if mutation == "missing_rule":
        del document["rules"]["TUNNEL_LIKE"]
    elif mutation == "missing_condition":
        del rule["conditions"]["query_count"]
    elif mutation == "unknown_condition":
        rule["conditions"]["unknown"] = 1
    elif mutation == "severity":
        rule["severity"] = "INVALID"
    else:
        metric = "nxdomain_ratio" if mutation == "ratio" else "query_count"
        rule["conditions"][metric] = {"negative": -1, "nonfinite": float("nan"),
                                       "boolean": True, "ratio": 1.01}[mutation]
    path = tmp_path / "invalid.json"
    path.write_text(json.dumps(document))
    with pytest.raises(ValueError):
        load_config(path)
