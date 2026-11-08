"""Pure independent rule evaluation, without database or ground-truth access."""

from dataclasses import dataclass
from typing import Any

from .config import DetectionConfig

METRICS = ("query_count", "unique_domain_count", "nxdomain_count", "nxdomain_ratio",
           "avg_domain_length", "avg_digit_ratio", "avg_entropy", "max_entropy")


@dataclass(frozen=True)
class Alert:
    alert_type: str
    severity: str
    reasons: list[dict[str, Any]]
    observed_metrics: dict[str, int | float | None]


def evaluate_window(metrics: dict[str, Any], config: DetectionConfig) -> list[Alert]:
    """Return every matching rule. A missing lexical value fails its comparison."""
    observed = {name: metrics[name] for name in METRICS}
    alerts = []
    for rule in config.rules:
        if all(observed[name] is not None and observed[name] >= threshold
               for name, threshold in rule.conditions):
            reasons = [{"metric": name, "operator": ">=", "observed": observed[name],
                        "threshold": threshold, "satisfied": True}
                       for name, threshold in rule.conditions]
            alerts.append(Alert(rule.alert_type, rule.severity, reasons, observed.copy()))
    return alerts
