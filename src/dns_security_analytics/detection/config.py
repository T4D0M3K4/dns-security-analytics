"""Explicit research configuration and reproducible configuration identity."""

from dataclasses import dataclass
import hashlib
from importlib.resources import files
import json
import math
from pathlib import Path
from typing import Any

RULE_FIELDS = {
    "HIGH_DNS_FREQUENCY": {"query_count"},
    "HIGH_NXDOMAIN_RATIO": {"query_count", "nxdomain_ratio"},
    "DGA_LIKE": {"query_count", "unique_domain_count", "nxdomain_ratio", "avg_entropy"},
    "TUNNEL_LIKE": {"query_count", "unique_domain_count", "avg_domain_length", "avg_entropy"},
}
DETECTOR_VERSION = "1"


@dataclass(frozen=True)
class Rule:
    alert_type: str
    severity: str
    conditions: tuple[tuple[str, int | float], ...]


@dataclass(frozen=True)
class DetectionConfig:
    name: str
    rules: tuple[Rule, ...]
    sha256: str
    snapshot: dict[str, Any]


def load_config(path: Path | None = None) -> DetectionConfig:
    """Validate a complete configuration; no implicit numeric thresholds."""
    content = (path.read_text(encoding="utf-8") if path else
               files("dns_security_analytics.detection").joinpath("default_rules.json").read_text(encoding="utf-8"))
    document = json.loads(content)
    if not isinstance(document, dict) or set(document) != {"name", "rules"}:
        raise ValueError("configuration requires exactly name and rules")
    if not isinstance(document["name"], str) or not document["name"].strip():
        raise ValueError("configuration name must be non-empty text")
    if not isinstance(document["rules"], dict) or set(document["rules"]) != set(RULE_FIELDS):
        raise ValueError("configuration must define exactly the four supported rules")
    rules = []
    for alert_type, required in RULE_FIELDS.items():
        rule = document["rules"][alert_type]
        if not isinstance(rule, dict) or set(rule) != {"severity", "conditions"}:
            raise ValueError(f"invalid rule structure: {alert_type}")
        if rule["severity"] not in ("MEDIUM", "HIGH"):
            raise ValueError(f"invalid severity: {alert_type}")
        conditions = rule["conditions"]
        if not isinstance(conditions, dict) or set(conditions) != required:
            raise ValueError(f"incorrect conditions: {alert_type}")
        for metric, value in conditions.items():
            if type(value) not in (int, float) or (type(value) is float and not math.isfinite(value)) or value < 0:
                raise ValueError(f"invalid numeric threshold: {alert_type}.{metric}")
            if metric in ("query_count", "unique_domain_count") and type(value) is not int:
                raise ValueError(f"count threshold must be an integer: {alert_type}.{metric}")
            if metric == "nxdomain_ratio" and value > 1:
                raise ValueError("ratio threshold must be in [0, 1]")
        rules.append(Rule(alert_type, rule["severity"], tuple(sorted(conditions.items()))))
    canonical = json.dumps(document, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return DetectionConfig(document["name"], tuple(rules), hashlib.sha256(canonical.encode()).hexdigest(), document)
