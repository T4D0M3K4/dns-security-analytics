"""Atomic synchronization of current explainable alerts from bounded window reads."""

from dataclasses import dataclass, field
from time import perf_counter

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .config import DETECTOR_VERSION, RULE_FIELDS, DetectionConfig
from .rules import METRICS, evaluate_window

KEYS = ("source_ip", "window_start", "alert_type")
EVIDENCE = ("severity", "reasons", "observed_metrics", "config_sha256", "threshold_config", "detector_version")
COLUMNS = ", ".join((*KEYS, *EVIDENCE))
CHANGED = ("ROW(" + ", ".join(f"a.{name}" for name in EVIDENCE) + ") IS DISTINCT FROM ROW(" +
           ", ".join(f"s.{name}" for name in EVIDENCE) + ")")


@dataclass
class DetectionSummary:
    config_name: str
    config_sha256: str
    detector_version: str = DETECTOR_VERSION
    windows_evaluated: int = 0
    alerts_generated: int = 0
    alerts_by_type: dict[str, int] = field(default_factory=lambda: dict.fromkeys(RULE_FIELDS, 0))
    alerts_inserted: int = 0
    alerts_updated: int = 0
    alerts_unchanged: int = 0
    stale_alerts_removed: int = 0
    elapsed_seconds: float = 0.0


def detect(settings: dict[str, str], config: DetectionConfig, batch_size: int = 500) -> DetectionSummary:
    """Synchronize all supported alerts to a consistent snapshot and one configuration."""
    if batch_size < 1:
        raise ValueError("batch size must be positive")
    started = perf_counter()
    summary = DetectionSummary(config.name, config.sha256)
    with psycopg.connect(**settings, connect_timeout=10) as connection:
        with connection.cursor() as target:
            target.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            # Freeze only derived windows while synchronizing their alerts.
            target.execute("LOCK TABLE public.dns_window_features IN SHARE MODE")
            target.execute("LOCK TABLE public.dns_alerts IN SHARE ROW EXCLUSIVE MODE")
            target.execute("""
                CREATE TEMP TABLE detection_stage (
                    source_ip inet, window_start timestamptz, alert_type text,
                    severity text, reasons jsonb, observed_metrics jsonb,
                    config_sha256 text, threshold_config jsonb, detector_version text,
                    PRIMARY KEY (source_ip, window_start, alert_type)
                ) ON COMMIT DROP
            """)
            with connection.cursor(name="detection_windows", row_factory=dict_row) as source:
                # Interpolated identifiers are fixed constants, never CLI/input values.
                source.execute("SELECT source_ip, window_start, " + ", ".join(METRICS) +
                               " FROM public.dns_window_features ORDER BY source_ip, window_start")
                while rows := source.fetchmany(batch_size):
                    summary.windows_evaluated += len(rows)
                    with target.copy(f"COPY detection_stage ({COLUMNS}) FROM STDIN") as copy:
                        for row in rows:
                            for alert in evaluate_window(row, config):
                                summary.alerts_generated += 1
                                summary.alerts_by_type[alert.alert_type] += 1
                                copy.write_row((row["source_ip"], row["window_start"], alert.alert_type,
                                                alert.severity, Jsonb(alert.reasons), Jsonb(alert.observed_metrics),
                                                config.sha256, Jsonb(config.snapshot), DETECTOR_VERSION))
            target.execute(f"""
                SELECT count(*) FILTER (WHERE a.id IS NULL),
                       count(*) FILTER (WHERE a.id IS NOT NULL AND {CHANGED})
                FROM detection_stage s LEFT JOIN public.dns_alerts a USING (source_ip, window_start, alert_type)
            """)
            summary.alerts_inserted, summary.alerts_updated = target.fetchone()
            summary.alerts_unchanged = summary.alerts_generated - summary.alerts_inserted - summary.alerts_updated
            assignments = ", ".join(f"{name}=EXCLUDED.{name}" for name in EVIDENCE)
            target.execute(f"""
                INSERT INTO public.dns_alerts AS a ({COLUMNS})
                SELECT {COLUMNS} FROM detection_stage ORDER BY source_ip, window_start, alert_type
                ON CONFLICT (source_ip, window_start, alert_type) DO UPDATE
                SET {assignments}, updated_at=CURRENT_TIMESTAMP
                WHERE {CHANGED.replace('s.', 'EXCLUDED.')}
            """)
            target.execute("""
                DELETE FROM public.dns_alerts a WHERE NOT EXISTS (
                    SELECT 1 FROM detection_stage s WHERE s.source_ip=a.source_ip
                      AND s.window_start=a.window_start AND s.alert_type=a.alert_type
                )
            """)
            summary.stale_alerts_removed = target.rowcount
    summary.elapsed_seconds = round(perf_counter() - started, 6)
    return summary
