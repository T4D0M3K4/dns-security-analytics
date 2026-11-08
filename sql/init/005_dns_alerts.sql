-- Current alert state; apply explicitly to existing database volumes.
BEGIN;
CREATE TABLE IF NOT EXISTS public.dns_alerts (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    source_ip inet NOT NULL,
    window_start timestamptz NOT NULL,
    alert_type text NOT NULL CHECK (alert_type IN
        ('HIGH_DNS_FREQUENCY', 'HIGH_NXDOMAIN_RATIO', 'DGA_LIKE', 'TUNNEL_LIKE')),
    severity text NOT NULL CHECK (severity IN ('MEDIUM', 'HIGH')),
    reasons jsonb NOT NULL CHECK (jsonb_typeof(reasons) = 'array' AND jsonb_array_length(reasons) > 0),
    observed_metrics jsonb NOT NULL CHECK (jsonb_typeof(observed_metrics) = 'object'),
    config_sha256 text NOT NULL CHECK (config_sha256 ~ '^[0-9a-f]{64}$'),
    threshold_config jsonb NOT NULL CHECK (jsonb_typeof(threshold_config) = 'object'),
    detector_version text NOT NULL,
    detected_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (source_ip, window_start, alert_type),
    FOREIGN KEY (source_ip, window_start)
        REFERENCES public.dns_window_features (source_ip, window_start) ON DELETE CASCADE
);
COMMENT ON TABLE public.dns_alerts IS
    'Synchronized current rule output for the latest successful full detector run; not alert history.';
COMMENT ON COLUMN public.dns_alerts.reasons IS
    'Structured satisfied comparisons: metric, operator, observed value, threshold, and satisfied flag.';
COMMENT ON COLUMN public.dns_alerts.detected_at IS
    'First detection of this currently stored alert. Preserved on evidence/config changes; updated_at tracks those changes.';
COMMIT;
