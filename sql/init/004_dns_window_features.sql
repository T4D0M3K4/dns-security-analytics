-- Apply explicitly to existing volumes; fresh volumes run this at initialization.
BEGIN;
CREATE TABLE IF NOT EXISTS public.dns_window_features (
    source_ip inet NOT NULL,
    window_start timestamptz NOT NULL,
    window_end timestamptz NOT NULL,
    query_count bigint NOT NULL CHECK (query_count > 0),
    unique_domain_count bigint NOT NULL CHECK (unique_domain_count BETWEEN 0 AND query_count),
    nxdomain_count bigint NOT NULL CHECK (nxdomain_count BETWEEN 0 AND query_count),
    nxdomain_ratio double precision NOT NULL CHECK (nxdomain_ratio BETWEEN 0 AND 1),
    avg_domain_length double precision CHECK (avg_domain_length >= 0 AND avg_domain_length < 'Infinity'::double precision),
    avg_digit_ratio double precision CHECK (avg_digit_ratio BETWEEN 0 AND 1),
    avg_entropy double precision CHECK (avg_entropy >= 0 AND avg_entropy < 'Infinity'::double precision),
    max_entropy double precision CHECK (max_entropy >= 0 AND max_entropy < 'Infinity'::double precision),
    calculated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (source_ip, window_start),
    CHECK (window_start = date_trunc('minute', window_start, 'UTC')),
    CHECK (window_end = window_start + interval '1 minute')
);
COMMENT ON TABLE public.dns_window_features IS
    'One-minute UTC source-IP activity aggregates. Window end is exclusive. No anomaly classification.';
COMMENT ON COLUMN public.dns_window_features.avg_entropy IS
    'Mean over available lexical rows only; NULL when none are available. Other lexical aggregates use the same population.';
COMMIT;
