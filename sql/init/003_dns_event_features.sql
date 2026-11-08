-- Apply explicitly to existing database volumes; fresh volumes run this at init.
BEGIN;
CREATE TABLE IF NOT EXISTS public.dns_event_features (
    dns_event_id bigint PRIMARY KEY REFERENCES public.dns_events(id) ON DELETE CASCADE,
    domain_length integer NOT NULL CHECK (domain_length >= 0),
    digit_count integer NOT NULL CHECK (digit_count >= 0 AND digit_count <= domain_length),
    digit_ratio double precision NOT NULL CHECK (digit_ratio BETWEEN 0 AND 1),
    entropy double precision NOT NULL CHECK (entropy >= 0 AND entropy < 'Infinity'::double precision),
    calculated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE public.dns_event_features IS
    'Current per-event lexical features of the complete query, lowercased with one trailing root dot removed. Raw events are unchanged.';
COMMENT ON COLUMN public.dns_event_features.digit_count IS
    'Count of ASCII digits 0-9 only.';
COMMENT ON COLUMN public.dns_event_features.entropy IS
    'Base-2 Shannon character entropy in bits; zero for an empty normalized query.';
COMMIT;
