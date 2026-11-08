-- Also apply explicitly to databases initialized before this file existed.
BEGIN;
ALTER TABLE public.dns_events
    ADD COLUMN IF NOT EXISTS source_sha256 text,
    ADD COLUMN IF NOT EXISTS source_line bigint;
CREATE UNIQUE INDEX IF NOT EXISTS dns_events_source_identity
    ON public.dns_events (source_sha256, source_line);
COMMENT ON COLUMN public.dns_events.source_sha256 IS
    'SHA-256 of complete source log bytes; NULL for legacy/manual rows.';
COMMENT ON COLUMN public.dns_events.source_line IS
    'One-based physical line number in the source log; used with source_sha256 for replay safety.';
COMMIT;
