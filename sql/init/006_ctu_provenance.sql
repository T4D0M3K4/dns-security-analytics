-- Only the CTU replacement uses this migration. Legacy initialized volumes are untouched.
BEGIN;
CREATE TABLE IF NOT EXISTS public.ctu_captures (
 capture text PRIMARY KEY CHECK (capture IN ('normal','malware')),
 source_sha256 text UNIQUE NOT NULL CHECK(source_sha256 ~ '^[0-9a-f]{64}$'),
 pcap_sha256 text NOT NULL CHECK(pcap_sha256 ~ '^[0-9a-f]{64}$')
);
ALTER TABLE public.dns_events ALTER COLUMN source_sha256 SET NOT NULL;
ALTER TABLE public.dns_events ALTER COLUMN source_line SET NOT NULL;
DO $$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conname='dns_events_ctu_source') THEN
  ALTER TABLE public.dns_events ADD CONSTRAINT dns_events_ctu_source
   FOREIGN KEY(source_sha256) REFERENCES public.ctu_captures(source_sha256);
 END IF;
END $$;
COMMENT ON TABLE public.ctu_captures IS 'Accepted immutable extraction identity, not event/window maliciousness labels.';
COMMIT;
