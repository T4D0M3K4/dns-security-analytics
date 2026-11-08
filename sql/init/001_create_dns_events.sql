BEGIN;

CREATE TABLE public.dns_events (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    event_timestamp timestamptz NOT NULL,
    zeek_uid text NOT NULL,
    source_ip inet NOT NULL,
    source_port integer NOT NULL CHECK (source_port BETWEEN 0 AND 65535),
    destination_ip inet NOT NULL,
    destination_port integer NOT NULL CHECK (destination_port BETWEEN 0 AND 65535),
    transport_protocol text NOT NULL,
    query text,
    query_class integer CHECK (query_class BETWEEN 0 AND 65535),
    query_type integer CHECK (query_type BETWEEN 0 AND 65535),
    response_code integer CHECK (response_code BETWEEN 0 AND 65535),
    rejected boolean,
    answers text[],
    ttls double precision[],
    ingested_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE public.dns_events IS
    'Raw normalized Zeek dns.log events; no detection or derived features.';
COMMENT ON COLUMN public.dns_events.zeek_uid IS
    'Zeek connection UID; not unique because one connection can contain multiple DNS events.';
COMMENT ON COLUMN public.dns_events.query_class IS
    'Numeric Zeek qclass; NULL when absent. DNS codes and ports use integer for unsigned 16-bit values.';
COMMENT ON COLUMN public.dns_events.answers IS
    'Ordered Zeek answers, including IP addresses and non-address records; NULL means missing, empty array means known empty.';
COMMENT ON COLUMN public.dns_events.ttls IS
    'Ordered Zeek TTLs in seconds; double precision preserves fractional intervals. No equal-length constraint with answers is assumed.';
COMMENT ON COLUMN public.dns_events.event_timestamp IS
    'Zeek ts converted from Unix seconds to a timezone-aware instant (microsecond precision).';

COMMIT;
