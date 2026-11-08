BEGIN;
CREATE SCHEMA IF NOT EXISTS reporting;
REVOKE ALL ON SCHEMA reporting FROM PUBLIC;
CREATE OR REPLACE VIEW reporting.vw_dns_event_analysis AS
SELECT e.id AS event_id,e.event_timestamp,date_trunc('minute',e.event_timestamp,'UTC') AS window_start,
 c.capture,CASE c.capture WHEN 'normal' THEN 'CTU Normal' ELSE 'CTU Malware' END AS capture_name,
 e.source_sha256,c.pcap_sha256,e.source_line,e.zeek_uid,host(e.source_ip) AS source_ip,
 e.source_port,host(e.destination_ip) AS destination_ip,e.destination_port,e.transport_protocol,
 e.query,e.query_type,e.response_code,e.response_code=3 AS is_nxdomain,
 CASE e.query_type WHEN 1 THEN 'A' WHEN 28 THEN 'AAAA' WHEN 12 THEN 'PTR' ELSE COALESCE(e.query_type::text,'Unknown') END AS query_type_name,
 COALESCE(e.response_code::text,'Unknown') AS response_code_name,
 f.domain_length,f.digit_count,f.digit_ratio,f.entropy
FROM public.dns_events e JOIN public.ctu_captures c USING(source_sha256)
LEFT JOIN public.dns_event_features f ON f.dns_event_id=e.id;
CREATE OR REPLACE VIEW reporting.vw_dns_window_analysis AS
WITH provenance AS (
 SELECT source_ip,window_start,min(capture) AS capture,min(capture_name) AS capture_name,
 count(DISTINCT capture) AS capture_count FROM reporting.vw_dns_event_analysis GROUP BY source_ip,window_start
), alerts AS (
 SELECT source_ip,window_start,count(*) AS alert_count,array_agg(alert_type ORDER BY alert_type) AS alert_types
 FROM public.dns_alerts GROUP BY source_ip,window_start
)
SELECT host(w.source_ip) AS source_ip,w.window_start,w.window_end,p.capture,p.capture_name,p.capture_count,
 w.query_count,w.unique_domain_count,w.nxdomain_count,w.nxdomain_ratio,
 w.avg_domain_length,w.avg_digit_ratio,w.avg_entropy,w.max_entropy,
 COALESCE(a.alert_count,0) AS alert_count,COALESCE(a.alert_types,ARRAY[]::text[]) AS alert_types,
 host(w.source_ip)||' | '||w.window_start::text AS window_key
FROM public.dns_window_features w JOIN provenance p ON host(w.source_ip)=p.source_ip AND w.window_start=p.window_start
LEFT JOIN alerts a ON a.source_ip=w.source_ip AND a.window_start=w.window_start;
CREATE OR REPLACE VIEW reporting.vw_dns_alert_analysis AS
SELECT a.id AS alert_id,host(a.source_ip) AS source_ip,a.window_start,w.window_end,w.capture,w.capture_name,
 a.alert_type,a.severity,a.observed_metrics,a.reasons,a.config_sha256,a.threshold_config,
 a.observed_metrics::text AS metrics_evidence,a.reasons::text AS threshold_evidence,
 a.threshold_config->>'name' AS config_name,a.detected_at,a.updated_at
FROM public.dns_alerts a JOIN reporting.vw_dns_window_analysis w ON host(a.source_ip)=w.source_ip AND a.window_start=w.window_start;
CREATE OR REPLACE VIEW reporting.vw_ctu_capture_sources AS
SELECT capture,capture_name,source_ip,sum(query_count)::bigint AS dns_events,count(*) AS total_windows,
 sum(nxdomain_count)::bigint AS nxdomain_events,sum(alert_count)::bigint AS alert_records,
 count(*) FILTER(WHERE alert_count>0) AS alerting_windows
FROM reporting.vw_dns_window_analysis GROUP BY capture,capture_name,source_ip;
CREATE OR REPLACE VIEW reporting.vw_ctu_detector_sources AS
SELECT capture,capture_name,source_ip,d.detector,count(*) AS total_windows,
 count(*) FILTER(WHERE d.detector=ANY(alert_types)) AS alerting_windows
FROM reporting.vw_dns_window_analysis
CROSS JOIN unnest(ARRAY['HIGH_DNS_FREQUENCY','HIGH_NXDOMAIN_RATIO','DGA_LIKE','TUNNEL_LIKE']) d(detector)
GROUP BY capture,capture_name,source_ip,d.detector;
CREATE OR REPLACE VIEW reporting.vw_ctu_feature_samples AS
SELECT capture,capture_name,source_ip,window_start,v.feature,v.value
FROM reporting.vw_dns_window_analysis
CROSS JOIN LATERAL(VALUES ('Queries per window',query_count::numeric),('Unique names',unique_domain_count::numeric),
 ('NXDOMAIN ratio (0–1)',nxdomain_ratio::numeric),('Mean length',avg_domain_length::numeric),
 ('Mean digit ratio (0–1)',avg_digit_ratio::numeric),('Mean entropy (bits)',avg_entropy::numeric)) v(feature,value);
COMMIT;
