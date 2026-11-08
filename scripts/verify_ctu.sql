\set ON_ERROR_STOP on
BEGIN READ ONLY;
SET LOCAL timezone='UTC';
SELECT 'dns_events' AS layer,count(*) FROM public.dns_events
UNION ALL SELECT 'dns_event_features',count(*) FROM public.dns_event_features
UNION ALL SELECT 'dns_window_features',count(*) FROM public.dns_window_features
UNION ALL SELECT 'dns_alerts',count(*) FROM public.dns_alerts;
SELECT capture_name,sum(dns_events) AS events,sum(total_windows) AS windows,
 sum(nxdomain_events)::numeric/nullif(sum(dns_events),0) AS nxdomain_ratio,
 sum(alert_records) AS alert_records,sum(alerting_windows) AS alerting_windows
FROM reporting.vw_ctu_capture_sources GROUP BY capture_name ORDER BY capture_name;
SELECT capture_name,detector,sum(alerting_windows) AS alerting_windows,sum(total_windows) AS windows,
 100.0*sum(alerting_windows)/nullif(sum(total_windows),0) AS activation_pct
FROM reporting.vw_ctu_detector_sources GROUP BY capture_name,detector ORDER BY capture_name,detector;
SELECT 'events' AS grain,count(*) AS rows,count(DISTINCT event_id) AS unique_keys FROM reporting.vw_dns_event_analysis
UNION ALL SELECT 'windows',count(*),count(DISTINCT(source_ip,window_start)) FROM reporting.vw_dns_window_analysis
UNION ALL SELECT 'alerts',count(*),count(DISTINCT alert_id) FROM reporting.vw_dns_alert_analysis;
SELECT count(*) AS mixed_capture_windows FROM reporting.vw_dns_window_analysis WHERE capture_count<>1;
SELECT count(*) AS unknown_sources FROM public.dns_events e LEFT JOIN public.ctu_captures c USING(source_sha256) WHERE c.capture IS NULL;
SELECT count(*) AS orphan_lexical FROM public.dns_event_features f LEFT JOIN public.dns_events e ON e.id=f.dns_event_id WHERE e.id IS NULL;
SELECT count(*) AS missing_lexical FROM public.dns_events e LEFT JOIN public.dns_event_features f ON e.id=f.dns_event_id WHERE e.query IS NOT NULL AND f.dns_event_id IS NULL;
SELECT count(*) AS orphan_alerts FROM public.dns_alerts a LEFT JOIN public.dns_window_features w USING(source_ip,window_start) WHERE w.source_ip IS NULL;
SELECT capture_name,source_ip,min(event_timestamp) AS first_utc,max(event_timestamp) AS last_utc,count(*) AS events
FROM reporting.vw_dns_event_analysis GROUP BY capture_name,source_ip ORDER BY capture_name,source_ip;
SELECT config_sha256,count(*) AS alerts FROM public.dns_alerts GROUP BY config_sha256;
COMMIT;
