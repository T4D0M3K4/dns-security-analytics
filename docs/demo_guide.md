# CTU demonstration — 12 minutes

Prepare beforehand: start `dns-ctu`, run the guarded pipeline, verify health, login at http://localhost:8089, and open three dashboard tabs. Use precomputed results; do not download, rebuild images or reset volumes during the presentation. Commands run at repository root. SQL can be pasted into `docker compose --env-file .env.ctu -f compose.yaml exec postgres sh -c 'psql -X -U "$POSTGRES_USER" -d "$POSTGRES_DB"'`.

| Step | Duration | Command / URL | Expected finding and explanation |
| --- | --- | --- | --- |
| Goal and architecture |1min|README.md architecture|Two immutable public captures → Zeek → Python/PostgreSQL → features/rules/evidence → Superset. No live DNS or malware execution.|
| PCAP extraction |1min|`head -n 1 <accepted-normal-directory>/dns.log` (use the extraction manifest path); optionally `./scripts/process_pcap.sh data/raw/pcap/public/normal/2015-03-24_capture1-only-dns.pcap`|JSON Zeek fields; separate output and read-only offline extraction. Optional rerun is extraction only, do not register a new hash during demo.|
| Provenance/data model |1min|`SELECT capture,source_sha256,pcap_sha256 FROM public.ctu_captures;` then scripts/verify_ctu.sql|5709 raw+lexical,183 windows,135 alerts; source/line keys and separated feature layers.|
| Features |1min|`SELECT query,domain_length,digit_ratio,entropy FROM reporting.vw_dns_event_analysis ORDER BY entropy DESC LIMIT 5;`|Deterministic full-name lexical features, not suffix-aware domains.|
| Behavioral features/rules |1min|`SELECT capture_name,source_ip,window_start,query_count,unique_domain_count,nxdomain_ratio,avg_entropy FROM reporting.vw_dns_window_analysis ORDER BY avg_entropy DESC LIMIT 5;`|One source/UTC minute; show src/dns_security_analytics/detection/default_rules.json without editing. Preserve1970 malware times.|
| Explainable alert |1min|`SELECT capture_name,alert_type,severity,observed_metrics,reasons,config_sha256 FROM reporting.vw_dns_alert_analysis WHERE alert_type='DGA_LIKE' ORDER BY source_ip,window_start LIMIT 1;`|Exact metric values and satisfied thresholds, multiple types may describe one window.|
| Traffic overview |1min|http://localhost:8089/superset/dashboard/dns-traffic-overview/|5709 events; filter Capture, show query types/response codes/top names.|
| Security analysis |1.5min|http://localhost:8089/superset/dashboard/dns-security-anomaly-analysis/|135 alert records; show source/capture, NXDOMAIN/volume, entropy/length and evidence table. Alert-type filter affects alert charts, not window plots.|
| CTU comparison |1.5min|http://localhost:8089/superset/dashboard/ctu-security-comparison/|Normal4/110 frequency; malware67/73 NXDOMAIN and64/73 DGA; zero tunnel detections. Detector filter applies comparison count/rate only. Actual sample distributions, not inferred distributions.|
| Methodology and conclusion |1min|docs/public_dns_dataset_analysis.md and project_summary.md|Publisher labels do not establish minute-level truth. Activations are descriptive; historical controlled calibration does not establish CTU or production performance. No formal CTU confusion matrix exists.|

If the accepted run paths differ, read `docs/public_datasets/extraction.json` or the generated accepted manifest. Never guess paths or show `.env.ctu` on screen. Source tables and thresholds are not edited during the presentation.

Fallback: retain screenshots and sanitized YAML assets plus release-audit verification tables locally before presenting. If Superset fails, use read-only psql queries and the report. If Docker fails, present saved screenshots and source/provenance/configuration evidence, clearly identify them as saved results, not live execution. Internet is unnecessary after images/data are cached; do not improvise live lookups. Historic evaluation may be discussed only as threshold history, never as CTU accuracy.
