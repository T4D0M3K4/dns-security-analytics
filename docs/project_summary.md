# CTU-only technical summary

**Analiza DNS saobraćaja i detekcija bezbjednosnih anomalija primjenom Data Engineering tehnika** analyzes offline public DNS traffic with a reproducible engineering pipeline and explainable rule alerts.

## Implementation

Pinned Docker Zeek 9.0.1 extracts two CTU PCAPs. Python >=3.11 / psycopg3 validates JSONL line by line, converts epoch timestamps to aware UTC, and inserts batches into PostgreSQL17. Source SHA-256 + line provides replay identity. `ctu_captures` links accepted logs to PCAP identity. Raw events remain separate from lexical rows, minute rows and alerts. `analysis.ctu` guards the only active environment and reuses ingestion/features/detection; public_datasets handles allowlisted downloads and offline inspection. Six live reporting views serve read-only Superset6.1.0. No streaming, ML or external DNS contact.

Lexical features use the full query lowercased with **one** final root dot removed: character length, ASCII digit count, digit ratio (0 for empty), Shannon base-2 character entropy (0 for empty). No suffix decomposition. UTC source-minute features: query_count, distinct normalized non-null names, NXDOMAIN count/ratio, lexical mean length/digit ratio/entropy, maximum entropy. Only available lexical rows enter averages. Minute end is exclusive; 1970 timestamps are retained. Core modules and schema001–005 are unchanged.

## Fixed rules and evidence

| Alert | Conditions (inclusive) | Severity |
| --- | --- | --- |
| HIGH_DNS_FREQUENCY | query_count >=100 | MEDIUM |
| HIGH_NXDOMAIN_RATIO | query_count >=20 and nxdomain_ratio >=0.50 | MEDIUM |
| DGA_LIKE | query_count >=20, unique_domain_count >=20, nxdomain_ratio >=0.50, avg_entropy >=4.0 | HIGH |
| TUNNEL_LIKE | query_count >=20, unique_domain_count >=20, avg_domain_length >=60, avg_entropy >=4.0 | HIGH |

Overlaps are retained. Alert identity is source/minute/type; synchronization inserts/updates current matches and removes stale matches. Evidence stores observed metrics, each satisfied condition, threshold snapshot and config hash. Current configuration SHA-256: `0a7631c7ca4d13ff112b913830714ac61e19f508457e8ede9df0216f89ed7a33`. It remains named `seed42-initial-v1` to preserve historical traceability. Thresholds were originally selected using a controlled synthetic calibration, **not** CTU; historical experiment claims do not transfer to public captures.

## Measured replacement results

| Capture | PCAP packets | Events / lexical | Windows | Frequency | NXDOMAIN | DGA-like | Tunnel-like |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| CTU Normal |5966|3029|110|4|0|0|0|
| CTU Malware |5945|2680|73|0|67|64|0|
| Total |11911|5709|183|4|67|64|0|

135 alert records represent 71 distinct alerting windows; 64 malware windows have two types. Normal frequency activation4/110=3.6364%; malware NXDOMAIN67/73=91.7808%, DGA64/73=87.6712%. These are **descriptive activations**, not confirmed attacks or false alarms. Pipeline replay and all persisted fact-row fingerprints agree. The release audit records current tests and verification scope; these totals are measured results, not application constants.

Dashboards: DNS Traffic Overview (8 charts), DNS Security & Anomaly Analysis (8), CTU Security Comparison (5); 6 datasets,3 published dashboards,21 charts. Capture and source filters use explicit provenance. Capture activity is compared categorically to avoid misleading1970/2015 continuous timelines. Feature summaries use actual window samples, median/p95 linearly interpolated at `(n-1)*p`.

## Interpretation and limits

Normal is a publisher dataset-level description, not independently verified per-event benign truth. The malware README identifies infected10.0.2.103 and DGA-associated DNS tuple, insufficient to label every event or minute. No formal precision/recall/F1 is computed for CTU. Epoch-relative malware timestamps are present in packet metadata and Zeek; UTC minute aggregation is valid for the recorded axis, not evidence of a1970 infection. Capture framing, incomplete responses, retries, resolver effects and small sample diversity limit conclusions. High NXDOMAIN or entropy is evidence for investigation, not proof of maliciousness. No threshold retuning occurred.

Historical local/synthetic code, walkthroughs and assets are absent from the current source tree; their development history remains in Git. The earlier controlled calibration is the historical origin of the unchanged thresholds, not a runtime dependency. See [reproduction](reproduction_guide.md), [data provenance](public_dns_dataset_analysis.md), [Superset](superset.md) and [release audit](release_audit.md). Future work could establish verified flow-to-window ground truth and study robustness; these are proposals, not implemented capabilities.
