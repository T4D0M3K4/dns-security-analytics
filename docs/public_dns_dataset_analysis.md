# CTU public DNS datasets — active provenance and findings

Only these two public captures feed the active application. Publisher: **Stratosphere Laboratory, CTU in Prague / Malware Capture Facility Project**. Sources: [CTU-Normal-4-only-DNS](https://mcfp.felk.cvut.cz/publicDatasets/CTU-Normal-4-only-DNS/) and [CTU-Malware-Capture-Botnet-25-3](https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-25-3/). Their READMEs and capinfos are retained beside ignored PCAPs. Full source/effective URLs, sizes, UTC retrieval instants and checksums are committed in [provenance.json](public_datasets/provenance.json). Accepted extraction identity is in [extraction.json](public_datasets/extraction.json).

| Capture | PCAP | Bytes | SHA-256 | Zeek packets | DNS events |
| --- | --- | ---: | --- | ---: | ---: |
| Normal |2015-03-24_capture1-only-dns.pcap|772961|`7fbefbe1a18867bc683f59890cbc0124e5f6166e5aa13035fcf1ccf2f06f7ae4`|5966|3029|
| Malware |2014-02-07_capture-win3.pcap|866582|`505f6e256381b3e427937c07ff6ab79cc5e07f205cded81324be07a29ca2db57`|5945|2680|

These hashes identify observed downloaded bytes, not publisher-authenticated signatures. Publisher capinfos SHA-1 matches both files. The [publisher FAQ](https://www.stratosphereips.org/datasets-faq) permits use with attribution; the READMEs contain no dataset-specific license. Do not transfer CTU-13 licensing to these different captures. Attribution: Stratosphere. (2015). Stratosphere Laboratory Datasets. Retrieved2026-11-03 UTC. Preserve citations and usage references when redistributing materials.

Download allowlist contains only2 PCAPs,2 READMEs and2 capinfos files. No malware executables, archives or extracted payloads are downloaded/executed. The existing digest-pinned Zeek script runs network-disabled with read-only input, default checksum handling and JSON output. Accepted extraction identity is retained for reproducible replay; raw inputs are immutable. All5709 records pass the existing mapping, with0 rejected, complete line identities and lexical rows. Commands for fresh extraction, acceptance and idempotent processing are in [reproduction_guide.md](reproduction_guide.md).

## Descriptive findings

| Capture/source | Events | Windows | Alerts | Interpretation |
| --- | ---: | ---: | ---: | --- |
| Normal /10.0.0.34 |3029|110|4|Four >=100-query minutes, no other rules|
| Malware /10.0.2.103 |2678|72|131|67 NXDOMAIN and64 DGA-like activations,64 overlapping|
| Malware /fe80::50be:8acf:be49:8c14 |2|1|0|Small non-alerting source, retained|

Normal DNS timestamps:2015-03-24 17:23:32.619989–19:18:13.398143 UTC (1:54:40.778154). Malware:1970-01-01 00:01:11.745356–01:35:54.139607 UTC (1:34:42.394251). The publisher capinfos also records1970; the packet clock appears epoch-relative or unset. Its actual historical calendar time is **unknown**. Zeek/parser did not invent these values. Minute aggregation preserves the recorded axis; timestamps must not be corrected from filenames. No cross-capture source/minute collisions were found; membership is verified by hashes, not these timestamps.

| Window metric | Normal min / median / max | Malware min / median / max |
| --- | --- | --- |
|query_count|2 /12.5 /248|2 /40 /40|
|unique_domain_count|1 /4 /86|1 /40 /40|
|nxdomain_ratio|0 /0 /0.076923|0 /1 /1|
|avg_domain_length|12.2 /17.649287 /29|4 /29.2 /30.025|
|avg_digit_ratio|0 /0.017738 /0.100099|0 /0 /0|
|avg_entropy|3.026987 /3.276908 /3.883337|2 /4.043226 /4.125047|

Medians use continuous linear interpolation. The normal capture exceeds the frequency rule in4/110 minutes, demonstrating why this alert is not automatic proof of attack. Malware has no >=100-query window; DGA-like activation relies on uniqueness, NXDOMAIN and entropy together, not frequency100. Nine malware windows lack DGA alerts: at least one condition fails; overlapping failures are query count6, unique names6, NXDOMAIN ratio2, entropy8. Exact values/reasons are in ignored data/processed/ctu/summary.json. Neither capture reaches mean length60; no tunnel-like alert is generated. This is not a sensitivity measurement for tunneling.

## Label reliability and methodological limits

Normal README describes privacy-filtered home-network DNS activity: a dataset-level benign characterization, not independently verified event labels. Malware README identifies infected Win3 /10.0.2.103 and DGA-associated DNS behavior for a resolver tuple. This supports investigation of that source/connection, but does not make all captured DNS, IPv6 traffic, individual Zeek events or entire minutes malicious. Tuple labels require documented verified flow-to-event/window mapping before formal evaluation. Current registry supplies provenance only.

Results are **descriptive detector activation rates**, not precision/recall/F1 or confirmed true/false positives. Thresholds were selected historically with controlled synthetic calibration and held fixed for CTU; no CTU retuning occurred. Small captures, retries, missing replies, resolver artifacts and uncertain timestamps limit generalization. Do not equate entropy/NXDOMAIN with malware intent.

See [project_summary.md](project_summary.md), [release audit](release_audit.md) and [Superset](superset.md). Generated reports and raw PCAP/log bytes are excluded from Git.
