# Third-party notices and dataset attribution

The root [MIT License](LICENSE), copyright (c) 2026 Luka Šućur, covers original DNS Security Analytics source, documentation and project-authored configuration. It does not relicense dependencies, container contents, trademarks or datasets.

## Source-tree review

No vendored third-party implementation, dependency binary, upstream UI bundle, font, logo or screenshot is included in the reviewed public source tree. The Superset YAML files are sanitized project dashboard/dataset/chart definitions; Python helpers and CSS are project configuration and automation, not a copy of the Superset implementation. Existing dataset attribution is retained in docs/public_datasets/provenance.json and docs/public_dns_dataset_analysis.md. This review does not claim that third-party software itself is MIT licensed.

## External software

These components are fetched/installed separately, not bundled into the public source export:

| Component | License/reference | Scope |
|---|---|---|
| Apache Superset 6.1.0 | [Apache License 2.0](https://github.com/apache/superset/blob/6.1.0/LICENSE.txt), [upstream notices](https://github.com/apache/superset/blob/6.1.0/NOTICE) | Base image and its dependencies retain upstream licenses/notices |
| Zeek 9.0.1 | [BSD-style three-clause license and file-specific notices](https://github.com/zeek/zeek/blob/v9.0.1/COPYING) | Official offline processing image |
| PostgreSQL | [PostgreSQL License](https://www.postgresql.org/about/licence/) | Analytics and Superset metadata services |
| Psycopg 3 | [LGPLv3](https://github.com/psycopg/psycopg/blob/master/LICENSE.txt) | Python PostgreSQL driver; binary distributions also contain separately licensed libraries |
| Psycopg 2 | [LGPL with exceptions / upstream license](https://www.psycopg.org/docs/license.html) | Pinned Superset PostgreSQL driver; not relicensed by this project |
| pytest | [MIT, copyright Holger Krekel and others](https://github.com/pytest-dev/pytest/blob/main/LICENSE) | Installed test dependency |
| Python | [Python license and incorporated-software notices](https://docs.python.org/3/license.html) | Interpreter; installed separately |

Superset also brings libraries such as SQLAlchemy, Flask, requests and PyYAML. This table is not a complete transitive SBOM or a substitute for the notices shipped with each exact distribution. No upstream notice was removed. Retain applicable licenses/notices when separately redistributing images, wheels or other third-party software; this source-only export does not contain those distributions.

## CTU datasets: separate rights and attribution

Sources: Stratosphere Laboratory, CTU in Prague / Malware Capture Facility Project:

- [CTU-Normal-4-only-DNS](https://mcfp.felk.cvut.cz/publicDatasets/CTU-Normal-4-only-DNS/), file 2015-03-24_capture1-only-dns.pcap.
- [CTU-Malware-Capture-Botnet-25-3](https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-25-3/), file 2014-02-07_capture-win3.pcap.

Attribution recorded by the project: **Stratosphere. (2015). Stratosphere Laboratory Datasets.** Source download provenance and observed hashes are in [provenance.json](docs/public_datasets/provenance.json). Consult the [publisher FAQ](https://www.stratosphereips.org/datasets-faq), dataset READMEs and applicable terms. No dataset-specific redistribution license was identified in the downloaded READMEs; do not transfer CTU-13 licensing to these different captures.

**MIT does not grant rights to redistribute CTU PCAPs, publisher documents, extracted traffic or third-party material.** The export includes project-authored references/provenance only, not PCAPs, Zeek logs, publisher README copies or binary payloads. Download the allowlisted files from their publishers for local analysis. Do not execute captured content or contact captured domains.

Upstream Apache Superset attribution (from its NOTICE, retained here as acknowledgement):

> Apache Superset  
> Copyright 2016-2024 The Apache Software Foundation  
> This product includes software developed at The Apache Software Foundation (http://www.apache.org/).
