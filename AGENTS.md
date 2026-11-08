# DNS Security Analytics — CTU-only project specification

Academic project: **Analiza DNS saobraćaja i detekcija bezbjednosnih anomalija primjenom Data Engineering tehnika**, course Zaštita komunikacija i protokoli.

## Active scope

Only CTU-Normal-4-only-DNS and CTU-Malware-Capture-Botnet-25-3 participate in active processing, reporting and presentation. Local Wireshark and generated scenarios are not part of this repository or its active inputs. Historical threshold calibration must remain accurately attributed.

CTU PCAPs → pinned Docker Zeek → JSON dns.log → Python ingestion → PostgreSQL → lexical features → UTC minute features → four configurable rules → explainable alerts → live reporting views → Apache Superset 6.1.0.

## Constraints

- Preserve raw bytes and original timestamps, including the malware capture's 1970 epoch. Never contact captured domains or execute captured content.
- Use `compose.yaml`, project `dns-ctu`, explicit `.env.ctu`, PostgreSQL loopback 55434 and Superset 8089. Never load CTU data into the archived demo cluster or reuse its credentials/volumes.
- Primary runner: `python -m dns_security_analytics.analysis.ctu --env-file .env.ctu`. It checks Docker cluster identity, accepted hashes, provenance and cross-capture minute collisions before writers.
- Keep ingestion, pure lexical calculations, SQL aggregation, rule evaluation, and persistence separate. Preserve current definitions and thresholds unless explicitly authorized.
- Capture membership comes from source SHA-256 and line identity, never timestamps alone. The registry is not an event maliciousness label.
- Reports describe detector activation. Insufficient event/window ground truth prevents CTU precision/recall/F1 or true/false-positive claims.
- Python >=3.11, type hints, pytest; simple Docker Compose infrastructure. Do not introduce distributed systems, ML, new datasets or detectors without authorization.
- Credentials are environment configuration, never tracked. Superset metadata is isolated and analytics connections are read-only. Assets use supported REST APIs, not metadata SQL writes.
- Run default unit tests with `.venv/bin/python -m pytest -q`. Run mutating integration tests only with `scripts/test_isolated.py`, never by exporting demo credentials.
- Obsolete experiments are available only in Git history. Do not restore them as active imports. Retain local volumes, raw data and backups; repository cleanup must not alter those resources.

Read README.md and docs/reproduction_guide.md before operating infrastructure. Explain significant architecture changes before implementation. Do not commit automatically.
