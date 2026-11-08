# Publication checklist and verification

Review date: **2026-11-08**. Scope: the current CTU-only source working tree and a separate history-free public export. No publication, commit, Git remote change or history rewrite was performed.

## License and attribution

- [x] Complete standard [MIT License](../LICENSE), with copyright (c) 2026 **Luka Šućur**, explicitly authorized by the owner. Operative wording matches the canonical SPDX MIT text after copyright substitution and whitespace normalization.
- [x] Package metadata and README identify MIT for original project code.
- [x] [Third-party notices](../THIRD_PARTY_NOTICES.md) distinguish external dependencies/images and retain publisher/upstream attribution. No vendored third-party implementation or binary asset was identified in the export.
- [x] No CTU PCAP, Zeek log, publisher README copy, dependency wheel or container image is included. MIT does not grant redistribution rights for those materials.

## Public-copy construction

The export uses existing reviewed tracked files from the **working tree**, omitting deleted files, plus the explicitly reviewed new LICENSE, THIRD_PARTY_NOTICES.md and this audit document. It does not use `git archive HEAD`, which would restore obsolete files and lose uncommitted cleanup changes. It contains **103 source/configuration/documentation files**, including empty data-directory markers.

- [x] No .git directory or old history, archive, synthetic/local experiment implementation, generated reports, caches, filled environment file, PCAP/log data, database dump or volume copied.
- [x] Current modifications and cleanup deletions included; executable script permissions preserved; final file hashes checked against the reviewed working tree.
- [x] Only .env.example is included; secrets are blank. Runtime credentials are generated privately after initialization.
- [x] Dashboard assets remain sanitized:3 dashboards,21 charts,6 datasets,32 YAML files including database placeholder/metadata.
- [x] Copyright holder identity is intentionally public. No author email, old author history or local-capture history is imported. Other names in notices are deliberate third-party attribution.

The export is separate from the private installation/runtime verification directory. Its exact location and file-hash manifest are supplied in the operator handoff, not embedded as machine-specific paths in public source. Recheck the tree if files are added after this review.

## Tests and current application

| Verification | Result |
|---|---|
| Existing isolated full suite on identical reviewed source/tests | **114 passed,0 skipped**; dedicated test database, active fact rows unchanged |
| Fresh-venv installation from private copy of exported source | Passed; MIT notice present in installed package metadata; pip check passes |
| Fresh-venv default tests | **104 passed,10 skipped**; skips are deliberate database opt-ins, covered by the isolated full run |
| Fresh environment versions | Python3.14.4, psycopg3.3.8, pytest9.2.0 |
| Python/CLI checks |19 modules import; Python compiles; retained CLI help and shell syntax validated |
| Compose | Active configuration and independent verification project validate; analytics/metadata have separate volumes |
| Public data | Fresh allowlisted downloads match all6 recorded checksums; pinned offline Zeek processes both PCAPs independently |
| Fresh database pipeline | Init001–006 succeeds; unchanged ingestion/features/detection reproduce5709/5709/183/135; replay full-row fingerprints match |
| Reporting | Six live CTU views and existing reader SQL provision on fresh database; reporting migration replay succeeds |
| Fresh Superset | Sanitized bundle imports into fresh metadata:3 published dashboards,21 executable charts,6 datasets; read-only ACL write probes denied |
| Superset roundtrip | Fresh sanitized export/reimport succeeds with32 YAML files; original public asset bundle unchanged |

Actual CTU findings:

| Capture | Events / lexical rows | Windows | Frequency | NXDOMAIN | DGA-like | Tunnel-like |
|---|---:|---:|---:|---:|---:|---:|
|CTU Normal|3029|110|4|0|0|0|
|CTU Malware|2680|73|0|67|64|0|
|Total|5709|183|4|67|64|0|

There are **135 alert records and71 distinct alerting windows**. DGA_LIKE activation is64/73 malware-capture windows (87.67%), a descriptive rate, **not precision, recall or F1**. The original1970 timestamps and exact fixed configuration remain unchanged. The earlier controlled synthetic calibration is the documented threshold origin, not an active input or a CTU evaluation claim.

## Security review

- [x] All export files reviewed for current private-secret values, provider-token/key patterns, unexpected binaries, large artifacts, private configuration, local home paths, dataset material and broken Markdown links.
- [x] detect-secrets **1.5.0** scans the full export with `--all-files --no-verify`: **0 findings**. Credential network verification is disabled. No detected value is printed or submitted to an external service.
- [x] Superset database URI is a deliberate placeholder; no real connection password, authentication token or SECRET_KEY is included.
- [x] Private IP addresses are the documented CTU source addresses or loopback/test documentation addresses, not undisclosed personal hosts. No captured domains are resolved/contacted.
- [x] Working-repository staging remains empty; raw/generated data and private config examples are ignored. No Git remote is created or modified.

A scan is evidence within its scope, not a guarantee against every possible secret. The old repository remains private and unchanged in history; its historical reports are not part of the new export. Do not import that .git directory or push the old history when creating the new public repository.

## Reproducibility scope

Fresh verification uses a private source copy, new venv, independently generated credentials, project dns-ctu-publication-check, new volumes and ports55436/8091. Core pipeline functions execute only against that independently identified cluster. The public export stays free of runtime files.

A complete **clean Git-clone execution of the primary guarded CLI has not been performed**. The export intentionally has no .git, and the primary CLI requires committed core files plus the fixed dns-ctu/55434 environment. No guard or application semantics were weakened for verification. Cached pinned container images were used; a fresh image rebuild and cross-platform reproduction were not exercised. Python dependencies use version ranges rather than a full transitive lockfile.

The source export therefore has no identified secret or source-licensing blocker within this review, but full clean-clone verification is **not claimed**. Dataset rights remain separate; only download instructions/provenance are distributed. The deployment is loopback-only academic infrastructure, not a hardened public service.

## Owner publication checklist

- [ ] Review the prepared export and confirm the intended public copyright identity and notices.
- [ ] Initialize a **new** Git repository in the export, review staged filenames/diff and create the initial source commit. Do not copy old .git/history.
- [ ] Review the Git author email before committing. The required copyright name does not require publishing a private email.
- [ ] Reproduce from the final commit/new clone if full clean-clone verification is needed. Use a separate machine or isolated Docker context for the fixed guarded endpoint; never reset the working CTU environment to test this.
- [ ] Create the remote repository and push only when separately authorized; no such action was taken here.

Commands to run manually from the prepared export:

```bash
git init -b main
git add .
git diff --cached --check
git diff --cached --stat
git status --short
git commit -m "Initial CTU-only DNS Security Analytics release (MIT)"
```

The initial commit is required before the normal runner's `HEAD` provenance comparison. Follow [reproduction_guide.md](reproduction_guide.md) after committing. At the time of this export review, screenshots were README placeholders. The README now includes dashboard screenshots from `docs/images/`; those later additions are outside the original export verification scope. Temporary verification data, secrets and tool outputs are retained outside the export and are not runtime dependencies.
