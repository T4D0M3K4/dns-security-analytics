"""Isolated public capture download and offline Zeek JSON exploration; no database access."""

import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
import hashlib
import json
from math import fsum
from pathlib import Path
import subprocess
import tempfile
from typing import Any

from dns_security_analytics.features.lexical import calculate_features, normalize_query
from dns_security_analytics.transformation.dns import parse_dns_line

BASE = "https://mcfp.felk.cvut.cz/publicDatasets/"
DATASETS = {
    "normal": ("CTU-Normal-4-only-DNS", "2015-03-24_capture1-only-dns"),
    "malware": ("CTU-Malware-Capture-Botnet-25-3", "2014-02-07_capture-win3"),
}
REQUIRED = ("ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto")
WINDOW_METRICS = ("query_count", "unique_domain_count", "nxdomain_count", "nxdomain_ratio",
                  "avg_domain_length", "avg_digit_ratio", "avg_entropy", "max_entropy")


def sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def write_json(path: Path, document: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(document, indent=2, sort_keys=True, allow_nan=False) + "\n")
    temporary.replace(path)


def download(root: Path, manifest: Path) -> dict[str, Any]:
    """Fetch only six allowlisted files, atomically, with HTTPS-only redirects.

    Existing files require their recorded hash; they are never overwritten.
    PCAP contents are not decoded here. capinfos files are publisher metadata.
    """
    report = json.loads(manifest.read_text()) if manifest.exists() else {
        "format_version": 1, "attribution": "Stratosphere Laboratory, CTU in Prague / Malware Capture Facility Project",
        "usage_reference": "https://www.stratosphereips.org/datasets-faq",
        "usage": "Publisher FAQ permits use with attribution. No dataset-specific license found in the READMEs; do not infer CTU-13's license.",
        "files": [],
    }
    recorded = {entry["source_url"]: entry for entry in report["files"]}
    for name, (directory, stem) in DATASETS.items():
        for filename in (stem + ".pcap", "README.md", stem + ".capinfos"):
            url = BASE + directory + "/" + filename
            target = root / name / filename
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.exists():
                if url not in recorded or sha256(target) != recorded[url]["sha256"]:
                    raise ValueError(f"Unverified existing file; refusing overwrite: {target}")
                print(f"Verified existing {target}")
                continue
            with tempfile.TemporaryDirectory(dir=target.parent) as temporary:
                partial = Path(temporary) / "download.part"
                result = subprocess.run([
                    "curl", "--silent", "--show-error", "--fail", "--location",
                    "--proto", "=https", "--proto-redir", "=https", "--retry", "3",
                    "--retry-delay", "2", "--connect-timeout", "15", "--max-time", "120",
                    "--max-filesize", "10485760", "--output", str(partial),
                    "--write-out", "%{url_effective}", url,
                ], check=True, capture_output=True, text=True)
                if not partial.stat().st_size:
                    raise ValueError(f"Empty download: {url}")
                if filename.endswith(".pcap"):
                    with partial.open("rb") as stream:
                        magic = stream.read(4)
                    if magic not in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d", b"\x0a\x0d\x0d\x0a"):
                        raise ValueError(f"Download has no PCAP signature: {url}")
                partial.replace(target)
            entry = {"dataset": name, "path": str(target), "source_url": url,
                     "effective_url": result.stdout, "bytes": target.stat().st_size,
                     "sha256": sha256(target), "retrieved_at_utc": datetime.now(timezone.utc).isoformat()}
            report["files"] = [item for item in report["files"] if item["source_url"] != url] + [entry]
            write_json(manifest, report)
            print(f"Downloaded {target}: {entry['bytes']} bytes, SHA-256 {entry['sha256']}")
    return report


def distribution(values: list[float | int]) -> dict[str, Any]:
    """Linear interpolated percentiles at (n-1)*p, matching percentile_cont."""
    ordered = sorted(values)
    if not ordered:
        return {"count": 0, **dict.fromkeys(("minimum", "p25", "p50", "p75", "p95", "maximum", "mean"))}

    def percentile(p: float) -> float:
        position = (len(ordered) - 1) * p
        left = int(position)
        return ordered[left] + (ordered[min(left + 1, len(ordered) - 1)] - ordered[left]) * (position - left)

    return {"count": len(ordered), "minimum": ordered[0], "p25": percentile(.25),
            "p50": percentile(.5), "p75": percentile(.75), "p95": percentile(.95),
            "maximum": ordered[-1], "mean": fsum(ordered) / len(ordered)}


def inspect_log(path: Path) -> dict[str, Any]:
    """Stream JSONL through the real ingestion validator and pure lexical functions.

    Retains distinct names/window samples for these small research captures.
    This is descriptive offline inspection, not a replacement ingestion pipeline.
    """
    sources, destinations, qtypes, rcodes, names, tuples = (Counter() for _ in range(6))
    missing, errors, structures = Counter(), Counter(), defaultdict(Counter)
    tuple_details: dict[str, dict] = {}
    lexical: dict[str, list] = {key: [] for key in ("domain_length", "digit_ratio", "entropy")}
    windows: dict[tuple[str, datetime], dict] = {}
    first = last = None
    lines = rejected = null_queries = missing_queries = empty_queries = nxdomain = 0
    examples = []
    with path.open(encoding="utf-8") as stream:
        for lines, line in enumerate(stream, 1):
            try:
                raw = json.loads(line)
                if isinstance(raw, dict):
                    for key in REQUIRED:
                        if raw.get(key) is None:
                            missing[key] += 1
                    for key in ("answers", "TTLs", "query"):
                        structures[key]["absent" if key not in raw else type(raw[key]).__name__] += 1
                event = parse_dns_line(line)
            except (ValueError, TypeError, OverflowError) as exc:
                rejected += 1
                errors[str(exc)] += 1
                if len(examples) < 10:
                    examples.append({"line": lines, "error": str(exc)})
                continue
            first = min(first, event.event_timestamp) if first else event.event_timestamp
            last = max(last, event.event_timestamp) if last else event.event_timestamp
            sources[event.source_ip] += 1
            destinations[event.destination_ip] += 1
            qtypes[str(event.query_type)] += 1
            rcodes[str(event.response_code)] += 1
            endpoint = f"{event.source_ip} -> {event.destination_ip}:{event.destination_port}/{event.transport_protocol}"
            tuples[endpoint] += 1
            is_nx = event.response_code == 3
            detail = tuple_details.setdefault(endpoint, {"uids": set(), "names": Counter(), "response_codes": Counter(),
                                                        "query_types": Counter(), "nxdomain_count": 0})
            detail["uids"].add(event.zeek_uid)
            detail["response_codes"][str(event.response_code)] += 1
            detail["query_types"][str(event.query_type)] += 1
            detail["nxdomain_count"] += is_nx
            nxdomain += is_nx
            minute = event.event_timestamp.replace(second=0, microsecond=0)
            window = windows.setdefault((event.source_ip, minute), {"query_count": 0, "nxdomain_count": 0, "names": set(), "lexical": [], "dns_tuples": Counter()})
            window["dns_tuples"][endpoint] += 1
            window["query_count"] += 1
            window["nxdomain_count"] += is_nx
            if event.query is None:
                null_queries += 1
                missing_queries += "query" not in raw
                continue
            normalized = normalize_query(event.query)
            names[normalized] += 1
            detail["names"][normalized] += 1
            empty_queries += normalized == ""
            window["names"].add(normalized)
            feature = calculate_features(event.query)
            window["lexical"].append(feature)
            for key in lexical:
                lexical[key].append(getattr(feature, key))
    window_rows = []
    for (source, minute), data in sorted(windows.items()):
        features = data["lexical"]
        window_rows.append({"source_ip": source, "window_start": minute.isoformat(),
            "dns_tuples": dict(data["dns_tuples"]),
            "query_count": data["query_count"], "unique_domain_count": len(data["names"]),
            "nxdomain_count": data["nxdomain_count"], "nxdomain_ratio": data["nxdomain_count"] / data["query_count"],
            **{output: fsum(getattr(feature, key) for feature in features) / len(features) if features else None
               for output, key in (("avg_domain_length", "domain_length"), ("avg_digit_ratio", "digit_ratio"), ("avg_entropy", "entropy"))},
            "max_entropy": max((feature.entropy for feature in features), default=None)})
    valid = lines - rejected
    return {"source_file": str(path), "source_sha256": sha256(path), "records_read": lines,
        "compatible_records": valid, "incompatible_records": rejected,
        "missing_required_fields": dict(missing), "validation_errors": dict(errors), "error_examples": examples,
        "field_structures": dict(structures), "source_ips": dict(sources), "destination_ips": dict(destinations),
        "dns_tuples": dict(tuples),
        "tuple_details": {key: {"events": tuples[key], "distinct_zeek_uids": len(detail["uids"]),
            "distinct_normalized_queries": len(detail["names"]), "top_queries": detail["names"].most_common(10),
            "nxdomain_count": detail["nxdomain_count"], "nxdomain_ratio": detail["nxdomain_count"] / tuples[key],
            "response_codes": dict(detail["response_codes"]), "query_types": dict(detail["query_types"])}
            for key, detail in tuple_details.items()},
        "query_types": dict(qtypes), "response_codes": dict(rcodes),
        "nxdomain_count": nxdomain, "nxdomain_ratio": nxdomain / valid if valid else 0.0,
        "null_or_missing_queries": null_queries, "missing_query_keys": missing_queries,
        "empty_normalized_queries": empty_queries, "distinct_normalized_queries": len(names),
        "top_queries": names.most_common(20), "query_occurrence_distribution": dict(Counter(names.values())),
        "lexical": {key: distribution(values) for key, values in lexical.items()},
        "first_dns_timestamp_utc": first.isoformat() if first else None,
        "last_dns_timestamp_utc": last.isoformat() if last else None,
        "dns_duration_seconds": (last - first).total_seconds() if first else None,
        "window_count": len(window_rows), "windows_by_source": dict(Counter(row["source_ip"] for row in window_rows)),
        "window_metrics": {key: distribution([row[key] for row in window_rows if row[key] is not None]) for key in WINDOW_METRICS},
        "windows": window_rows, "percentile_method": "linear interpolation at (n-1)*p; non-null samples; equal weight"}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    fetch = commands.add_parser("download", help="download only the two selected PCAPs and their documentation")
    fetch.add_argument("--root", type=Path, default=Path("data/raw/pcap/public"))
    fetch.add_argument("--manifest", type=Path, required=True)
    inspect = commands.add_parser("inspect", help="inspect existing Zeek JSON; never connect to PostgreSQL")
    inspect.add_argument("dns_log", type=Path)
    inspect.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == "download":
            download(args.root, args.manifest)
        else:
            report = inspect_log(args.dns_log)
            write_json(args.output, report)
            print(json.dumps({key: report[key] for key in ("records_read", "compatible_records", "incompatible_records", "window_count", "nxdomain_ratio")}, indent=2))
    except subprocess.CalledProcessError as exc:
        parser.exit(1, f"Download failed: {exc.stderr.strip()}\n")
    except (OSError, ValueError) as exc:
        parser.exit(1, f"Exploration failed: {exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
