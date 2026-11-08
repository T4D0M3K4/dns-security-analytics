"""Offline exploration tests; no network, PCAP decoder, or database writes."""

import json
from pathlib import Path
import subprocess

import pytest

from dns_security_analytics.analysis.public_datasets import download, distribution, inspect_log
from dns_security_analytics.features.lexical import calculate_features


def record(ts: float, **extra: object) -> dict:
    return {"ts": ts, "uid": "unit-test", "id.orig_h": "192.0.2.1", "id.orig_p": 12345,
            "id.resp_h": "192.0.2.53", "id.resp_p": 53, "proto": "udp",
            "query": "ChatGPT.COM.", "qtype": 1, "rcode": 0, **extra}


def test_inspection_minute_boundaries_normalization_and_optional_fields(tmp_path: Path) -> None:
    source = tmp_path / "dns.log"
    rows = [record(59.999), record(59.5, query="chatgpt.com", rcode=3),
            record(60, query=None), record(60, **{"id.orig_h": "192.0.2.2", "query": "x12.test"})]
    source.write_text("\n".join(json.dumps(row) for row in rows) + "\n")
    result = inspect_log(source)
    assert result["compatible_records"] == 4
    assert result["window_count"] == 3
    assert result["nxdomain_ratio"] == .25
    assert result["distinct_normalized_queries"] == 2
    assert result["null_or_missing_queries"] == 1
    windows = result["windows"]
    assert windows[0]["window_start"] == "1970-01-01T00:00:00+00:00"
    assert windows[0]["query_count"] == 2 and windows[0]["unique_domain_count"] == 1
    assert windows[0]["nxdomain_ratio"] == .5
    assert windows[0]["avg_entropy"] == calculate_features("chatgpt.com").entropy
    assert windows[1]["window_start"] == "1970-01-01T00:01:00+00:00"
    assert windows[1]["avg_entropy"] is None


def test_incompatible_rows_are_reported_and_do_not_stop_inspection(tmp_path: Path) -> None:
    path = tmp_path / "dns.log"
    path.write_text('invalid\n[]\n{"ts":0}\n' + json.dumps(record(0)) + "\n")
    result = inspect_log(path)
    assert result["records_read"] == 4
    assert result["incompatible_records"] == 3
    assert result["compatible_records"] == 1
    assert result["missing_required_fields"]["uid"] == 1
    assert [item["line"] for item in result["error_examples"]] == [1, 2, 3]


def test_percentiles_and_empty_input() -> None:
    result = distribution([0, 10, 20, 30])
    assert (result["p25"], result["p50"], result["p95"], result["mean"]) == pytest.approx((7.5, 15, 28.5, 15))
    assert distribution([])["mean"] is None
    assert distribution([4])["p95"] == 4


def test_download_allowlist_retries_hash_replay_and_immutability(tmp_path: Path, monkeypatch) -> None:
    calls = []

    def fake_curl(command: list, **kwargs) -> subprocess.CompletedProcess:
        calls.append(command)
        filename = command[-1].rsplit("/", 1)[-1]
        payload = b"\xd4\xc3\xb2\xa1test" if filename.endswith(".pcap") else b"publisher documentation"
        Path(command[command.index("--output") + 1]).write_bytes(payload)
        return subprocess.CompletedProcess(command, 0, stdout=command[-1])

    monkeypatch.setattr(subprocess, "run", fake_curl)
    root, manifest = tmp_path / "raw", tmp_path / "provenance.json"
    first = download(root, manifest)
    assert len(calls) == len(first["files"]) == 6
    assert all(call[-1].startswith("https://mcfp.felk.cvut.cz/publicDatasets/") for call in calls)
    assert all(call[-1].endswith((".pcap", "/README.md", ".capinfos")) for call in calls)
    assert all("--retry" in call and "--max-time" in call and "--proto-redir" in call for call in calls)
    assert download(root, manifest) == first and len(calls) == 6
    pcap = next(root.rglob("*.pcap"))
    pcap.write_bytes(b"changed")
    with pytest.raises(ValueError, match="refusing overwrite"):
        download(root, manifest)
    assert pcap.read_bytes() == b"changed"


def test_failed_download_does_not_publish_partial_file(tmp_path: Path, monkeypatch) -> None:
    def fail(command: list, **kwargs) -> None:
        Path(command[command.index("--output") + 1]).write_bytes(b"partial")
        raise subprocess.CalledProcessError(22, command, stderr="HTTP error")

    monkeypatch.setattr(subprocess, "run", fail)
    with pytest.raises(subprocess.CalledProcessError):
        download(tmp_path / "raw", tmp_path / "manifest.json")
    assert not list(tmp_path.rglob("*.pcap"))
    assert not (tmp_path / "manifest.json").exists()
