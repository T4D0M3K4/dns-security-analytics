from datetime import datetime, timezone
import json

import pytest

from dns_security_analytics.transformation.dns import parse_dns_line


@pytest.fixture
def record() -> dict:
    return {"ts": 1793526679.533648, "uid": "test-uid",
            "id.orig_h": "192.0.2.1", "id.orig_p": 65460,
            "id.resp_h": "192.0.2.53", "id.resp_p": 53, "proto": "udp",
            "query": "example.test", "qclass": 1, "qtype": 1, "rcode": 0,
            "rejected": False, "answers": ["192.0.2.2"], "TTLs": [166.5]}


def test_normal_a_response(record: dict) -> None:
    event = parse_dns_line(json.dumps(record))
    assert event.event_timestamp == datetime(2026, 11, 1, 9, 51, 19, 533648, tzinfo=timezone.utc)
    assert event.values()[1:] == ("test-uid", "192.0.2.1", 65460, "192.0.2.53", 53,
                                  "udp", "example.test", 1, 1, 0, False, ["192.0.2.2"], [166.5])


def test_aaaa_response(record: dict) -> None:
    record.update({"qtype": 28, "answers": ["2001:db8::2"], "id.orig_h": "2001:db8::1"})
    event = parse_dns_line(json.dumps(record))
    assert event.query_type == 28
    assert event.source_ip == "2001:db8::1"
    assert event.answers == ["2001:db8::2"]


def test_nxdomain(record: dict) -> None:
    record.update(rcode=3)
    del record["answers"], record["TTLs"]
    event = parse_dns_line(json.dumps(record))
    assert event.response_code == 3
    assert event.answers is None and event.ttls is None


def test_missing_optional_fields(record: dict) -> None:
    for key in ("query", "qclass", "qtype", "rcode", "rejected", "answers", "TTLs"):
        del record[key]
    assert parse_dns_line(json.dumps(record)).values()[7:] == (None,) * 7


@pytest.mark.parametrize("line", ['{"ts":', '[]', 'null', '', '{invalid}'])
def test_malformed_json_or_object(line: str) -> None:
    with pytest.raises(ValueError):
        parse_dns_line(line)


@pytest.mark.parametrize("key", ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto"])
def test_missing_required_field(record: dict, key: str) -> None:
    del record[key]
    with pytest.raises(ValueError, match="missing required field"):
        parse_dns_line(json.dumps(record))


@pytest.mark.parametrize("key,value", [
    ("ts", True), ("ts", "1793526679"), ("ts", float("nan")), ("ts", 1e100),
    ("id.orig_p", True), ("id.orig_p", 65536), ("id.resp_p", -1),
    ("id.orig_h", "bad-ip"), ("id.resp_h", "2001:db8::1%eth0"),
    ("uid", ""), ("proto", None), ("query", "bad\x00query"),
    ("qtype", 1.5), ("rcode", "0"), ("rejected", "false"),
    ("answers", "192.0.2.2"), ("answers", [None]), ("query", "\ud800"),
    ("TTLs", [-1]), ("TTLs", [float("inf")]), ("TTLs", ["60"]),
])
def test_invalid_fields(record: dict, key: str, value: object) -> None:
    record[key] = value
    with pytest.raises(ValueError):
        parse_dns_line(json.dumps(record))


def test_empty_arrays_and_extra_fields(record: dict) -> None:
    record.update(answers=[], TTLs=[], trans_id=123, opcode=0)
    event = parse_dns_line(json.dumps(record))
    assert event.answers == [] and event.ttls == []
    assert len(event.values()) == 14
