"""Validate and map Zeek JSON records to the existing DNS event schema."""

from dataclasses import dataclass, astuple
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from ipaddress import ip_address
import json
import math
from typing import Any


@dataclass(frozen=True)
class DNSEvent:
    event_timestamp: datetime
    zeek_uid: str
    source_ip: str
    source_port: int
    destination_ip: str
    destination_port: int
    transport_protocol: str
    query: str | None
    query_class: int | None
    query_type: int | None
    response_code: int | None
    rejected: bool | None
    answers: list[str] | None
    ttls: list[float] | None

    def values(self) -> tuple[Any, ...]:
        """Return values in the explicit INSERT column order."""
        return astuple(self)


def text(value: Any, field: str) -> str:
    if not isinstance(value, str) or "\x00" in value:
        raise ValueError(f"{field} must be text without NUL characters")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError(f"{field} must contain valid Unicode") from exc
    return value


def code(value: Any, field: str) -> int:
    if type(value) is not int or not 0 <= value <= 65535:
        raise ValueError(f"{field} must be an integer between 0 and 65535")
    return value


def number(value: Any, field: str) -> Decimal:
    if isinstance(value, bool) or not isinstance(value, (int, Decimal)):
        raise ValueError(f"{field} must be a finite number")
    result = Decimal(value)
    if not result.is_finite():
        raise ValueError(f"{field} must be a finite number")
    return result


def parse_dns_line(line: str) -> DNSEvent:
    """Parse one object, rejecting invalid fields before database insertion."""
    record = json.loads(line, parse_float=Decimal)
    if not isinstance(record, dict):
        raise ValueError("expected a JSON object")
    required = ("ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto")
    for key in required:
        if key not in record or record[key] is None:
            raise ValueError(f"missing required field: {key}")
    try:
        micros = int((number(record["ts"], "ts") * 1_000_000).to_integral_value())
        timestamp = datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=micros)
    except (OverflowError, ArithmeticError) as exc:
        raise ValueError("ts is outside the supported datetime range") from exc
    uid = text(record["uid"], "uid")
    proto = text(record["proto"], "proto")
    if not uid or not proto:
        raise ValueError("uid and proto must not be empty")
    addresses = []
    for key in ("id.orig_h", "id.resp_h"):
        value = text(record[key], key)
        if "%" in value:
            raise ValueError(f"{key} must not contain an IPv6 scope ID")
        try:
            addresses.append(str(ip_address(value)))
        except ValueError as exc:
            raise ValueError(f"{key} must be an IPv4 or IPv6 host address") from exc
    rejected = record.get("rejected")
    if rejected is not None and type(rejected) is not bool:
        raise ValueError("rejected must be boolean or null")
    answers = record.get("answers")
    if answers is not None:
        if not isinstance(answers, list):
            raise ValueError("answers must be an array or null")
        answers = [text(value, "answers element") for value in answers]
    ttls = record.get("TTLs")
    if ttls is not None:
        if not isinstance(ttls, list):
            raise ValueError("TTLs must be an array or null")
        normalized = []
        for value in ttls:
            ttl = number(value, "TTLs element")
            if ttl < 0 or not math.isfinite(float(ttl)):
                raise ValueError("TTLs elements must be finite non-negative seconds")
            normalized.append(float(ttl))
        ttls = normalized
    return DNSEvent(
        timestamp, uid, addresses[0], code(record["id.orig_p"], "id.orig_p"),
        addresses[1], code(record["id.resp_p"], "id.resp_p"), proto,
        text(record["query"], "query") if record.get("query") is not None else None,
        *(code(record[key], key) if record.get(key) is not None else None
          for key in ("qclass", "qtype", "rcode")),
        rejected, answers, ttls,
    )
