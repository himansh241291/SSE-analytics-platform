from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .models import ParsedRecord, S3Object

SOURCE_PREFIXES = {
    "audit": "auditlogs/",
    "dlp": "dlplogs/",
    "dns": "dnslogs/",
    "firewall": "firewalllogs/",
    "proxy": "proxylogs/",
    "rc_event": "rceventlogs/",
    "ztna": "ztnaflowlogs/",
}


def detect_source(key: str) -> str:
    for source, prefix in SOURCE_PREFIXES.items():
        if prefix in key:
            return source
    raise ValueError(f"Unable to identify SSE source from S3 key: {key}")


def _first(row: dict[str, Any], *names: str) -> Any:
    lowered = {str(k).strip().lower(): v for k, v in row.items()}
    for name in names:
        value = lowered.get(name.lower())
        if value not in (None, ""):
            return value
    return None


def _int(value: Any) -> int | None:
    if value in (None, ""):
        return None
    try:
        return int(float(str(value)))
    except (TypeError, ValueError):
        return None


def normalize(row: dict[str, Any], source_object: S3Object, row_number: int) -> dict[str, Any]:
    """Normalize only high-confidence cross-source fields; retain the entire row."""
    source = detect_source(source_object.key)
    event_time_raw = _first(row, "timestamp", "event_time", "eventtime", "time", "date")
    event_time = event_time_raw
    if not event_time:
        event_time = datetime.now(timezone.utc).isoformat()

    return {
        "event_id": f"{source_object.identity}:{row_number}",
        "event_time": event_time,
        "ingested_at": datetime.now(timezone.utc).isoformat(),
        "source_log_type": source,
        "event_type": _first(row, "event_type", "event type", "type") or source,
        "action": _first(row, "action", "disposition", "status"),
        "severity": _first(row, "severity", "risk", "priority"),
        "user_email": _first(row, "user_email", "email", "user", "username", "identity"),
        "source_ip": _first(row, "source_ip", "src_ip", "source ip", "client_ip", "internal_ip"),
        "destination_ip": _first(row, "destination_ip", "dst_ip", "destination ip", "remote_ip"),
        "destination_domain": _first(row, "destination_domain", "domain", "fqdn", "hostname"),
        "url": _first(row, "url", "request_url", "uri"),
        "source_port": _int(_first(row, "source_port", "src_port")),
        "destination_port": _int(_first(row, "destination_port", "dst_port", "port")),
        "protocol": _first(row, "protocol"),
        "application": _first(row, "application", "application_id", "app"),
        "private_resource_id": _first(row, "private_resource_id", "private app id"),
        "connector_id": _first(row, "connector_id", "app connector", "connector"),
        "policy_id": _first(row, "policy_id", "policy"),
        "ruleset_id": _first(row, "ruleset_id", "ruleset"),
        "rule_id": _first(row, "rule_id", "rule"),
        "bytes_sent": _int(_first(row, "bytes_sent", "tx_bytes", "tx bytes", "bytes out")),
        "bytes_received": _int(_first(row, "bytes_received", "rx_bytes", "rx bytes", "bytes in")),
        "packets_sent": _int(_first(row, "packets_sent", "tx_packets", "packets out")),
        "packets_received": _int(_first(row, "packets_received", "rx_packets", "packets in")),
        "category": _first(row, "category", "content_category", "content categories"),
        "threat": _first(row, "threat", "threat name", "threat_type"),
        "malware_name": _first(row, "malware_name", "amp malware name", "malware"),
        "av_disposition": _first(row, "av_disposition", "amp disposition", "av disposition"),
        "dlp_status": _first(row, "dlp_status", "dlp status"),
        "dlp_rule": _first(row, "dlp_rule", "dlp rule"),
        "file_name": _first(row, "file_name", "file name"),
        "file_sha256": _first(row, "file_sha256", "sha256", "file hash"),
        "event_correlation_id": _first(row, "event_correlation_id", "event correlation id", "correlation_id", "transaction id"),
        "raw_event": row,
    }
