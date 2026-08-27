from __future__ import annotations

import csv
import gzip
import hashlib
import json
import sys
from datetime import datetime
from pathlib import Path

import clickhouse_connect

SOURCE_FILES = {
    "audit": "auditlogs.csv.gz",
    "dlp": "dlplogs.csv.gz",
    "dns": "dnslogs.csv.gz",
    "firewall": "firewalllogs.csv.gz",
    "proxy": "proxylogs.csv.gz",
    "rc_event": "rceventlogs.csv.gz",
    "ztna": "ztnaflowlogs.csv.gz",
}


def s(value: object) -> str:
    return "" if value is None else str(value)


def int_or_zero(value: object) -> int:
    try:
        return int(float(s(value).strip()))
    except (TypeError, ValueError):
        return 0


def parse_time(value: str) -> datetime:
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%SZ"):
        try:
            return datetime.strptime(value.strip(), fmt)
        except ValueError:
            pass
    raise ValueError(f"Unsupported timestamp: {value!r}")


def identity(row: dict[str, str], source: str, line: int) -> str:
    seed = json.dumps([source, line, sorted(row.items())], separators=(",", ":"))
    return hashlib.sha256(seed.encode()).hexdigest()


def normalize(source: str, row: dict[str, str], line: int) -> dict:
    def first(*names: str) -> str:
        lower = {k.strip().lower(): v for k, v in row.items()}
        for name in names:
            value = lower.get(name.lower())
            if value not in (None, ""):
                return s(value)
        return ""

    event = {
        "event_time": parse_time(first("Timestamp", "Time")),
        "source_type": source,
        "organization_id": first("Organization ID", "MSP Organization ID"),
        "event_id": first("Unique Event ID", "Event ID", "FW Event ID", "Transaction ID", "ID") or identity(row, source, line),
        "event_correlation_id": first("Event Correlation ID"),
        "user_identity": first("Identities", "Most Granular Identity", "Identity Email", "Email", "User", "Event User ID"),
        "identity_type": first("Identity Types", "Most Granular Identity Type", "Identity Type Labels", "Policy Identity Type", "Origin Type"),
        "hostname": first("Host Name", "Hostname"),
        "source_ip": first("Internal IP", "Internal Client IP", "Source IP", "External IP", "External Client IP"),
        "destination_ip": first("Destination IP"),
        "destination": first("URL", "Domain", "FQDNS", "Server Name", "Destination", "Destination IP"),
        "destination_port": int_or_zero(first("Destination Port", "Egress Port")),
        "protocol": first("Protocol", "Destination Protocol"),
        "action": first("Action", "Connection Status", "Agent Tunnel Status"),
        "severity": first("Severity", "Event Level"),
        "policy_id": first("Policy ID", "Policy Identity Label"),
        "rule_id": first("Rule ID"),
        "ruleset_id": first("Ruleset ID"),
        "application": first("Application", "Application Entity Name", "App ID", "Application IDs"),
        "category": first("Categories", "Content Categories", "Content Category IDs", "Application Entity Category"),
        "country": first("Destination Country", "Destination Countries", "Geo Location Of Blocked Destination Countries"),
        "bytes_sent": int_or_zero(first("Bytes Sent", "Tx Bytes")),
        "bytes_received": int_or_zero(first("Bytes Received", "Rx Bytes")),
        "packets_sent": int_or_zero(first("Packets Sent")),
        "packets_received": int_or_zero(first("Packets Received")),
        "threat_name": first("AMP Malware Name", "AV Detections", "Threat"),
        "threat_score": float(first("AMP Score") or 0),
        "raw_event": json.dumps(row, ensure_ascii=False),
    }
    return event


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: python sample_import.py /path/to/sse-samples")

    sample_dir = Path(sys.argv[1]).expanduser().resolve()
    client = clickhouse_connect.get_client(
        host="localhost", port=8123, database="sse"
    )

    rows = []
    for source, filename in SOURCE_FILES.items():
        path = sample_dir / filename
        if not path.exists():
            # The first sample collection sometimes leaves an older dns.csv.gz name.
            if source == "dns" and (sample_dir / "dns.csv.gz").exists():
                path = sample_dir / "dns.csv.gz"
            else:
                print(f"SKIP {source}: {path} not found")
                continue

        with gzip.open(path, "rt", encoding="utf-8-sig", newline="") as fh:
            reader = csv.DictReader(fh)
            source_count = 0
            for line, row in enumerate(reader, start=2):
                rows.append(normalize(source, row, line))
                source_count += 1
        print(f"READ {source}: {source_count} records")

    if not rows:
        raise SystemExit("No sample records found")

    columns = [
        "event_time", "source_type", "organization_id", "event_id",
        "event_correlation_id", "user_identity", "identity_type", "hostname",
        "source_ip", "destination_ip", "destination", "destination_port",
        "protocol", "action", "severity", "policy_id", "rule_id", "ruleset_id",
        "application", "category", "country", "bytes_sent", "bytes_received",
        "packets_sent", "packets_received", "threat_name", "threat_score", "raw_event",
    ]
    data = [[row[column] for column in columns] for row in rows]
    client.insert("events", data, column_names=columns)
    print(f"INSERTED {len(data)} records into sse.events")


if __name__ == "__main__":
    main()
