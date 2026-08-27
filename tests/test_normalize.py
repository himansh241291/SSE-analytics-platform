from collector.models import S3Object
from collector.normalize import detect_source, normalize


def test_detect_source():
    assert detect_source("tenant/dnslogs/2026-08-27/sample.csv.gz") == "dns"
    assert detect_source("tenant/ztnaflowlogs/2026-08-27/sample.csv.gz") == "ztna"


def test_normalize_preserves_raw_event():
    obj = S3Object(bucket="bucket", key="tenant/firewalllogs/2026-08-27/sample.csv.gz")
    row = {
        "Timestamp": "2026-08-27T04:30:00Z",
        "Source IP": "10.0.0.1",
        "Destination IP": "203.0.113.10",
        "Destination Port": "443",
        "Bytes": "1024",
        "Custom Cisco Field": "keep-me",
    }
    event = normalize(row, obj, 1)
    assert event["source_log_type"] == "firewall"
    assert event["source_ip"] == "10.0.0.1"
    assert event["destination_ip"] == "203.0.113.10"
    assert event["destination_port"] == 443
    assert event["raw_event"]["Custom Cisco Field"] == "keep-me"
