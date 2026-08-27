CREATE DATABASE IF NOT EXISTS sse;

CREATE TABLE IF NOT EXISTS sse.events
(
    event_time DateTime,
    source_type LowCardinality(String),
    organization_id String DEFAULT '',
    event_id String DEFAULT '',
    event_correlation_id String DEFAULT '',
    user_identity String DEFAULT '',
    identity_type String DEFAULT '',
    hostname String DEFAULT '',
    source_ip String DEFAULT '',
    destination_ip String DEFAULT '',
    destination String DEFAULT '',
    destination_port UInt16 DEFAULT 0,
    protocol String DEFAULT '',
    action LowCardinality(String) DEFAULT '',
    severity LowCardinality(String) DEFAULT '',
    policy_id String DEFAULT '',
    rule_id String DEFAULT '',
    ruleset_id String DEFAULT '',
    application String DEFAULT '',
    category String DEFAULT '',
    country String DEFAULT '',
    bytes_sent UInt64 DEFAULT 0,
    bytes_received UInt64 DEFAULT 0,
    packets_sent UInt64 DEFAULT 0,
    packets_received UInt64 DEFAULT 0,
    threat_name String DEFAULT '',
    threat_score Float32 DEFAULT 0,
    raw_event String DEFAULT ''
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(event_time)
ORDER BY (event_time, source_type, organization_id, user_identity)
TTL event_time + INTERVAL 365 DAY;
