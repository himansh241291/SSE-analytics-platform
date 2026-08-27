CREATE DATABASE IF NOT EXISTS sse_analytics;

CREATE TABLE IF NOT EXISTS sse_analytics.events
(
    event_time DateTime64(3, 'UTC'),
    ingested_at DateTime64(3, 'UTC') DEFAULT now64(3),
    event_id String,
    source_log_type LowCardinality(String),
    event_type LowCardinality(String) DEFAULT '',
    action LowCardinality(String) DEFAULT '',
    severity LowCardinality(String) DEFAULT '',

    organization_id UInt64 DEFAULT 0,
    user_email String DEFAULT '',
    user_label String DEFAULT '',
    identity_types Array(String) DEFAULT [],
    source_ip IPv4 DEFAULT toIPv4('0.0.0.0'),
    destination_ip IPv4 DEFAULT toIPv4('0.0.0.0'),
    destination_domain String DEFAULT '',
    url String DEFAULT '',
    protocol LowCardinality(String) DEFAULT '',
    source_port UInt16 DEFAULT 0,
    destination_port UInt16 DEFAULT 0,

    application String DEFAULT '',
    application_id String DEFAULT '',
    private_resource_id String DEFAULT '',
    private_resource_group_id String DEFAULT '',
    connector_id String DEFAULT '',
    connector_group_id String DEFAULT '',
    policy_id String DEFAULT '',
    ruleset_id String DEFAULT '',
    rule_id String DEFAULT '',

    bytes_sent UInt64 DEFAULT 0,
    bytes_received UInt64 DEFAULT 0,
    packets_sent UInt64 DEFAULT 0,
    packets_received UInt64 DEFAULT 0,
    request_size UInt64 DEFAULT 0,
    response_size UInt64 DEFAULT 0,

    category String DEFAULT '',
    blocked_categories String DEFAULT '',
    threat String DEFAULT '',
    malware_name String DEFAULT '',
    av_disposition String DEFAULT '',
    amp_score Float32 DEFAULT 0,
    dlp_status LowCardinality(String) DEFAULT '',
    dlp_rule String DEFAULT '',
    data_classification String DEFAULT '',
    data_identifier String DEFAULT '',
    file_name String DEFAULT '',
    file_sha256 String DEFAULT '',

    connection_status LowCardinality(String) DEFAULT '',
    connection_failure_reason String DEFAULT '',
    event_correlation_id String DEFAULT '',
    transaction_id String DEFAULT '',
    user_agent String DEFAULT '',
    status_code UInt16 DEFAULT 0,
    certificate_errors String DEFAULT '',
    egress_ip IPv4 DEFAULT toIPv4('0.0.0.0'),
    destination_country LowCardinality(String) DEFAULT '',
    aws_region LowCardinality(String) DEFAULT '',

    raw_event String CODEC(ZSTD(3))
)
ENGINE = MergeTree
PARTITION BY toDate(event_time)
ORDER BY (source_log_type, event_time, organization_id, user_email, event_id)
TTL event_time + INTERVAL 30 DAY DELETE
SETTINGS index_granularity = 8192;

CREATE INDEX IF NOT EXISTS idx_domain ON sse_analytics.events (destination_domain) TYPE bloom_filter GRANULARITY 4;
CREATE INDEX IF NOT EXISTS idx_url ON sse_analytics.events (url) TYPE bloom_filter GRANULARITY 4;
CREATE INDEX IF NOT EXISTS idx_threat ON sse_analytics.events (threat, malware_name) TYPE bloom_filter GRANULARITY 4;
CREATE INDEX IF NOT EXISTS idx_correlation ON sse_analytics.events (event_correlation_id) TYPE bloom_filter GRANULARITY 4;
