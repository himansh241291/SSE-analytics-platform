# Architecture

## Phase 1

```text
Cisco SSE S3
    |
    v
S3 Collector -> Raw object metadata/checkpoints
    |
    v
Source Parser -> Canonical Event
    |
    +--> ClickHouse analytics store
    |
    +--> Detection engine
    |
    +--> Correlation/risk engine
    |
    v
FastAPI -> Web Console
```

## Design principles

- Preserve the original source event alongside normalized fields.
- Treat `source_log_type` as the authoritative source family.
- Use UTC timestamps internally; retain the original timestamp when useful for auditability.
- Do not require every source to populate every canonical field.
- Never store credentials or secrets in source code or Git.
- Ingestion must be idempotent: an S3 object should not produce duplicate canonical events when processed again.
- Store an ingestion checkpoint keyed by S3 bucket, object key, ETag/version where available.

## Source families

| Source | Primary purpose |
|---|---|
| auditlogs | Administrative/configuration activity |
| dlplogs | Data-loss-prevention activity |
| dnslogs | DNS requests and policy activity |
| firewalllogs | Network flows and enforcement |
| proxylogs | Web/proxy and content-security activity |
| rceventlogs | Connector/agent/control-plane health events |
| ztnaflowlogs | Private application / Zero Trust flows |

## Correlation strategy

The first correlation keys are timestamp, tenant/organization identifiers, identity, source/internal IP, destination IP/domain, rule/policy identifiers, application/resource identifiers, and event correlation IDs where present. Correlation must be time-window aware and should never assume that two events are related solely because they share an IP.

## Storage direction

ClickHouse is the initial analytics-store candidate because the workload is dominated by append-heavy event telemetry, time-range queries, aggregations, and investigation pivots. Raw objects remain in S3.
