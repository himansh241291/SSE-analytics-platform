# SSE Analytics Platform

A security analytics and investigation platform for Cisco SSE exported telemetry.

## Telemetry sources

- `auditlogs`
- `dlplogs`
- `dnslogs`
- `firewalllogs`
- `proxylogs`
- `rceventlogs`
- `ztnaflowlogs`

## Goals

1. Discover and ingest SSE log objects from AWS S3.
2. Preserve raw events while normalizing them into a canonical security-event model.
3. Correlate identity, device, IP, domain, URL, policy, rule, application, and threat activity.
4. Produce detections, risk scores, anomalies, and investigations.
5. Provide views for Threat/IPS, DNS, Web/Proxy, Firewall/Traffic, DLP, ZTNA, Audit, Users, Devices, Policies, and SSE Health.
6. Scale from local development to high-volume production telemetry.

## Repository layout

```text
backend/        API and analytics services
collector/      S3 discovery and ingestion
schemas/        Canonical event schemas and source mappings
docs/           Architecture and design documentation
docker/         Local infrastructure configuration
frontend/       Web console (planned)
tests/          Automated tests
```

## Security

Never commit AWS credentials, API keys, tokens, cookies, customer log exports, or raw production telemetry. Use environment variables or a secret manager for credentials.

## Status

Phase 1: repository and architecture foundation.
