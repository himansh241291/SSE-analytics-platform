# S3 Collector

Phase 2 collector foundation for Cisco SSE S3 exports.

## Goals

- Discover objects under configured SSE prefixes.
- Support environments where `ListBucket` is unavailable by allowing an explicit object manifest/prefix strategy.
- Track processed objects idempotently.
- Download and parse `.csv.gz` objects without storing production credentials in the repository.
- Preserve raw source fields for forward compatibility.

## Configuration

See `config.example.yaml` and environment variables documented there.

## Current implementation scope

This first version provides the configuration model, object identity/checkpoint model, CSV/GZIP parsing primitives, and a collector service boundary. AWS API integration is deliberately isolated so it can support both normal S3 listing and restricted Cisco-managed bucket access patterns.
