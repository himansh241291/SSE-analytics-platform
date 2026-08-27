from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any


@dataclass(frozen=True)
class S3Object:
    bucket: str
    key: str
    etag: str | None = None
    version_id: str | None = None
    size: int | None = None
    last_modified: datetime | None = None

    @property
    def identity(self) -> str:
        """Stable processing identity for idempotent ingestion."""
        return ":".join(
            [
                self.bucket,
                self.key,
                self.version_id or "",
                self.etag or "",
            ]
        )


@dataclass
class ParsedRecord:
    source_log_type: str
    source_object: S3Object
    row_number: int
    raw_event: dict[str, Any]


@dataclass
class Checkpoint:
    processed_at: datetime
    record_count: int
