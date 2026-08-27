from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class CheckpointStore:
    """Small local checkpoint store for the first collector iteration."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def _load(self) -> dict[str, Any]:
        if not self.path.exists():
            return {}
        return json.loads(self.path.read_text(encoding="utf-8"))

    def contains(self, object_identity: str) -> bool:
        return object_identity in self._load()

    def mark_processed(self, object_identity: str, record_count: int) -> None:
        state = self._load()
        state[object_identity] = {
            "processed_at": datetime.now(timezone.utc).isoformat(),
            "record_count": record_count,
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(json.dumps(state, indent=2, sort_keys=True), encoding="utf-8")
        tmp.replace(self.path)
