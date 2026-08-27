from __future__ import annotations

import argparse
import json
from pathlib import Path

from .checkpoint import CheckpointStore
from .csv_gzip import iter_csv_gzip_file
from .normalize import normalize


def ingest_local_file(source: str, path: str, checkpoint_path: str, output: str) -> int:
    """Local development path: parse a downloaded SSE CSV.GZ into JSONL."""
    checkpoint = CheckpointStore(checkpoint_path)
    object_identity = f"local:{source}:{Path(path).resolve()}"
    if checkpoint.contains(object_identity):
        return 0

    # Local files don't have an S3 object identity, so use a minimal adapter.
    from .models import S3Object

    obj = S3Object(bucket="local", key=f"{source}/{Path(path).name}")
    count = 0
    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("a", encoding="utf-8") as handle:
        for count, row in enumerate(iter_csv_gzip_file(path), start=1):
            handle.write(json.dumps(normalize(row, obj, count), ensure_ascii=False) + "\n")

    checkpoint.mark_processed(object_identity, count)
    return count


def main() -> None:
    parser = argparse.ArgumentParser(description="SSE Analytics local ingestion utility")
    parser.add_argument("--source", required=True, choices=["audit", "dlp", "dns", "firewall", "proxy", "rc_event", "ztna"])
    parser.add_argument("--file", required=True, help="Path to a .csv.gz sample")
    parser.add_argument("--checkpoint", default="./data/checkpoints.json")
    parser.add_argument("--output", default="./data/events.jsonl")
    args = parser.parse_args()
    count = ingest_local_file(args.source, args.file, args.checkpoint, args.output)
    print(f"processed_records={count}")


if __name__ == "__main__":
    main()
