from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import boto3

from .models import S3Object


class S3Source:
    """Thin S3 adapter. Listing is isolated so restricted buckets can use another discovery source."""

    def __init__(self, bucket: str, region: str) -> None:
        self.bucket = bucket
        self.client = boto3.client("s3", region_name=region)

    def list_objects(self, prefix: str) -> Iterator[S3Object]:
        paginator = self.client.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=self.bucket, Prefix=prefix):
            for item in page.get("Contents", []):
                yield S3Object(
                    bucket=self.bucket,
                    key=item["Key"],
                    etag=str(item.get("ETag", "")).strip('"') or None,
                    size=item.get("Size"),
                    last_modified=item.get("LastModified"),
                )

    def download(self, obj: S3Object, destination: str) -> None:
        self.client.download_file(obj.bucket, obj.key, destination)
