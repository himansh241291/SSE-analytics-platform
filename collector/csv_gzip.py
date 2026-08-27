from __future__ import annotations

import csv
import gzip
import io
from collections.abc import Iterator
from typing import TextIO


def iter_csv_gzip(stream: io.BufferedIOBase) -> Iterator[dict[str, str]]:
    """Yield CSV rows from a gzip-compressed binary stream."""
    with gzip.GzipFile(fileobj=stream, mode="rb") as gz:
        with io.TextIOWrapper(gz, encoding="utf-8-sig", newline="") as text:
            yield from csv.DictReader(text)


def iter_csv_gzip_file(path: str) -> Iterator[dict[str, str]]:
    with open(path, "rb") as stream:
        yield from iter_csv_gzip(stream)
