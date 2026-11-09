"""Streaming hashes.  MD5 is computed only for legacy identification, never for integrity decisions."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass

CHUNK = 1024 * 1024


@dataclass(frozen=True)
class Hashes:
    sha256: str
    md5: str
    size: int


class Hasher:
    def __init__(self):
        self._sha = hashlib.sha256()
        self._md5 = hashlib.md5(usedforsecurity=False)
        self.size = 0

    def update(self, data: bytes) -> None:
        self._sha.update(data)
        self._md5.update(data)
        self.size += len(data)

    def result(self) -> Hashes:
        return Hashes(self._sha.hexdigest(), self._md5.hexdigest(), self.size)


def hash_path(path) -> Hashes:
    h = Hasher()
    with open(path, "rb") as fh:
        while chunk := fh.read(CHUNK):
            h.update(chunk)
    return h.result()
