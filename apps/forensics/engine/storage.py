"""Evidence storage: originals are written once, made read-only, and never modified.

Layout under ``root`` (kept OUTSIDE any web-served directory):
    incoming/   temporary upload target
    originals/  ab/<32-hex-name>   random server-generated names, mode 0440
    working/    short-lived working copies used for analysis, deleted afterwards
"""
from __future__ import annotations

import os
import re
import shutil
import stat
import tempfile
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator

from .hashing import CHUNK, Hasher, hash_path

NAME_RE = re.compile(r"^[0-9a-f]{32}$")


class StorageError(Exception):
    pass


class TooLarge(StorageError):
    pass


class EmptyFile(StorageError):
    pass


class UnsafeStorage(StorageError):
    pass


class IntegrityError(StorageError):
    pass


@dataclass(frozen=True)
class StoredFile:
    name: str
    size: int
    sha256: str
    md5: str


@dataclass(frozen=True)
class VerifyResult:
    status: str  # "verified" | "failed" | "missing"
    actual_sha256: str = ""
    actual_md5: str = ""


class EvidenceStore:
    def __init__(self, root, forbidden_roots: Iterable = ()):
        self.root = Path(root).resolve()
        for bad in forbidden_roots:
            bad = Path(bad).resolve()
            if self.root == bad or bad in self.root.parents:
                raise UnsafeStorage(f"Evidence root {self.root} must not be inside {bad} (it could be web-served).")
        for sub in ("incoming", "originals", "working"):
            (self.root / sub).mkdir(parents=True, exist_ok=True)
        os.chmod(self.root, 0o700)

    # -- paths -------------------------------------------------------------
    def path(self, name: str) -> Path:
        if not NAME_RE.fullmatch(name or ""):
            raise UnsafeStorage("Invalid stored file name.")
        return self.root / "originals" / name[:2] / name

    def exists(self, name: str) -> bool:
        p = self.path(name)
        return p.is_file() and not p.is_symlink()

    # -- ingest ------------------------------------------------------------
    def ingest(self, chunks: Iterable[bytes], max_bytes: int) -> StoredFile:
        """Stream ``chunks`` to disk while hashing and enforcing the size limit."""
        fd, tmp = tempfile.mkstemp(dir=self.root / "incoming", prefix="up-")
        hasher = Hasher()
        try:
            with os.fdopen(fd, "wb") as out:
                for chunk in chunks:
                    hasher.update(chunk)
                    if hasher.size > max_bytes:
                        raise TooLarge(f"File exceeds the {max_bytes} byte limit.")
                    out.write(chunk)
                out.flush()
                os.fsync(out.fileno())
            if hasher.size == 0:
                raise EmptyFile("The file is empty.")
            name = uuid.uuid4().hex
            dest = self.path(name)
            dest.parent.mkdir(parents=True, exist_ok=True)
            os.chmod(dest.parent, 0o700)
            os.replace(tmp, dest)  # atomic on the same filesystem
            os.chmod(dest, 0o440)  # read-only: the original is never modified
            h = hasher.result()
            return StoredFile(name, h.size, h.sha256, h.md5)
        except BaseException:
            try:
                os.unlink(tmp)
            except FileNotFoundError:
                pass
            raise

    # -- verification ------------------------------------------------------
    def verify(self, name: str, expected_sha256: str) -> VerifyResult:
        p = self.path(name)
        if not p.is_file() or p.is_symlink():
            return VerifyResult("missing")
        h = hash_path(p)
        ok = h.sha256 == expected_sha256.lower()
        return VerifyResult("verified" if ok else "failed", h.sha256, h.md5)

    # -- working copies ----------------------------------------------------
    @contextmanager
    def working_copy(self, name: str, expected_sha256: str) -> Iterator[Path]:
        """Copy the original to a private temp dir, prove the copy is identical, yield it, then delete it."""
        src = self.path(name)
        if not src.is_file() or src.is_symlink():
            raise IntegrityError("Original file is missing.")
        workdir = Path(tempfile.mkdtemp(dir=self.root / "working", prefix="wc-"))
        os.chmod(workdir, 0o700)
        dest = workdir / "copy.bin"
        try:
            h = Hasher()
            with open(src, "rb") as fin, open(dest, "wb") as fout:
                while chunk := fin.read(CHUNK):
                    h.update(chunk)
                    fout.write(chunk)
            if h.result().sha256 != expected_sha256.lower():
                raise IntegrityError("Original no longer matches its recorded SHA-256; analysis refused.")
            os.chmod(dest, stat.S_IRUSR)
            yield dest
        finally:
            shutil.rmtree(workdir, ignore_errors=True)

    def stat_times(self, name: str) -> dict:
        from datetime import datetime, timezone
        st = self.path(name).stat()
        iso = lambda t: datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        return {"stored_modified": iso(st.st_mtime), "stored_changed": iso(st.st_ctime)}
