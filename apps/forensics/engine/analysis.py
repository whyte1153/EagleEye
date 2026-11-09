"""Static analysis of a (working copy of a) file: type, extension agreement, risk flags, metadata.

Everything here is READ-ONLY and STATIC.  Files are never opened by an
interpreter, never executed, and archives are never extracted.
"""
from __future__ import annotations

import collections
import math
import os
import re
import struct
import unicodedata
import zipfile
from dataclasses import dataclass, field

from . import filetype as ft

ENTROPY_SAMPLE = 1024 * 1024
# Thresholds are module constants so tests can lower them.
ZIP_MAX_ENTRIES = 10_000
ZIP_BOMB_TOTAL = 1024 ** 3
ZIP_BOMB_RATIO_MIN_TOTAL = 100 * 1024 ** 2
ZIP_BOMB_RATIO = 200

BIDI_CHARS = {chr(c) for c in (*range(0x202A, 0x202F), *range(0x2066, 0x206A), 0x200E, 0x200F, 0x061C)}
WINDOWS_RESERVED = {"con", "prn", "aux", "nul", *(f"com{i}" for i in range(1, 10)), *(f"lpt{i}" for i in range(1, 10))}
DOC_EXTS = frozenset({"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf", "csv", "jpg", "jpeg", "png", "gif", "zip", "mp3", "mp4", "odt"})
SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3}


@dataclass
class Flag:
    code: str
    severity: str
    title: str
    detail: str

    def as_dict(self) -> dict:
        return {"code": self.code, "severity": self.severity, "title": self.title, "detail": self.detail}


@dataclass
class AnalysisResult:
    kind: str
    label: str
    mime: str
    family: str
    extension: str
    extension_status: str  # ok | mismatch | unverified | no_extension
    flags: list = field(default_factory=list)
    metadata: dict = field(default_factory=dict)

    @property
    def highest_severity(self) -> str:
        return max((f.severity for f in self.flags), key=lambda s: SEVERITY_RANK[s], default="")


# ----------------------------------------------------------------- names
def sanitize_filename(name: str, max_len: int = 120) -> str:
    """A safe display / download name.  Never used for storage on disk."""
    name = (name or "").replace("\\", "/").split("/")[-1]
    name = unicodedata.normalize("NFC", name)
    name = "".join(ch for ch in name if ch not in BIDI_CHARS and ch.isprintable() and ch not in '<>:"|?*')
    name = name.strip(" .")
    if not name:
        return "unnamed"
    stem, dot, ext = name.rpartition(".")
    if not dot:
        stem, ext = name, ""
    if stem.lower() in WINDOWS_RESERVED:
        name = "_" + name
    if len(name) > max_len:
        ext_part = ("." + ext) if ext and len(ext) <= 16 else ""
        name = name[:max_len - len(ext_part)] + ext_part
    return name


def get_extension(name: str) -> str:
    base = sanitize_filename(name)
    return base.rsplit(".", 1)[1].lower() if "." in base else ""


def name_flags(raw_name: str) -> list[Flag]:
    flags = []
    if any(ch in BIDI_CHARS for ch in raw_name):
        flags.append(Flag("bidi_override", "high", "Name contains bidirectional control characters",
                          "Characters such as U+202E reverse how a name is displayed (e.g. 'photo‮gpj.exe' shows as 'photoexe.jpg'). Treat as deliberate disguise."))
    if any(not ch.isprintable() for ch in raw_name if ch not in BIDI_CHARS):
        flags.append(Flag("control_chars", "low", "Name contains control characters", "Unprintable characters were removed from the display name."))
    if ".." in raw_name or "/" in raw_name or "\\" in raw_name:
        flags.append(Flag("path_in_name", "low", "Name contains path separators", "Only the final path component is used for display; the server never uses it on disk."))
    if len(raw_name) > 200:
        flags.append(Flag("long_name", "info", "Very long file name", f"{len(raw_name)} characters."))
    parts = sanitize_filename(raw_name).lower().split(".")
    if len(parts) >= 3 and parts[-2] in DOC_EXTS:
        if parts[-1] in ft.EXEC_EXTS:
            flags.append(Flag("double_extension_executable", "high", "Executable disguised by a document-style double extension",
                              f"'.{parts[-2]}.{parts[-1]}' presents as a {parts[-2]} file but ends in an executable/script extension."))
        elif parts[-1] in ft.MAGIC_EXTS:
            flags.append(Flag("double_extension", "low", "Double file extension", f"'.{parts[-2]}.{parts[-1]}'"))
    return flags


# --------------------------------------------------------------- content
def shannon_entropy(path: str, limit: int = ENTROPY_SAMPLE) -> float:
    with open(path, "rb") as fh:
        data = fh.read(limit)
    if not data:
        return 0.0
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in collections.Counter(data).values())


def _image_dims(path: str, kind: str) -> dict:
    with open(path, "rb") as fh:
        head = fh.read(65536)
    if kind == "png" and len(head) >= 24:
        w, h = struct.unpack(">II", head[16:24])
        return {"width": w, "height": h}
    if kind == "gif" and len(head) >= 10:
        w, h = struct.unpack("<HH", head[6:10])
        return {"width": w, "height": h}
    if kind == "bmp" and len(head) >= 26:
        w, h = struct.unpack("<ii", head[18:26])
        return {"width": w, "height": abs(h)}
    if kind == "jpeg":
        i = 2
        while i + 9 < len(head):
            if head[i] != 0xFF:
                i += 1
                continue
            marker = head[i + 1]
            if marker in (0xD8, 0x01) or 0xD0 <= marker <= 0xD7:
                i += 2
                continue
            seg = struct.unpack(">H", head[i + 2:i + 4])[0]
            if 0xC0 <= marker <= 0xCF and marker not in (0xC4, 0xC8, 0xCC):
                h, w = struct.unpack(">HH", head[i + 5:i + 9])
                return {"width": w, "height": h}
            i += 2 + seg
    return {}


def _zip_info(path: str) -> tuple[dict, list[Flag]]:
    flags, meta = [], {}
    try:
        with zipfile.ZipFile(path) as zf:
            infos = zf.infolist()
    except (zipfile.BadZipFile, OSError, NotImplementedError, ValueError):
        return {}, [Flag("archive_corrupt", "low", "ZIP structure could not be read", "The file starts like a ZIP but its directory is damaged or non-standard.")]
    total = sum(i.file_size for i in infos[:ft.MAX_ZIP_NAMES])
    packed = sum(i.compress_size for i in infos[:ft.MAX_ZIP_NAMES])
    meta.update(entries=len(infos), uncompressed_bytes=total, compressed_bytes=packed)
    if len(infos) > ZIP_MAX_ENTRIES:
        flags.append(Flag("archive_many_entries", "medium", "Archive has a very large number of entries", f"{len(infos)} entries."))
    ratio = total / max(packed, 1)
    if total > ZIP_BOMB_TOTAL or (ratio > ZIP_BOMB_RATIO and total > ZIP_BOMB_RATIO_MIN_TOTAL):
        flags.append(Flag("archive_expansion_risk", "medium", "Archive expands to a very large size",
                          f"Declares {total:,} bytes uncompressed (ratio {ratio:,.0f}:1). Do not extract it without limits."))
    if any(i.flag_bits & 0x1 for i in infos):
        flags.append(Flag("archive_encrypted", "info", "Archive contains encrypted entries", "Contents cannot be inspected without the password."))
    if any(i.filename.lower().endswith("vbaproject.bin") for i in infos):
        flags.append(Flag("office_macros", "medium", "Office document contains a macro project", "A vbaProject.bin entry is present. Macros can run code when opened in Office."))
    if any(".." in i.filename.replace("\\", "/").split("/") or i.filename.startswith(("/", "\\")) for i in infos):
        flags.append(Flag("archive_path_traversal", "medium", "Archive has entry names that escape their folder", "Extracting naively could write files outside the target folder (zip-slip)."))
    return meta, flags


_PDF_TOKENS = [(b"/JavaScript", "JavaScript"), (b"/JS", "JS action"), (b"/OpenAction", "OpenAction"),
               (b"/Launch", "Launch action"), (b"/EmbeddedFile", "embedded file"), (b"/AA", "additional actions")]


def _pdf_info(path: str) -> tuple[dict, list[Flag]]:
    with open(path, "rb") as fh:
        data = fh.read(2 * 1024 * 1024)
    meta = {}
    m = re.match(rb"%PDF-(\d\.\d)", data)
    if m:
        meta["pdf_version"] = m.group(1).decode()
    found = [label for token, label in _PDF_TOKENS if token in data]
    flags = []
    if found:
        sev = "medium" if any(t in found for t in ("JavaScript", "JS action", "Launch action")) else "low"
        flags.append(Flag("pdf_active_content", sev, "PDF contains active-content keywords",
                          f"Found: {', '.join(found)}. Keyword presence is not proof of malice, and keywords inside compressed object streams are not detected."))
        meta["pdf_keywords"] = found
    return meta, flags


def _text_info(path: str) -> dict:
    lines, size = 0, 0
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            size += len(chunk)
            lines += chunk.count(b"\n")
            if size >= ENTROPY_SAMPLE * 4:
                break
    return {"lines_in_first_4mb": lines}


# ----------------------------------------------------------- extension rule
def extension_status(detected: ft.Detected, ext: str) -> tuple[str, str]:
    """Return (status, explanation)."""
    if not ext:
        return "no_extension", "The file has no extension; content type was identified from its bytes."
    allowed = ft.KINDS[detected.kind][3]
    if detected.family == "text":
        if ext in ft.MAGIC_EXTS and ext not in allowed:
            return "mismatch", f"Content is {detected.label.lower()} but the extension '.{ext}' implies a binary format."
        return "ok", "Text-based content; extension is plausible."
    if detected.kind in ("unknown", "empty"):
        if detected.kind == "empty":
            return "unverified", "The file is empty, so its type cannot be verified."
        if ext in ft.MAGIC_EXTS:
            return "mismatch", f"The extension '.{ext}' implies a known format but the content has no matching signature (corrupt, encrypted or disguised)."
        return "unverified", "No known signature; the type cannot be verified from content."
    if ext in allowed:
        return "ok", f"Content matches '.{ext}'."
    return "mismatch", f"Content is {detected.label} but the extension is '.{ext}'."


# ---------------------------------------------------------------- main
def analyze(path: str, original_name: str) -> AnalysisResult:
    """Analyse a file on disk (should be a working copy)."""
    size = os.path.getsize(path)
    detected, zip_names = ft.detect_file(path)
    ext = get_extension(original_name)
    status, why = extension_status(detected, ext)
    flags = name_flags(original_name)
    meta: dict = {"size_bytes": size}

    if status == "mismatch":
        if detected.family in ("executable", "shortcut") and ext not in ft.KINDS[detected.kind][3]:
            flags.append(Flag("executable_disguised", "high", "Executable content with a non-executable extension",
                              f"{why} Executable files renamed to look harmless are a common delivery trick."))
        elif detected.kind in ("html", "svg", "script"):
            flags.append(Flag("active_text_disguised", "medium", "Script/markup content with a binary-format extension", why))
        else:
            flags.append(Flag("extension_mismatch", "medium", "File extension does not match content", why))
    elif status == "unverified" and detected.kind == "unknown":
        flags.append(Flag("unrecognised_type", "info", "Content type could not be identified", why))
    if size == 0:
        flags.append(Flag("empty_file", "info", "File is empty", "Zero bytes. The SHA-256 is that of empty input."))

    try:
        meta["entropy"] = round(shannon_entropy(path), 3)
        if meta["entropy"] >= 7.5 and size >= 1024 and detected.kind not in ft.COMPRESSED_KINDS:
            sev = "medium" if detected.family == "executable" else "low"
            flags.append(Flag("high_entropy", sev, "Content looks encrypted, compressed or packed",
                              f"Shannon entropy {meta['entropy']}/8.0 in a type that is not normally compressed."
                              + (" Packed executables are common in malware, but also in legitimate software." if detected.family == "executable" else "")))
        if detected.kind in ("png", "jpeg", "gif", "bmp"):
            meta.update(_image_dims(path, detected.kind))
        elif detected.kind in ("zip", "docx", "xlsx", "pptx", "ooxml", "odf", "jar", "apk"):
            zmeta, zflags = _zip_info(path)
            meta.update(zmeta)
            flags += zflags
            if zip_names:
                meta["sample_entries"] = zip_names[:25]
        elif detected.kind == "pdf":
            pmeta, pflags = _pdf_info(path)
            meta.update(pmeta)
            flags += pflags
        elif detected.family == "text":
            meta.update(_text_info(path))
    except (OSError, struct.error, ValueError) as exc:  # corrupt file: report, don't crash
        flags.append(Flag("analysis_partial", "info", "Some analysis steps failed", f"{type(exc).__name__}"))

    flags.sort(key=lambda f: -SEVERITY_RANK[f.severity])
    return AnalysisResult(detected.kind, detected.label, detected.mime, detected.family, ext, status, flags, meta)
