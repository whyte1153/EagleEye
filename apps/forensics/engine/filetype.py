"""File-type identification by CONTENT (magic numbers), extension-mismatch rules and basic metadata.

Nothing here executes, renders or extracts the file.  Detection is signature
based and covers a deliberately limited set of common formats; anything else is
reported as "unrecognised", never guessed.  A match means the first bytes look
like that format, not that the whole file is valid or safe.
"""
from __future__ import annotations

import json
import math
import re
import struct
import zipfile
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone

from .sanitize import extension_of, safe_display_name


@dataclass(frozen=True)
class Detected:
    kind: str
    mime: str
    exts: frozenset
    category: str  # image document archive executable audio video database capture text script other


def D(kind, mime, exts, category):
    return Detected(kind, mime, frozenset(exts.split()), category)


# (offset, signature, Detected)
SIGNATURES = [
    (0, b"\x89PNG\r\n\x1a\n", D("png", "image/png", "png", "image")),
    (0, b"\xff\xd8\xff", D("jpeg", "image/jpeg", "jpg jpeg jpe jfif", "image")),
    (0, b"GIF87a", D("gif", "image/gif", "gif", "image")),
    (0, b"GIF89a", D("gif", "image/gif", "gif", "image")),
    (0, b"II*\x00", D("tiff", "image/tiff", "tif tiff", "image")),
    (0, b"MM\x00*", D("tiff", "image/tiff", "tif tiff", "image")),
    (0, b"%PDF-", D("pdf", "application/pdf", "pdf", "document")),
    (0, b"{\\rtf", D("rtf", "application/rtf", "rtf", "document")),
    (0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", D("ole2", "application/x-ole-storage", "doc dot xls xlt ppt pps msi msg pub vsd", "document")),
    (0, b"PK\x03\x04", D("zip", "application/zip", "zip", "archive")),
    (0, b"PK\x05\x06", D("zip", "application/zip", "zip", "archive")),
    (0, b"Rar!\x1a\x07", D("rar", "application/vnd.rar", "rar", "archive")),
    (0, b"7z\xbc\xaf\x27\x1c", D("7z", "application/x-7z-compressed", "7z", "archive")),
    (0, b"\x1f\x8b", D("gzip", "application/gzip", "gz tgz", "archive")),
    (0, b"BZh", D("bzip2", "application/x-bzip2", "bz2 tbz2", "archive")),
    (0, b"\xfd7zXZ\x00", D("xz", "application/x-xz", "xz txz", "archive")),
    (257, b"ustar", D("tar", "application/x-tar", "tar", "archive")),
    (0, b"\x7fELF", D("elf", "application/x-executable", "elf so bin o out ko axf", "executable")),
    (0, b"\xfe\xed\xfa\xce", D("macho", "application/x-mach-binary", "dylib bin o", "executable")),
    (0, b"\xfe\xed\xfa\xcf", D("macho", "application/x-mach-binary", "dylib bin o", "executable")),
    (0, b"\xce\xfa\xed\xfe", D("macho", "application/x-mach-binary", "dylib bin o", "executable")),
    (0, b"\xcf\xfa\xed\xfe", D("macho", "application/x-mach-binary", "dylib bin o", "executable")),
    (0, b"\xca\xfe\xba\xbe", D("java-class-or-macho-fat", "application/java-vm", "class dylib bin", "executable")),
    (0, b"SQLite format 3\x00", D("sqlite", "application/vnd.sqlite3", "sqlite sqlite3 db db3", "database")),
    (0, b"\xd4\xc3\xb2\xa1", D("pcap", "application/vnd.tcpdump.pcap", "pcap cap", "capture")),
    (0, b"\xa1\xb2\xc3\xd4", D("pcap", "application/vnd.tcpdump.pcap", "pcap cap", "capture")),
    (0, b"M<\xb2\xa1", D("pcap", "application/vnd.tcpdump.pcap", "pcap cap", "capture")),
    (0, b"\xa1\xb2<M", D("pcap", "application/vnd.tcpdump.pcap", "pcap cap", "capture")),
    (0, b"\x0a\x0d\x0d\x0a", D("pcapng", "application/x-pcapng", "pcapng ntar", "capture")),
    (0, b"ID3", D("mp3", "audio/mpeg", "mp3", "audio")),
    (0, b"fLaC", D("flac", "audio/flac", "flac", "audio")),
    (0, b"OggS", D("ogg", "audio/ogg", "ogg oga ogv opus", "audio")),
    (0, b"\x1a\x45\xdf\xa3", D("matroska", "video/x-matroska", "mkv webm mka", "video")),
    (0, b"L\x00\x00\x00\x01\x14\x02\x00", D("lnk", "application/x-ms-shortcut", "lnk", "executable")),
]

SCRIPT_EXTS = set("sh bash zsh py pl rb php js vbs ps1 bat cmd".split())
TEXT_EXTS = set("txt log csv tsv json md xml html htm css ini cfg conf yaml yml sql eml tex c h cpp hpp java srt vcf ics rst toml "
                "svg".split()) | SCRIPT_EXTS
ZIP_FAMILY = set("zip docx xlsx pptx odt ods odp jar apk epub war ear aar whl xpi nupkg vsix kmz cbz".split())
OLE_EXTS = {"doc", "dot", "xls", "xlt", "ppt", "pps", "msi", "msg", "pub", "vsd"}
PE_EXTS = set("exe dll sys scr ocx drv cpl efi mui com".split())
RIFF = {b"WEBP": D("webp", "image/webp", "webp", "image"), b"WAVE": D("wav", "audio/wav", "wav", "audio"),
        b"AVI ": D("avi", "video/x-msvideo", "avi", "video")}


def _all_known_exts() -> set:
    known = set(TEXT_EXTS) | ZIP_FAMILY | OLE_EXTS | PE_EXTS | {"bmp", "ico", "webp", "wav", "avi", "mp4", "m4a", "m4v", "mov", "3gp"}
    for _, _, det in SIGNATURES:
        known |= det.exts
    return known


KNOWN_EXTS = _all_known_exts()
_ZIP_SPECIFIC = {
    "docx": "docx", "xlsx": "xlsx", "pptx": "pptx", "odt": "odt", "ods": "ods", "odp": "odp",
    "jar": "jar", "apk": "apk", "epub": "epub",
}


ZIP_KINDS = set(_ZIP_SPECIFIC.values()) | {"zip"}


# ------------------------------------------------------------------ detection
def _text_kind(head: bytes) -> Detected | None:
    """Recognise text/scripts from a sample; None if it looks binary."""
    if not head:
        return None
    if head.startswith(b"#!"):
        return D("script", "text/x-script", " ".join(SCRIPT_EXTS) + " txt", "script")
    sample = head
    if sample.startswith((b"\xff\xfe", b"\xfe\xff")):
        enc = "utf-16"
    else:
        enc = "utf-8"
    try:
        text = sample.decode(enc)
    except UnicodeDecodeError as exc:
        if exc.start >= len(sample) - 4 and enc == "utf-8":  # sample cut mid-character
            text = sample[: exc.start].decode("utf-8", "ignore")
        else:
            return None
    if not text:
        return None
    ctrl = sum(1 for c in text if ord(c) < 32 and c not in "\t\n\r\f\v")
    if ctrl / len(text) > 0.02 or "\x00" in text:
        return None
    stripped = text.lstrip("﻿ \t\r\n")
    low = stripped[:200].lower()
    if low.startswith("<?xml"):
        return D("xml", "application/xml", "xml svg", "text")
    if low.startswith(("<!doctype html", "<html")):
        return D("html", "text/html", "html htm", "text")
    if stripped[:1] in "{[" and len(sample) < 1_000_000:
        try:
            json.loads(text)
            return D("json", "application/json", "json", "text")
        except ValueError:
            pass
    return D("text", "text/plain", " ".join(TEXT_EXTS), "text")


def _zip_refine(path, det: Detected) -> Detected:
    try:
        with zipfile.ZipFile(path) as zf:
            names = set(zf.namelist()[:5000])
            if "[Content_Types].xml" in names:
                if any(n.startswith("word/") for n in names):
                    return D("docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", "docx", "document")
                if any(n.startswith("xl/") for n in names):
                    return D("xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "xlsx", "document")
                if any(n.startswith("ppt/") for n in names):
                    return D("pptx", "application/vnd.openxmlformats-officedocument.presentationml.presentation", "pptx", "document")
            if "AndroidManifest.xml" in names:
                return D("apk", "application/vnd.android.package-archive", "apk", "executable")
            if "META-INF/MANIFEST.MF" in names:
                return D("jar", "application/java-archive", "jar war ear aar", "executable")
            if "mimetype" in names:
                mt = zf.read("mimetype")[:100].decode("ascii", "ignore")
                for suffix, kind in (("text", "odt"), ("spreadsheet", "ods"), ("presentation", "odp")):
                    if mt.endswith(suffix):
                        return D(kind, mt, kind, "document")
                if mt.endswith("epub+zip"):
                    return D("epub", "application/epub+zip", "epub", "document")
    except (zipfile.BadZipFile, OSError, KeyError, RuntimeError, ValueError):
        pass
    return det


def detect(path, head: bytes | None = None) -> Detected | None:
    """Identify by content.  Returns None when no known signature or text pattern matches."""
    if head is None:
        with open(path, "rb") as fh:
            head = fh.read(65536)
    for offset, sig, det in SIGNATURES:
        if head[offset:offset + len(sig)] == sig:
            if det.kind == "zip":
                return _zip_refine(path, det)
            return det
    if head[:2] == b"BM" and len(head) > 10 and head[6:10] == b"\x00\x00\x00\x00":
        return D("bmp", "image/bmp", "bmp", "image")
    if head[:4] == b"\x00\x00\x01\x00" and len(head) > 5 and head[4:6] != b"\x00\x00":
        return D("ico", "image/x-icon", "ico", "image")
    if head[:4] == b"RIFF" and head[8:12] in RIFF:
        return RIFF[head[8:12]]
    if head[4:8] == b"ftyp":
        return D("mp4", "video/mp4", "mp4 m4a m4v mov 3gp", "video")
    if head[:2] == b"MZ":
        pe = False
        if len(head) >= 0x40:
            (lfanew,) = struct.unpack_from("<I", head, 0x3C)
            pe = lfanew + 4 <= len(head) and head[lfanew:lfanew + 4] == b"PE\x00\x00"
        return D("pe" if pe else "dos-exe", "application/vnd.microsoft.portable-executable", " ".join(PE_EXTS), "executable")
    return _text_kind(head)


# ------------------------------------------------------------ mismatch rules
def check_extension(name: str, det: Detected | None) -> tuple[str, str]:
    """Compare the claimed extension with the detected content.

    Returns (severity, note) where severity is one of
    ``match`` | ``info`` | ``warn`` | ``high``.
    """
    ext = extension_of(name)
    shown = f".{ext}" if ext else "no extension"

    if det is None:
        if ext in TEXT_EXTS:
            return "warn", f"Extension {shown} suggests text, but the content is binary or not valid text."
        if ext in KNOWN_EXTS:
            return "warn", (f"Extension {shown} implies a known format, but the content matches no known signature "
                            "(file may be corrupt, truncated, encrypted or disguised).")
        return "info", "Format not recognised by EagleEye's signature set."

    if det.category == "executable":
        if ext in det.exts or (ext == "" and det.kind in ("elf", "macho")):
            return "match", f"Executable content ({det.kind}) with a consistent extension."
        if ext in ZIP_FAMILY and det.kind in ("apk", "jar"):
            return "match", f"{det.kind.upper()} package."
        return "high", f"Executable content ({det.kind}) carries {shown}: executables disguised as other file types are a common malware technique."

    if det.category == "script":
        if ext in SCRIPT_EXTS or ext == "":
            return "match", "Script with a consistent extension."
        if ext in TEXT_EXTS and ext != "txt":
            return "warn", f"Content starts with a script interpreter line (#!) but the extension is {shown}."
        if ext in KNOWN_EXTS and ext != "txt":
            return "high", f"Executable script content carries {shown}."
        return "info", f"Script content with {shown}."

    if ext in det.exts:
        return "match", f"Content ({det.kind}) matches {shown}."

    if det.kind in ("zip",) and ext in ZIP_FAMILY:
        return "match", f"Generic ZIP container with {shown} (a {ext.upper()} file is a ZIP; internal structure not confirmed)."
    if det.kind in _ZIP_SPECIFIC.values() and ext in ZIP_FAMILY:
        if ext == "zip":
            return "info", f"A {det.kind.upper()} file is a ZIP container; extension .zip is acceptable but less specific."
        return "warn", f"Content is a {det.kind.upper()} package but the extension is {shown}."
    if det.kind == "ole2" and ext in OLE_EXTS:
        return "match", "OLE2 compound document."
    if det.kind == "dos-exe" and ext in PE_EXTS:
        return "match", "DOS/Windows executable."

    if ext == "":
        return "info", f"No extension; content identified as {det.kind}."
    if ext in KNOWN_EXTS:
        return "warn", f"Content is {det.kind} but the extension {shown} belongs to a different format (file may have been renamed)."
    return "info", f"Unrecognised extension {shown}; content identified as {det.kind}."


# ------------------------------------------------------------------ metadata
def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    n = len(data)
    return round(-sum(c / n * math.log2(c / n) for c in Counter(data).values()), 3)


def _png_dims(head):
    if head[12:16] == b"IHDR" and len(head) >= 24:
        w, h = struct.unpack(">II", head[16:24])
        return {"width": w, "height": h}
    return {}


def _gif_dims(head):
    if len(head) >= 10:
        w, h = struct.unpack("<HH", head[6:10])
        return {"width": w, "height": h}
    return {}


def _jpeg_dims(data):
    i = 2
    while i + 9 < len(data):
        if data[i] != 0xFF:
            i += 1
            continue
        marker = data[i + 1]
        if marker in (0xD8, 0x01) or 0xD0 <= marker <= 0xD7:
            i += 2
            continue
        (seglen,) = struct.unpack(">H", data[i + 2:i + 4])
        if 0xC0 <= marker <= 0xCF and marker not in (0xC4, 0xC8, 0xCC):
            h, w = struct.unpack(">HH", data[i + 5:i + 9])
            return {"width": w, "height": h}
        i += 2 + seglen
    return {}


def _zip_listing(path, size: int) -> dict:
    if size > 25 * 1024 * 1024:
        return {"listing_skipped": "Archive larger than 25 MB: entries not listed."}
    try:
        with zipfile.ZipFile(path) as zf:  # reads the central directory only; nothing is extracted
            infos = zf.infolist()
            entries, suspicious, encrypted = [], 0, 0
            for info in infos[:200]:
                name = info.filename
                bad = name.startswith(("/", "\\")) or ".." in name.replace("\\", "/").split("/") or re.match(r"^[A-Za-z]:", name) is not None
                enc = bool(info.flag_bits & 0x1)
                suspicious += bad
                encrypted += enc
                entries.append({"name": safe_display_name(name, 180) if not name.endswith("/") else safe_display_name(name.rstrip("/"), 180) + "/",
                                "size": info.file_size, "compressed": info.compress_size,
                                "encrypted": enc, "suspicious_path": bool(bad)})
            return {"entry_count": len(infos), "entries": entries, "listing_truncated": len(infos) > 200,
                    "suspicious_paths": suspicious, "encrypted_entries": encrypted,
                    "declared_uncompressed_total": sum(i.file_size for i in infos),
                    "note": "Sizes are values declared inside the archive and may be inaccurate."}
    except (zipfile.BadZipFile, OSError, RuntimeError, ValueError):
        return {"listing_error": "Archive structure could not be read (corrupt or not a valid ZIP)."}


def extract_metadata(path, det: Detected | None, size: int) -> dict:
    """Basic, safe metadata.  Reads at most 1 MB for statistics and never interprets embedded code."""
    with open(path, "rb") as fh:
        sample = fh.read(1024 * 1024)
    head = sample[:65536]
    meta: dict = {
        "header_hex": head[:32].hex(" "),
        "entropy_bits_per_byte": shannon_entropy(sample),
        "entropy_note": "Values near 8 are typical of compressed or encrypted data; this alone proves nothing.",
        "sampled_bytes": len(sample),
    }
    if det is None:
        return meta
    if det.kind == "png":
        meta.update(_png_dims(head))
    elif det.kind == "gif":
        meta.update(_gif_dims(head))
    elif det.kind == "jpeg":
        meta.update(_jpeg_dims(head))
    elif det.kind == "pdf":
        m = re.match(rb"%PDF-(\d\.\d)", head)
        meta["pdf_version"] = m.group(1).decode() if m else ""
        meta["has_eof_marker"] = b"%%EOF" in sample[-2048:]
    elif det.kind in ZIP_KINDS:
        meta.update(_zip_listing(path, size))
    elif det.category in ("text", "script"):
        meta["line_count_in_sample"] = sample.count(b"\n") + (1 if sample and not sample.endswith(b"\n") else 0)
        meta["encoding_guess"] = "utf-16" if sample.startswith((b"\xff\xfe", b"\xfe\xff")) else "utf-8"
    elif det.kind == "elf" and len(head) > 5:
        meta["elf_class"] = {1: "32-bit", 2: "64-bit"}.get(head[4], "unknown")
    elif det.kind == "pe":
        meta["note"] = "Windows PE executable. Not executed or parsed beyond its signature."
    return meta


def analyze_file(path, claimed_name: str, size: int, times: dict | None = None) -> dict:
    """Full analysis of a (working copy of a) file.  Returns a JSON-safe dict."""
    det = detect(path)
    severity, note = check_extension(claimed_name, det)
    meta = extract_metadata(path, det, size)
    if times:
        meta["filesystem_timestamps"] = times
        meta["timestamp_caveat"] = ("These are the timestamps of EagleEye's stored copy and reflect upload time. "
                                    "The file's original creation/modification times are not transferred by a browser upload "
                                    "and acquisition or upload can alter metadata.")
    return {
        "detected_kind": det.kind if det else "unrecognised",
        "detected_mime": det.mime if det else "",
        "detected_category": det.category if det else "unknown",
        "declared_extension": extension_of(claimed_name),
        "extension_severity": severity,
        "extension_note": note,
        "mismatch": severity in ("warn", "high"),
        "metadata": meta,
        "analyzed_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
    }
