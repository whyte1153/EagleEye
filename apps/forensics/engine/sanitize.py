"""Safe handling of user-supplied file names."""
from __future__ import annotations

import unicodedata

_FORBIDDEN = set('<>:"|?*\\/')


def safe_display_name(name: str, max_len: int = 200) -> str:
    """Return a harmless name for DISPLAY only (files are stored under random names).

    Strips directory parts, control characters, and invisible/bidirectional
    format characters (used to spoof extensions, e.g. "invoice‮gpj.exe").
    """
    name = (name or "").replace("\\", "/").split("/")[-1]
    name = unicodedata.normalize("NFC", name)
    name = "".join(ch for ch in name if ch.isprintable() and ch not in _FORBIDDEN)
    name = name.strip(" .")
    if not name:
        return "unnamed"
    if len(name) > max_len:
        stem, dot, ext = name.rpartition(".")
        ext = ext[:20]
        name = (stem[: max_len - len(ext) - 1] + "." + ext) if dot else name[:max_len]
    return name


def extension_of(name: str) -> str:
    """Lower-case extension without the dot ('' when none)."""
    base = safe_display_name(name)
    if "." not in base.lstrip("."):
        return ""
    return base.rsplit(".", 1)[-1].lower()
