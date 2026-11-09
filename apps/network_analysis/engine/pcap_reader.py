"""Bounded, pure-Python reader for classic PCAP and PCAPNG capture files.

The reader only *reads bytes*; it never executes, renders or reassembles content.  Every length field is
validated against the remaining file size and the configured limits before use.
"""
from __future__ import annotations

import os
import struct
import time

from .limits import Limits, ParseError

LINK_NULL, LINK_ETHERNET, LINK_RAW, LINK_LINUX_SLL = 0, 1, 101, 113
SUPPORTED_LINKS = {LINK_NULL, LINK_ETHERNET, LINK_RAW, 12, LINK_LINUX_SLL}


def read_packets(path, limits: Limits = Limits()):
    """Yield (timestamp_float, linktype, data, orig_len). Raises ParseError on invalid input."""
    size = os.path.getsize(path)
    if size < 24:
        raise ParseError("The file is too small to be a packet capture.")
    if size > limits.max_file_bytes:
        raise ParseError("The file is larger than the allowed size.")
    with open(path, "rb") as fh:
        magic = fh.read(4)
        fh.seek(0)
        if magic in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
            yield from _read_pcap(fh, magic, limits)
        elif magic == b"\x0a\x0d\x0d\x0a":
            yield from _read_pcapng(fh, size, limits)
        else:
            raise ParseError("Unrecognised capture format. Supported: .pcap and .pcapng (not compressed).")


def _read_pcap(fh, magic, limits):
    little = magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1")
    nano = magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
    e = "<" if little else ">"
    hdr = fh.read(24)
    if len(hdr) < 24:
        raise ParseError("Truncated PCAP header.")
    _, _, _, _, snaplen, linktype = struct.unpack(e + "HHiIII", hdr[4:])
    if linktype not in SUPPORTED_LINKS:
        raise ParseError(f"Unsupported link type {linktype}. Supported: Ethernet, raw IP, Linux cooked, loopback.")
    div = 1e9 if nano else 1e6
    count = 0
    while True:
        rec = fh.read(16)
        if not rec:
            return
        if len(rec) < 16:
            raise ParseError("The capture is truncated in a packet header.")
        sec, frac, caplen, origlen = struct.unpack(e + "IIII", rec)
        if caplen > limits.max_packet_len:
            raise ParseError("A packet record is larger than the allowed maximum; the file is corrupt or hostile.")
        data = fh.read(caplen)
        if len(data) < caplen:
            raise ParseError("The capture is truncated in packet data.")
        count += 1
        if count > limits.max_packets:
            raise _PacketLimit()
        yield sec + frac / div, linktype, data, origlen


class _PacketLimit(ParseError):
    """Raised internally when the packet limit is hit; analyzer converts this to a warning."""


def _read_pcapng(fh, size, limits):
    e = "<"
    ifaces: list[tuple[int, float]] = []  # (linktype, ts_resolution_divisor)
    count = 0
    while True:
        head = fh.read(8)
        if not head:
            return
        if len(head) < 8:
            raise ParseError("The capture is truncated in a block header.")
        btype = struct.unpack("<I", head[:4])[0]
        if btype == 0x0A0D0D0A:  # section header: byte order lives in the body
            body_start = fh.read(4)
            if len(body_start) < 4:
                raise ParseError("Truncated section header.")
            bom = body_start
            e = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">" if bom == b"\x1a\x2b\x3c\x4d" else None
            if e is None:
                raise ParseError("Invalid PCAPNG byte-order marker.")
            blen = struct.unpack(e + "I", head[4:])[0]
            _skip(fh, blen - 12, size)
            ifaces = []
            continue
        btype, blen = struct.unpack(e + "II", head)
        if blen < 12 or blen % 4 or blen > limits.max_packet_len + 1024:
            raise ParseError("Invalid PCAPNG block length.")
        body = fh.read(blen - 8)
        if len(body) < blen - 8:
            raise ParseError("The capture is truncated in a block.")
        body = body[:-4]
        if btype == 1:  # interface description
            linktype = struct.unpack(e + "H", body[:2])[0]
            ifaces.append((linktype, _tsresol(body[8:], e)))
        elif btype == 6:  # enhanced packet
            if len(body) < 20:
                raise ParseError("Malformed enhanced packet block.")
            idx, hi, lo, caplen, origlen = struct.unpack(e + "IIIII", body[:20])
            if idx >= len(ifaces) or 20 + caplen > len(body):
                raise ParseError("Enhanced packet block references invalid data.")
            link, div = ifaces[idx]
            if link not in SUPPORTED_LINKS:
                continue
            count += 1
            if count > limits.max_packets:
                raise _PacketLimit()
            yield ((hi << 32) | lo) / div, link, body[20:20 + caplen], origlen
        elif btype == 3 and ifaces:  # simple packet
            origlen = struct.unpack(e + "I", body[:4])[0]
            link, _ = ifaces[0]
            if link in SUPPORTED_LINKS:
                count += 1
                if count > limits.max_packets:
                    raise _PacketLimit()
                yield 0.0, link, body[4:4 + origlen], origlen


def _skip(fh, n, size):
    if n < 0 or fh.tell() + n > size:
        raise ParseError("Invalid block length.")
    fh.seek(n, 1)


def _tsresol(options: bytes, e: str) -> float:
    i = 0
    while i + 4 <= len(options):
        code, ln = struct.unpack(e + "HH", options[i:i + 4])
        if code == 0:
            break
        if code == 9 and ln >= 1:
            v = options[i + 4]
            return float(2 ** (v & 0x7F)) if v & 0x80 else float(10 ** min(v, 12))
        i += 4 + ((ln + 3) & ~3)
    return 1e6
