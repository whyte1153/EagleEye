"""Minimal, bounds-checked decoders for Ethernet/IPv4/IPv6/TCP/UDP/ICMP/ARP/DNS.  Never raises on bad data."""
from __future__ import annotations

import ipaddress
import struct

TCP_FLAGS = (("F", 0x01), ("S", 0x02), ("R", 0x04), ("P", 0x08), ("A", 0x10), ("U", 0x20))


def decode_packet(linktype: int, data: bytes) -> dict | None:
    try:
        if linktype == 1:
            return _eth(data)
        if linktype in (101, 12):
            return _ip(data, 0)
        if linktype == 113 and len(data) >= 16:
            proto = struct.unpack("!H", data[14:16])[0]
            return _l3(proto, data, 16)
        if linktype == 0 and len(data) >= 4:
            return _ip(data, 4)
    except (struct.error, IndexError, ValueError):
        return None
    return None


def _eth(d):
    if len(d) < 14:
        return None
    et, off = struct.unpack("!H", d[12:14])[0], 14
    while et in (0x8100, 0x88A8) and len(d) >= off + 4:  # VLAN tags
        et = struct.unpack("!H", d[off + 2:off + 4])[0]
        off += 4
    return _l3(et, d, off)


def _l3(et, d, off):
    if et == 0x0800 or et == 0x86DD:
        return _ip(d, off)
    if et == 0x0806 and len(d) >= off + 28:
        op = struct.unpack("!H", d[off + 6:off + 8])[0]
        return {"proto": "ARP", "src": str(ipaddress.IPv4Address(d[off + 14:off + 18])),
                "dst": str(ipaddress.IPv4Address(d[off + 24:off + 28])), "sport": None, "dport": None,
                "flags": "", "info": "who-has" if op == 1 else "is-at" if op == 2 else f"op {op}", "payload": 0}
    return None


def _ip(d, off):
    ver = d[off] >> 4
    if ver == 4:
        ihl = (d[off] & 15) * 4
        if ihl < 20 or len(d) < off + ihl:
            return None
        proto = d[off + 9]
        src, dst = str(ipaddress.IPv4Address(d[off + 12:off + 16])), str(ipaddress.IPv4Address(d[off + 16:off + 20]))
        frag = struct.unpack("!H", d[off + 6:off + 8])[0] & 0x1FFF
        return _l4(proto, src, dst, d, off + ihl, frag)
    if ver == 6 and len(d) >= off + 40:
        nxt = d[off + 6]
        src, dst = str(ipaddress.IPv6Address(d[off + 8:off + 24])), str(ipaddress.IPv6Address(d[off + 24:off + 40]))
        return _l4(nxt, src, dst, d, off + 40, 0)
    return None


def _l4(proto, src, dst, d, off, frag):
    base = {"src": src, "dst": dst, "sport": None, "dport": None, "flags": "", "info": "", "payload": 0}
    if frag:
        return {**base, "proto": "IP-frag"}
    if proto == 6 and len(d) >= off + 20:
        sp, dp, _, _, doff, fl = struct.unpack("!HHIIBB", d[off:off + 14])
        hl = (doff >> 4) * 4
        flags = "".join(c for c, bit in TCP_FLAGS if fl & bit)
        return {**base, "proto": "TCP", "sport": sp, "dport": dp, "flags": flags, "payload": max(0, len(d) - off - hl)}
    if proto == 17 and len(d) >= off + 8:
        sp, dp, ln = struct.unpack("!HHH", d[off:off + 6])
        out = {**base, "proto": "UDP", "sport": sp, "dport": dp, "payload": max(0, len(d) - off - 8)}
        if 53 in (sp, dp):
            q = dns_query_name(d[off + 8:])
            if q:
                out["info"] = "dns:" + q
        return out
    if proto in (1, 58) and len(d) >= off + 2:
        return {**base, "proto": "ICMP" if proto == 1 else "ICMPv6", "info": f"type {d[off]} code {d[off + 1]}"}
    return {**base, "proto": f"IP-proto-{proto}"}


def dns_query_name(payload: bytes) -> str:
    """First question name of a DNS message, with strict bounds (no compression pointers followed)."""
    if len(payload) < 13:
        return ""
    qd = struct.unpack("!H", payload[4:6])[0]
    if qd < 1:
        return ""
    i, labels = 12, []
    while i < len(payload) and len(labels) < 32:
        n = payload[i]
        if n == 0:
            break
        if n & 0xC0 or i + 1 + n > len(payload):
            return ""
        label = payload[i + 1:i + 1 + n]
        if not all(32 < b < 127 for b in label):
            return ""
        labels.append(label.decode("ascii"))
        i += 1 + n
    name = ".".join(labels).lower()
    return name[:253]
