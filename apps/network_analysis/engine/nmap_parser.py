"""Safe parser for Nmap XML (-oX) output.

Hardening:
* Files containing DTD internal subsets, ENTITY declarations, or external DOCTYPE references are rejected
  before parsing (stops entity-expansion and XXE attacks).  Nmap's own plain ``<!DOCTYPE nmaprun>`` is accepted.
* Incremental parsing with limits on file size, element count, nesting depth, hosts and ports.
* Nothing in the file is executed, fetched, or transformed (the xml-stylesheet instruction is ignored).
* All text is length-limited and stripped of control characters; IP addresses are validated.
"""
from __future__ import annotations

import ipaddress
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

from .limits import Limits, ParseError
from .rules import assess_port

_DOCTYPE_RE = re.compile(rb"<!DOCTYPE\s+([^>\[]*?)\s*(\[|>)", re.I | re.S)
_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f‪-‮⁦-⁩]")
SCRIPTS_KEPT = {"ftp-anon", "smb-security-mode", "http-title", "ssh-hostkey", "banner", "ssl-cert", "smb-os-discovery"}


def clean(text, limit: int) -> str:
    return _CTRL_RE.sub("", text or "")[:limit]


def _reject_dangerous_markup(head: bytes) -> None:
    low = head.lower()
    if b"<!entity" in low or b"<!element" in low or b"<!attlist" in low:
        raise ParseError("The file contains DTD declarations, which are not allowed (possible XML entity attack).")
    for m in _DOCTYPE_RE.finditer(head):
        name, closer = m.group(1).strip().lower(), m.group(2)
        if closer == b"[" or name != b"nmaprun":
            raise ParseError("The file declares a DOCTYPE other than plain 'nmaprun', which is not allowed.")


def _epoch(value):
    try:
        return datetime.fromtimestamp(int(value), timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except (TypeError, ValueError, OverflowError, OSError):
        return ""


def parse_nmap_xml(path, limits: Limits = Limits()) -> dict:
    """Parse an Nmap XML file.  Returns a JSON-safe dict; raises ParseError for invalid or abusive input."""
    import os
    size = os.path.getsize(path)
    if size == 0:
        raise ParseError("The file is empty.")
    if size > limits.max_file_bytes:
        raise ParseError("The file is larger than the allowed size.")
    with open(path, "rb") as fh:
        head = fh.read(8192)
    if b"<nmaprun" not in head and b"<nmaprun" not in _tail_probe(path):
        raise ParseError("This does not look like Nmap XML output (no <nmaprun> element). Create it with: nmap -oX scan.xml <target>")
    _reject_dangerous_markup(head)

    warnings: list[str] = []
    result: dict = {"scanner": {}, "hosts": [], "stats": {}, "warnings": warnings}
    elements = depth = ports_total = 0
    skipped_hosts = skipped_ports = bad_addresses = 0
    seen_root = False

    parser = ET.XMLParser()  # expat: external entities are never fetched; internal subset rejected above
    try:
        with open(path, "rb") as fh:
            for event, el in ET.iterparse(fh, events=("start", "end"), parser=parser):
                if event == "start":
                    elements += 1
                    depth += 1
                    if elements > limits.max_xml_elements:
                        raise ParseError("The file has too many XML elements to analyse safely.")
                    if depth > limits.max_xml_depth:
                        raise ParseError("The XML is nested too deeply.")
                    if not seen_root:
                        seen_root = True
                        if el.tag != "nmaprun":
                            raise ParseError("The root element is not <nmaprun>: not an Nmap XML file.")
                        result["scanner"] = {
                            "scanner": clean(el.get("scanner"), 40), "version": clean(el.get("version"), 40),
                            "args": clean(el.get("args"), 500), "started": _epoch(el.get("start")),
                            "xml_output_version": clean(el.get("xmloutputversion"), 10)}
                    continue
                depth -= 1
                if el.tag == "host":
                    if len(result["hosts"]) >= limits.max_hosts:
                        skipped_hosts += 1
                    else:
                        host, nports, bad = _parse_host(el, limits, ports_total)
                        bad_addresses += bad
                        if host:
                            ports_total += nports
                            skipped_ports += host.pop("_skipped_ports", 0)
                            result["hosts"].append(host)
                        else:
                            bad_addresses += 0
                    el.clear()
                elif el.tag == "finished":
                    result["stats"].update({"finished": _epoch(el.get("time")), "elapsed": clean(el.get("elapsed"), 20),
                                            "summary": clean(el.get("summary"), 300)})
                    el.clear()
                elif el.tag == "hosts" and el.get("up") is not None:
                    result["stats"].update({"hosts_up": _int(el.get("up")), "hosts_down": _int(el.get("down")),
                                            "hosts_total": _int(el.get("total"))})
    except ET.ParseError:
        raise ParseError("The XML is malformed or truncated.") from None

    if not seen_root:
        raise ParseError("The file is not valid Nmap XML.")
    if skipped_hosts:
        warnings.append(f"Host limit reached: {skipped_hosts} further host(s) were not imported (limit {limits.max_hosts}).")
    if skipped_ports:
        warnings.append(f"Port limit reached: {skipped_ports} port entries were not imported (limit {limits.max_ports_total}).")
    if bad_addresses:
        warnings.append(f"{bad_addresses} host(s) had no valid IP address and were skipped.")
    result["element_count"] = elements
    return result


def _tail_probe(path) -> bytes:
    import os
    with open(path, "rb") as fh:
        fh.seek(max(0, os.path.getsize(path) - 4096))
        return fh.read()


def _int(v, default=0):
    try:
        return max(0, int(v))
    except (TypeError, ValueError):
        return default


def _parse_host(el, limits: Limits, ports_so_far: int):
    """Returns (host_dict | None, ports_imported, invalid_address_count)."""
    addr, addr_type, mac, vendor = "", "", "", ""
    for a in el.findall("address"):
        t = a.get("addrtype", "")
        value = clean(a.get("addr"), 64)
        if t in ("ipv4", "ipv6") and not addr:
            try:
                addr = str(ipaddress.ip_address(value))
                addr_type = t
            except ValueError:
                pass
        elif t == "mac":
            mac, vendor = value, clean(a.get("vendor"), 80)
    if not addr:
        return None, 0, 1
    status = el.find("status")
    state = clean(status.get("state") if status is not None else "unknown", 20)
    hostnames = [clean(h.get("name"), 255) for h in el.findall("hostnames/hostname") if h.get("name")][:10]
    os_guess = ""
    best = None
    for m in el.findall("os/osmatch"):
        acc = _int(m.get("accuracy"))
        if best is None or acc > best[0]:
            best = (acc, clean(m.get("name"), 120))
    if best:
        os_guess = f"{best[1]} ({best[0]}%)"

    ports, skipped = [], 0
    for p in el.findall("ports/port"):
        if ports_so_far + len(ports) >= limits.max_ports_total:
            skipped += 1
            continue
        port_no = _int(p.get("portid"), -1)
        if not 0 <= port_no <= 65535:
            continue
        proto = clean(p.get("protocol"), 8).lower()
        st = p.find("state")
        pstate = clean(st.get("state") if st is not None else "unknown", 20)
        svc = p.find("service")
        service = clean(svc.get("name") if svc is not None else "", 60).lower()
        scripts = {clean(s.get("id"), 60): clean(s.get("output"), limits.max_text_len) for s in p.findall("script")}
        risk = assess_port(port_no, proto, service, pstate, scripts)
        kept = "\n".join(f"{k}: {v}" for k, v in scripts.items() if k in SCRIPTS_KEPT)[: limits.max_text_len]
        ports.append({
            "port": port_no, "protocol": proto, "state": pstate, "service": service,
            "product": clean(svc.get("product") if svc is not None else "", 120),
            "version": clean(svc.get("version") if svc is not None else "", 120),
            "extrainfo": clean(svc.get("extrainfo") if svc is not None else "", 200),
            "tunnel": clean(svc.get("tunnel") if svc is not None else "", 10),
            "script_output": kept,
            "severity": risk.severity if risk else -1, "rule_id": risk.rule_id if risk else "",
            "risk_title": risk.title if risk else "", "risk_reason": risk.reason if risk else "",
            "recommendation": risk.recommendation if risk else "",
        })
    extra = [{"state": clean(e.get("state"), 20), "count": _int(e.get("count"))} for e in el.findall("ports/extraports")]
    open_ports = [p for p in ports if p["state"] == "open"]
    host = {
        "address": addr, "addr_type": addr_type, "hostnames": hostnames, "mac": mac, "vendor": vendor,
        "state": state, "os_guess": os_guess, "ports": ports, "extraports": extra,
        "open_ports": len(open_ports), "max_severity": max((p["severity"] for p in open_ports), default=-1),
        "_skipped_ports": skipped,
    }
    return host, len(ports), 0
