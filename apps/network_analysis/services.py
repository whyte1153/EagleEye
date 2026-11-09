"""Glue between the pure engines and the database."""
from __future__ import annotations

import csv
import hashlib
import io
import json

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from apps.forensics.engine.sanitize import safe_display_name
from apps.forensics.reports import csv_safe
from apps.scanner.engine.datatypes import SEVERITY_LABELS

from .engine.limits import Limits, ParseError
from .engine.nmap_parser import parse_nmap_xml
from .engine.pcap_analyzer import analyze_pcap
from .models import NetworkHost, NetworkImport

SEV_SLUG = {-1: "none", 0: "info", 1: "low", 2: "medium", 3: "high", 4: "critical"}


def sev_slug(value: int) -> str:
    return SEV_SLUG.get(value, "none")


def sev_label(value: int) -> str:
    return SEVERITY_LABELS.get(value, "Not flagged")


def get_limits() -> Limits:
    return Limits(max_file_bytes=settings.NETWORK_MAX_BYTES, max_hosts=settings.NETWORK_MAX_HOSTS,
                  max_packets=settings.NETWORK_MAX_PACKETS, deadline_seconds=settings.NETWORK_DEADLINE_SECONDS)


class UnsupportedFile(ParseError):
    pass


def sniff_kind(path) -> str:
    """Decide by CONTENT, never by extension or browser-declared type."""
    with open(path, "rb") as fh:
        head = fh.read(4096)
    if head[:4] in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d", b"\x0a\x0d\x0d\x0a"):
        return NetworkImport.PCAP
    if b"<nmaprun" in head or head.lstrip()[:5] == b"<?xml":
        return NetworkImport.NMAP
    raise UnsupportedFile("Unrecognised file. Upload Nmap XML (nmap -oX) or an uncompressed .pcap/.pcapng capture.")


def _sha256_of(upload) -> str:
    h = hashlib.sha256()
    for chunk in upload.chunks():
        h.update(chunk)
    return h.hexdigest()


def import_upload(user, upload, description="", case_reference="") -> NetworkImport:
    """Parse an uploaded file in place (it is never executed, moved into a web directory, or kept).  Raises ParseError."""
    limits = get_limits()
    if upload.size > limits.max_file_bytes:
        raise ParseError(f"The file is larger than the {limits.max_file_bytes // (1024 * 1024)} MB limit.")
    path = upload.temporary_file_path()  # FILE_UPLOAD_HANDLERS always streams to a temp file
    kind = sniff_kind(path)
    sha = _sha256_of(upload)
    display = safe_display_name(upload.name)
    if kind == NetworkImport.NMAP:
        parsed = parse_nmap_xml(path, limits)
        hosts = parsed["hosts"]
        up = [h for h in hosts if h["state"] == "up"]
        sev_counts = {}
        for h in hosts:
            for p in h["ports"]:
                if p["state"] == "open" and p["severity"] >= 0:
                    sev_counts[p["severity"]] = sev_counts.get(p["severity"], 0) + 1
        summary = {"hosts": len(hosts), "hosts_up": len(up), "open_ports": sum(h["open_ports"] for h in hosts),
                   "flagged_ports": sum(sev_counts.values()), "by_severity": {str(k): v for k, v in sev_counts.items()},
                   **{k: v for k, v in parsed["stats"].items() if k in ("elapsed", "summary", "finished")}}
        record = dict(summary=summary, warnings=parsed["warnings"], findings=[], data={"scanner": parsed["scanner"]},
                      max_severity=max((h["max_severity"] for h in hosts), default=-1))
    else:
        parsed = analyze_pcap(path, limits)
        record = dict(summary={**parsed["summary"], "protocols": parsed["protocols"][:12], "flagged": len(parsed["findings"])},
                      warnings=parsed["warnings"], findings=parsed["findings"],
                      data={"protocols": parsed["protocols"], "talkers": parsed["talkers"], "flows": parsed["flows"],
                            "dns": parsed["dns"]},
                      max_severity=max((f["severity"] for f in parsed["findings"]), default=-1))
    with transaction.atomic():
        ni = NetworkImport(kind=kind, original_filename=display, size=upload.size, sha256=sha, imported_by=user,
                           case_reference=case_reference[:100], description=description[:2000], **record)
        ni.save()
        ni.import_id = f"NI-{ni.imported_at.year}-{ni.pk:06d}"
        ni.save(update_fields=["import_id"])
        if kind == NetworkImport.NMAP:
            NetworkHost.objects.bulk_create([
                NetworkHost(network_import=ni, address=h["address"], hostnames=", ".join(h["hostnames"])[:600],
                            state=h["state"], os_guess=h["os_guess"][:140], mac=h["mac"], vendor=h["vendor"],
                            open_ports=h["open_ports"], max_severity=h["max_severity"], ports=h["ports"])
                for h in hosts], batch_size=500)
    return ni


def host_ports(ni, q="", min_sev=None, port=None, only_open=True):
    """Flatten an import's hosts into port rows filtered by search text / severity / port number."""
    q = q.strip().lower()
    rows = []
    for h in ni.hosts.all():
        for p in h.ports:
            if only_open and p["state"] != "open":
                continue
            if min_sev is not None and p["severity"] < min_sev:
                continue
            if port is not None and p["port"] != port:
                continue
            hay = f"{h.address} {h.hostnames} {p['service']} {p['product']} {p['version']} {p['rule_id']} {p['port']}".lower()
            if q and q not in hay:
                continue
            rows.append({**p, "address": h.address, "hostnames": h.hostnames, "sev_slug": sev_slug(p["severity"]),
                         "sev_label": sev_label(p["severity"])})
    rows.sort(key=lambda r: (-r["severity"], r["address"], r["port"]))
    return rows


def ports_csv(rows) -> bytes:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\r\n")
    cols = ["address", "hostnames", "port", "protocol", "state", "service", "product", "version", "severity", "rule", "reason", "recommendation"]
    w.writerow(cols)
    for r in rows:
        w.writerow([csv_safe(v) for v in (r["address"], r["hostnames"], r["port"], r["protocol"], r["state"], r["service"],
                                          r["product"], r["version"], r["sev_label"] if r["severity"] >= 0 else "", r["rule_id"],
                                          r["risk_reason"], r["recommendation"])])
    return ("﻿" + buf.getvalue()).encode("utf-8")


def flows_csv(flows) -> bytes:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\r\n")
    w.writerow(["proto", "src", "sport", "dst", "dport", "packets", "bytes", "tcp_flags_seen", "first_seen"])
    for f in flows:
        w.writerow([csv_safe(v) for v in (f["proto"], f["src"], f["sport"], f["dst"], f["dport"], f["packets"], f["bytes"],
                                          f["flags"], f["first"])])
    return ("﻿" + buf.getvalue()).encode("utf-8")


def export_json(ni, extra=None) -> bytes:
    doc = {"import_id": ni.import_id, "kind": ni.kind, "file": ni.original_filename, "sha256": ni.sha256, "size_bytes": ni.size,
           "imported_at": ni.imported_at.isoformat(), "imported_by": ni.imported_by.get_username() if ni.imported_by else "",
           "summary": ni.summary, "warnings": ni.warnings, "findings": ni.findings,
           "note": "Findings are heuristic indicators from transparent rules, not proof of a vulnerability or an attack."}
    doc.update(extra or {})
    return json.dumps(doc, indent=2, ensure_ascii=False).encode("utf-8")


def import_stats() -> dict:
    qs = NetworkImport.objects
    flagged = qs.filter(max_severity__gte=2).count()
    return {"total": qs.count(), "nmap": qs.filter(kind="nmap").count(), "pcap": qs.filter(kind="pcap").count(), "flagged": flagged}
