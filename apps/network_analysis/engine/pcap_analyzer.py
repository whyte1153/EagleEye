"""Summarise a capture: protocols, top talkers, flows, DNS names, and transparent heuristic findings.

Heuristics are indicators for a human to review, not proof of an attack.  Packet payloads are NOT stored.
"""
from __future__ import annotations

import ipaddress
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone

from apps.scanner.engine.datatypes import HIGH, INFO, LOW, MEDIUM

from .decode import decode_packet
from .limits import Limits, ParseError
from .pcap_reader import _PacketLimit, read_packets

CLEARTEXT = {21: "FTP", 23: "Telnet", 25: "SMTP", 80: "HTTP", 110: "POP3", 143: "IMAP", 161: "SNMP", 69: "TFTP"}
CLEARTEXT_SEV = {23: HIGH, 21: MEDIUM, 69: MEDIUM, 161: MEDIUM, 25: LOW, 80: LOW, 110: MEDIUM, 143: MEDIUM}
SCAN_PORT_THRESHOLD = 20   # distinct destination ports probed by one source with SYN-only packets
SWEEP_HOST_THRESHOLD = 20  # distinct destination hosts probed by one source
DNS_LONG_LABEL = 40


def _iso(ts):
    try:
        return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC") if ts else ""
    except (OverflowError, OSError, ValueError):
        return ""


def analyze_pcap(path, limits: Limits = Limits()) -> dict:
    deadline = time.monotonic() + limits.deadline_seconds
    warnings: list[str] = []
    proto, flows = Counter(), {}
    ip_pkts, ip_bytes = Counter(), Counter()
    dns = Counter()
    syn_ports, syn_hosts = defaultdict(set), defaultdict(set)
    cleartext = Counter()
    total = undecoded = total_bytes = 0
    first = last = 0.0

    try:
        for ts, link, data, orig in read_packets(path, limits):
            total += 1
            total_bytes += orig
            if ts:
                first = ts if not first else min(first, ts)
                last = max(last, ts)
            if total % 2000 == 0 and time.monotonic() > deadline:
                warnings.append("Time limit reached: analysis stopped early; results cover part of the capture.")
                break
            p = decode_packet(link, data)
            if p is None:
                undecoded += 1
                continue
            proto[p["proto"]] += 1
            src, dst = p["src"], p["dst"]
            for ip in (src, dst):
                if ip in ip_pkts or len(ip_pkts) < limits.max_ips:
                    ip_pkts[ip] += 1
                    ip_bytes[ip] += orig
            if p["proto"] in ("TCP", "UDP"):
                key = (p["proto"], src, p["sport"], dst, p["dport"])
                rkey = (p["proto"], dst, p["dport"], src, p["sport"])
                key = rkey if rkey in flows else key
                f = flows.get(key)
                if f is None and len(flows) < limits.max_flows:
                    f = flows[key] = {"proto": p["proto"], "src": src, "sport": p["sport"], "dst": dst,
                                      "dport": p["dport"], "packets": 0, "bytes": 0, "flags": set(), "first": ts}
                if f is not None:
                    f["packets"] += 1
                    f["bytes"] += orig
                    f["flags"].update(p["flags"])
                if p["proto"] == "TCP" and p["flags"] == "S":
                    if len(syn_ports[src]) < 500:
                        syn_ports[src].add((dst, p["dport"]))
                    if len(syn_hosts[src]) < 500:
                        syn_hosts[src].add(dst)
                for port in (p["dport"], p["sport"]):
                    if port in CLEARTEXT and p["payload"] > 0:
                        cleartext[(CLEARTEXT[port], port, src if port == p["dport"] else dst,
                                   dst if port == p["dport"] else src)] += 1
                        break
            if p["info"].startswith("dns:") and (p["info"][4:] in dns or len(dns) < limits.max_dns_names):
                dns[p["info"][4:]] += 1
    except _PacketLimit:
        warnings.append(f"Packet limit reached: only the first {limits.max_packets} packets were analysed.")
    except ParseError:
        raise

    if total == 0:
        raise ParseError("The capture contains no packets.")
    if undecoded:
        warnings.append(f"{undecoded} packet(s) could not be decoded (unsupported or malformed) and were counted only.")
    if len(flows) >= limits.max_flows:
        warnings.append(f"Flow table limit reached ({limits.max_flows}); later new flows are not listed.")

    findings = _findings(syn_ports, syn_hosts, cleartext, dns)
    flow_list = []
    for f in sorted(flows.values(), key=lambda x: -x["bytes"]):
        flow_list.append({**f, "flags": "".join(sorted(f["flags"])), "first": _iso(f["first"])})
    talkers = [{"ip": ip, "packets": n, "bytes": ip_bytes[ip], "scope": _scope(ip)} for ip, n in ip_pkts.most_common(50)]
    return {
        "summary": {"packets": total, "bytes": total_bytes, "decoded": total - undecoded, "first_seen": _iso(first),
                    "last_seen": _iso(last), "duration_s": round(last - first, 3) if last and first else 0,
                    "unique_ips": len(ip_pkts), "flows": len(flows)},
        "protocols": [{"name": k, "packets": v} for k, v in proto.most_common()],
        "talkers": talkers, "flows": flow_list, "dns": [{"name": k, "count": v} for k, v in dns.most_common(500)],
        "findings": findings, "warnings": warnings,
    }


def _scope(ip: str) -> str:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return "unknown"
    return "private" if a.is_private else "multicast" if a.is_multicast else "public"


def _findings(syn_ports, syn_hosts, cleartext, dns):
    out = []
    for src, targets in syn_ports.items():
        per_host = defaultdict(set)
        for host, port in targets:
            per_host[host].add(port)
        for host, ports in per_host.items():
            if len(ports) >= SCAN_PORT_THRESHOLD:
                out.append({"rule_id": "port-scan-pattern", "severity": MEDIUM,
                            "title": "Possible port scan",
                            "detail": f"{src} sent SYN-only packets to {len(ports)} different ports on {host}.",
                            "recommendation": "Confirm whether this was an authorised scan. If not, investigate the source host."})
    for src, hosts in syn_hosts.items():
        if len(hosts) >= SWEEP_HOST_THRESHOLD:
            out.append({"rule_id": "host-sweep-pattern", "severity": MEDIUM, "title": "Possible host sweep",
                        "detail": f"{src} sent SYN-only packets to {len(hosts)} different hosts.",
                        "recommendation": "Confirm whether this was an authorised discovery scan."})
    for (name, port, client, server), n in cleartext.most_common(30):
        out.append({"rule_id": f"cleartext-{name.lower()}", "severity": CLEARTEXT_SEV.get(port, LOW),
                    "title": f"Cleartext {name} traffic",
                    "detail": f"{client} exchanged {n} data packet(s) with {server} on port {port} ({name}), which is not encrypted.",
                    "recommendation": "Prefer an encrypted alternative (SSH, SFTP, HTTPS, IMAPS/POP3S) and avoid sending credentials in cleartext."})
    for name, n in dns.items():
        labels = name.split(".")
        if any(len(l) > DNS_LONG_LABEL for l in labels):
            out.append({"rule_id": "dns-long-label", "severity": LOW, "title": "Unusually long DNS label",
                        "detail": f"Query for '{name[:120]}' ({n}x) has a label over {DNS_LONG_LABEL} characters, sometimes seen with DNS tunnelling or random-name malware; also common with some CDNs.",
                        "recommendation": "Review the domain and the querying host; this is an indicator only."})
    out.sort(key=lambda f: -f["severity"])
    return out[:200]


def filter_flows(flows, ip="", port=None, proto="", text=""):
    """Filter a list of flow dicts. Pure function used by the web layer."""
    ip, proto, text = ip.strip(), proto.strip().upper(), text.strip().lower()
    res = []
    for f in flows:
        if ip and ip not in (f["src"], f["dst"]):
            continue
        if port is not None and port not in (f["sport"], f["dport"]):
            continue
        if proto and f["proto"] != proto:
            continue
        if text and text not in f"{f['src']} {f['dst']} {f['sport']} {f['dport']} {f['proto']}".lower():
            continue
        res.append(f)
    return res
