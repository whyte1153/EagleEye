"""Parsing limits.  Every imported file is untrusted: all loops are bounded by these values."""
from __future__ import annotations

from dataclasses import dataclass


class ParseError(Exception):
    """The file is not a valid file of the expected type (message is safe to show to users)."""


@dataclass(frozen=True)
class Limits:
    max_file_bytes: int = 100 * 1024 * 1024
    # Nmap XML
    max_xml_elements: int = 1_500_000
    max_xml_depth: int = 40
    max_hosts: int = 5_000
    max_ports_total: int = 100_000
    max_text_len: int = 2_000
    # PCAP
    max_packets: int = 500_000
    max_packet_len: int = 262_144
    max_flows: int = 20_000
    max_ips: int = 50_000
    max_dns_names: int = 5_000
    deadline_seconds: float = 60.0
