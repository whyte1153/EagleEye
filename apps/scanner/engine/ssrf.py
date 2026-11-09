"""Target normalisation and SSRF protection.

Rules enforced *before any connection is made*, and again for every redirect hop:

1. Only http/https URLs, no credentials in the URL, sane length/characters.
2. There is no host allowlist: the user attests authorization for each scan on the web form.
   Safety comes from rules 3-5 (and the lab-mode rule for loopback/private targets).
3. The port must be permitted.
4. DNS is resolved by us, ALL returned addresses must be public (global) unless
   the host is an explicitly configured lab target.  Cloud-metadata addresses
   are blocked even for lab targets.
5. The caller then connects to the validated IP address itself (see fetcher.py),
   so a second DNS lookup can never return a different, internal address
   (DNS rebinding).
"""
from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass
from typing import Callable
from urllib.parse import urlsplit

MAX_URL_LENGTH = 2048

METADATA_IPS = {
    ipaddress.ip_address(a)
    for a in ("169.254.169.254", "169.254.170.2", "100.100.100.200", "192.0.0.192", "fd00:ec2::254")
}
METADATA_HOSTS = {"metadata.google.internal", "metadata", "instance-data", "metadata.goog"}

_SCHEME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.\-]*://")
_BAD_CHARS_RE = re.compile(r"[\s\x00-\x1f\x7f\\]")


class InvalidTarget(ValueError):
    """The submitted URL is malformed or uses a disallowed scheme."""


class TargetBlocked(Exception):
    """The target is well-formed but not permitted by policy."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class ResolveError(Exception):
    """DNS resolution failed (a network problem, not a policy decision)."""


@dataclass(frozen=True)
class ScanPolicy:
    lab_mode: bool = False
    lab_targets: tuple = ()  # entries: "host" or "host:port"
    allowed_ports: frozenset = frozenset({80, 443, 8080, 8443})
    timeout: float = 8.0
    max_body_bytes: int = 262_144
    max_redirects: int = 5
    deadline: float = 30.0
    resolver: Callable | None = None  # (host, port) -> list[str]; injectable for tests


@dataclass(frozen=True)
class Target:
    url: str
    scheme: str
    host: str
    port: int
    path: str  # path + query, always starts with "/"

    @property
    def default_port(self) -> bool:
        return self.port == (443 if self.scheme == "https" else 80)

    @property
    def host_header(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        return host if self.default_port else f"{host}:{self.port}"


def normalize_url(raw: str) -> Target:
    """Validate and normalise user input.  Bare hosts default to https://."""
    if not isinstance(raw, str):
        raise InvalidTarget("URL must be text.")
    raw = raw.strip()
    if not raw:
        raise InvalidTarget("URL is empty.")
    if len(raw) > MAX_URL_LENGTH:
        raise InvalidTarget("URL is too long.")
    if _BAD_CHARS_RE.search(raw):
        raise InvalidTarget("URL contains whitespace, control characters or backslashes.")
    if "://" not in raw:
        raw = "https://" + raw
    elif not _SCHEME_RE.match(raw):
        raise InvalidTarget("Malformed URL.")

    try:
        parts = urlsplit(raw)
        port = parts.port  # raises ValueError for invalid ports
    except ValueError:
        raise InvalidTarget("Malformed URL or port.") from None

    scheme = parts.scheme.lower()
    if scheme not in ("http", "https"):
        raise InvalidTarget("Only http and https URLs are allowed.")
    if "@" in parts.netloc:
        raise InvalidTarget("URLs containing credentials are not allowed.")
    host = (parts.hostname or "").lower().rstrip(".")
    if not host:
        raise InvalidTarget("URL has no host.")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError:
            raise InvalidTarget("Host name is not valid.") from None
        if not re.fullmatch(r"[a-z0-9]([a-z0-9\-_.]*[a-z0-9])?", host) or ".." in host:
            raise InvalidTarget("Host name is not valid.")

    if port is None:
        port = 443 if scheme == "https" else 80
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query

    default = port == (443 if scheme == "https" else 80)
    shown = f"[{host}]" if ":" in host else host
    url = f"{scheme}://{shown}{'' if default else f':{port}'}{path}"
    return Target(url=url, scheme=scheme, host=host, port=port, path=path)


# --------------------------------------------------------------------------
def lab_match(target: Target, policy: ScanPolicy) -> bool:
    """True only when lab mode is on AND the target is an explicit lab entry."""
    if not policy.lab_mode:
        return False
    for entry in policy.lab_targets:
        entry = entry.strip().lower()
        if not entry:
            continue
        if entry.count(":") == 1:
            host, _, port = entry.partition(":")
            if host == target.host and port.isdigit() and int(port) == target.port:
                return True
        elif entry == target.host:
            return True
    return False


def check_allowed(target: Target, policy: ScanPolicy) -> bool:
    """Static policy checks (no DNS).  Returns True if the target is a lab target."""
    if target.host in METADATA_HOSTS:
        raise TargetBlocked("Cloud metadata hosts are never scannable.")
    try:
        literal = ipaddress.ip_address(target.host)
    except ValueError:
        literal = None
    if literal is not None and _unwrap(literal) in METADATA_IPS:
        raise TargetBlocked("Cloud metadata addresses are never scannable.")

    is_lab = lab_match(target, policy)
    if not is_lab:
        if target.port not in policy.allowed_ports:
            raise TargetBlocked(f"Port {target.port} is not permitted.")
    return is_lab


def _unwrap(ip):
    """Treat IPv4-mapped / 6to4-style IPv6 forms as the embedded IPv4 address."""
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped:
            return ip.ipv4_mapped
        if ip.sixtofour:
            return ip.sixtofour
    return ip


def _default_resolver(host: str, port: int) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError) as exc:
        raise ResolveError(f"DNS resolution failed for '{host}'.") from exc
    return [info[4][0] for info in infos]


def resolve_and_validate(target: Target, policy: ScanPolicy) -> list[str]:
    """Return validated IP addresses to connect to, or raise TargetBlocked."""
    is_lab = check_allowed(target, policy)
    try:
        ipaddress.ip_address(target.host)
        raw = [target.host]
    except ValueError:
        resolver = policy.resolver or _default_resolver
        raw = list(resolver(target.host, target.port))
    if not raw:
        raise ResolveError(f"DNS returned no addresses for '{target.host}'.")

    validated: list[str] = []
    for text in dict.fromkeys(raw):  # unique, order preserved
        ip = _unwrap(ipaddress.ip_address(text.split("%")[0]))
        if ip in METADATA_IPS:
            raise TargetBlocked("Resolves to a cloud metadata address.")
        # is_global alone is not enough: Python reports some multicast ranges as global.
        public = ip.is_global and not (ip.is_multicast or ip.is_reserved or ip.is_unspecified
                                       or ip.is_loopback or ip.is_link_local or ip.is_private)
        if not public and not is_lab:
            raise TargetBlocked(f"'{target.host}' resolves to a non-public address ({ip}).")
        validated.append(str(ip))
    # Prefer IPv4: simplest and most widely reachable.
    validated.sort(key=lambda s: ":" in s)
    return validated
