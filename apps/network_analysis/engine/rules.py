"""Transparent rules that flag potentially risky exposed services in Nmap results.

A flag means "this service type is commonly a risk when reachable"; it is NOT proof of a vulnerability.
Rules look only at what Nmap reported (state, port, protocol, service name, NSE script output).
No version-based vulnerability claims are made.
"""
from __future__ import annotations

from dataclasses import dataclass

from apps.scanner.engine.datatypes import HIGH, INFO, LOW, MEDIUM


@dataclass(frozen=True)
class Rule:
    rule_id: str
    title: str
    severity: int
    services: tuple = ()        # Nmap service names (lower case)
    ports: tuple = ()           # (port, protocol) fallbacks when the service name is unknown or generic
    reason: str = ""
    recommendation: str = ""


RULES = [
    Rule("telnet", "Telnet exposed", HIGH, ("telnet",), ((23, "tcp"),),
         "Telnet sends credentials and session data in clear text.", "Disable Telnet; use SSH."),
    Rule("remote-r-services", "r-services (rsh/rlogin/rexec) exposed", HIGH, ("exec", "login", "shell", "rsh", "rlogin", "rexec"),
         ((512, "tcp"), (513, "tcp"), (514, "tcp")),
         "Legacy trust-based remote execution with no encryption.", "Disable these services; use SSH."),
    Rule("docker-api", "Docker remote API exposed", HIGH, ("docker",), ((2375, "tcp"),),
         "The unencrypted Docker API usually allows full control of the host.", "Do not expose it; use TLS-protected sockets or SSH tunnels."),
    Rule("ftp", "FTP exposed", MEDIUM, ("ftp",), ((21, "tcp"),),
         "FTP sends credentials and data in clear text.", "Use SFTP or FTPS."),
    Rule("tftp", "TFTP exposed", MEDIUM, ("tftp",), ((69, "udp"),),
         "TFTP has no authentication or encryption.", "Disable it or restrict it to a management network."),
    Rule("smb", "SMB / NetBIOS file sharing exposed", MEDIUM, ("microsoft-ds", "netbios-ssn", "smb"), ((445, "tcp"), (139, "tcp")),
         "File-sharing services are frequent targets for credential attacks and wormable flaws.", "Restrict to trusted networks; patch; disable SMBv1."),
    Rule("rdp", "Remote Desktop exposed", MEDIUM, ("ms-wbt-server", "rdp"), ((3389, "tcp"),),
         "Internet-exposed RDP is heavily brute-forced and has had critical flaws.", "Place behind a VPN or gateway; enable NLA and MFA."),
    Rule("vnc", "VNC exposed", MEDIUM, ("vnc", "vnc-http"), tuple((p, "tcp") for p in range(5900, 5906)),
         "VNC often uses weak passwords and weak or no encryption.", "Tunnel over SSH/VPN; use strong authentication."),
    Rule("cleartext-mail", "POP3 / IMAP without TLS", MEDIUM, ("pop3", "imap"), ((110, "tcp"), (143, "tcp")),
         "Mail retrieval protocols on their plain ports send passwords in clear text.", "Use POP3S/IMAPS or STARTTLS."),
    Rule("snmp", "SNMP exposed", MEDIUM, ("snmp",), ((161, "udp"),),
         "SNMP v1/v2c uses community strings sent in clear text, often left at defaults.", "Use SNMPv3; restrict access."),
    Rule("rpc-nfs", "RPC / NFS exposed", MEDIUM, ("rpcbind", "nfs", "nfs_acl", "sunrpc"), ((111, "tcp"), (111, "udp"), (2049, "tcp")),
         "RPC and NFS expose host details and file shares.", "Restrict to trusted hosts."),
    Rule("x11", "X11 exposed", MEDIUM, ("x11",), tuple((p, "tcp") for p in range(6000, 6006)),
         "Remote X11 can allow screen capture and keystroke injection if access control is weak.", "Do not expose X11."),
    Rule("ajp", "Apache JServ Protocol exposed", MEDIUM, ("ajp13",), ((8009, "tcp"),),
         "AJP exposure has led to file-read and code-execution vulnerabilities.", "Bind to localhost or restrict access."),
    Rule("database", "Database service exposed", MEDIUM,
         ("mysql", "postgresql", "ms-sql-s", "oracle-tns", "mongodb", "redis", "memcached", "couchdb", "elasticsearch", "cassandra"),
         ((3306, "tcp"), (5432, "tcp"), (1433, "tcp"), (1521, "tcp"), (27017, "tcp"), (6379, "tcp"), (11211, "tcp"),
          (5984, "tcp"), (9200, "tcp")),
         "Databases should not be reachable from untrusted networks; some (Redis, Memcached, MongoDB, Elasticsearch) are frequently deployed without authentication.",
         "Bind to internal interfaces and require authentication."),
    Rule("http-clear", "Unencrypted web service", LOW, ("http", "http-alt", "http-proxy"), ((80, "tcp"), (8080, "tcp")),
         "HTTP traffic and any logins are readable on the network path.", "Serve over HTTPS and redirect HTTP."),
    Rule("ldap-clear", "LDAP (plain) exposed", LOW, ("ldap",), ((389, "tcp"),),
         "LDAP on its plain port can send bind credentials in clear text unless StartTLS is enforced.", "Use LDAPS or require StartTLS."),
    Rule("ssh", "SSH exposed", INFO, ("ssh",), ((22, "tcp"),),
         "Informational: SSH is reachable. Ensure key-based auth and current software.", "Restrict by source address; disable password login."),
]

# NSE script output that escalates a finding.
SCRIPT_RULES = [
    ("ftp-anon", "anonymous ftp login allowed", HIGH, "ftp-anon", "Anonymous FTP login allowed",
     "Anyone can log in and list or fetch files.", "Disable anonymous access."),
    ("smb-security-mode", "message_signing: disabled", MEDIUM, "smb-signing", "SMB message signing disabled",
     "Without signing, SMB sessions can be relayed or tampered with.", "Require SMB signing."),
    ("smb-security-mode", "message_signing: supported", LOW, "smb-signing", "SMB message signing not required",
     "Signing is supported but not enforced.", "Require SMB signing."),
]


@dataclass(frozen=True)
class Risk:
    rule_id: str
    title: str
    severity: int
    reason: str
    recommendation: str


def assess_port(port: int, protocol: str, service: str, state: str, scripts: dict[str, str]) -> Risk | None:
    """Return the most severe applicable Risk for an OPEN port, else None."""
    if state != "open":
        return None
    service = (service or "").lower()
    protocol = (protocol or "").lower()
    candidates: list[Risk] = []
    for sid, needle, sev, rid, title, reason, rec in SCRIPT_RULES:
        out = scripts.get(sid, "")
        if out and needle in out.lower():
            candidates.append(Risk(rid, title, sev, reason, rec))
    for rule in RULES:
        by_service = service in rule.services
        # Port is only trusted when Nmap could not identify the service.
        by_port = (port, protocol) in rule.ports and service in ("", "unknown", "tcpwrapped")
        if by_service or by_port:
            candidates.append(Risk(rule.rule_id, rule.title, rule.severity, rule.reason, rule.recommendation))
    if not candidates:
        return None
    return max(candidates, key=lambda r: r.severity)
