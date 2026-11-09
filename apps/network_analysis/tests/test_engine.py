"""Pure-Python engine tests (no Django needed): python -m unittest apps.network_analysis.tests.test_engine"""
import os
import socket
import struct
import tempfile
import unittest

from apps.network_analysis.engine.decode import decode_packet, dns_query_name
from apps.network_analysis.engine.limits import Limits, ParseError
from apps.network_analysis.engine.nmap_parser import parse_nmap_xml
from apps.network_analysis.engine.pcap_analyzer import analyze_pcap, filter_flows
from apps.network_analysis.engine.rules import assess_port

NMAP = b'''<?xml version="1.0"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sV x" start="1762000000" version="7.94">
<host><status state="up"/><address addr="192.168.56.10" addrtype="ipv4"/>
<ports>
<port protocol="tcp" portid="21"><state state="open"/><service name="ftp"/><script id="ftp-anon" output="Anonymous FTP login allowed"/></port>
<port protocol="tcp" portid="23"><state state="open"/><service name="telnet"/></port>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port>
<port protocol="tcp" portid="445"><state state="closed"/><service name="microsoft-ds"/></port>
<port protocol="tcp" portid="3389"><state state="open"/><service name="unknown"/></port>
<port protocol="tcp" portid="8080"><state state="open"/><service name="http-proxy"/></port>
</ports></host>
<host><status state="up"/><address addr="not-an-ip" addrtype="ipv4"/></host>
</nmaprun>'''


def _write(data, suffix=".bin"):
    fd, p = tempfile.mkstemp(suffix=suffix)
    os.write(fd, data)
    os.close(fd)
    return p


def _ip(src, dst, proto, payload):
    return struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 1, 0, 64, proto, 0,
                       socket.inet_aton(src), socket.inet_aton(dst)) + payload


def _tcp(sp, dp, fl, data=b""):
    return struct.pack("!HHIIBBHHH", sp, dp, 0, 0, 5 << 4, fl, 1000, 0, 0) + data


def _eth(ip):
    return b"\0" * 6 + b"\1" * 6 + b"\x08\x00" + ip


def _pcap(packets, endian="<", magic=0xA1B2C3D4):
    out = struct.pack(endian + "IHHiIII", magic, 2, 4, 0, 0, 65535, 1)
    for i, x in enumerate(packets):
        out += struct.pack(endian + "IIII", 1762000000 + i, 0, len(x), len(x)) + x
    return out


def _pcapng(packets):
    def block(t, body):
        body += b"\0" * (-len(body) % 4)
        return struct.pack("<II", t, len(body) + 12) + body + struct.pack("<I", len(body) + 12)
    out = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    out += block(1, struct.pack("<HHI", 1, 0, 65535))
    for i, x in enumerate(packets):
        ts = (1762000000 + i) * 1_000_000
        out += block(6, struct.pack("<IIIII", 0, ts >> 32, ts & 0xFFFFFFFF, len(x), len(x)) + x)
    return out


class RuleTests(unittest.TestCase):
    def test_telnet_high(self):
        self.assertEqual(assess_port(23, "tcp", "telnet", "open", {}).rule_id, "telnet")

    def test_closed_port_not_flagged(self):
        self.assertIsNone(assess_port(23, "tcp", "telnet", "closed", {}))

    def test_port_fallback_only_when_service_unknown(self):
        self.assertEqual(assess_port(3389, "tcp", "unknown", "open", {}).rule_id, "rdp")
        self.assertIsNone(assess_port(3389, "tcp", "somesvc", "open", {}))

    def test_script_anon_ftp_raises_severity(self):
        r = assess_port(21, "tcp", "ftp", "open", {"ftp-anon": "Anonymous FTP login allowed"})
        self.assertEqual(r.rule_id, "ftp-anon")


class NmapTests(unittest.TestCase):
    def test_parses_hosts_and_risks(self):
        r = parse_nmap_xml(_write(NMAP))
        self.assertEqual(len(r["hosts"]), 1)
        h = r["hosts"][0]
        self.assertEqual(h["open_ports"], 5)
        by = {p["port"]: p for p in h["ports"]}
        self.assertEqual(by[23]["rule_id"], "telnet")
        self.assertEqual(by[21]["rule_id"], "ftp-anon")
        self.assertEqual(by[22]["rule_id"], "ssh")
        self.assertEqual(by[445]["severity"], -1)
        self.assertEqual(by[3389]["rule_id"], "rdp")
        self.assertTrue(any("no valid IP" in w for w in r["warnings"]))

    def test_entity_attack_rejected(self):
        bomb = b'<!DOCTYPE nmaprun [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;">]><nmaprun>&b;</nmaprun>'
        with self.assertRaises(ParseError):
            parse_nmap_xml(_write(bomb))

    def test_external_doctype_rejected(self):
        with self.assertRaises(ParseError):
            parse_nmap_xml(_write(b'<!DOCTYPE nmaprun SYSTEM "http://evil.example/x.dtd"><nmaprun/>'))

    def test_not_nmap(self):
        with self.assertRaises(ParseError):
            parse_nmap_xml(_write(b"<html><body>hi</body></html>"))

    def test_malformed(self):
        with self.assertRaises(ParseError):
            parse_nmap_xml(_write(b"<nmaprun><host>"))

    def test_empty(self):
        with self.assertRaises(ParseError):
            parse_nmap_xml(_write(b""))

    def test_size_limit(self):
        with self.assertRaises(ParseError):
            parse_nmap_xml(_write(NMAP), Limits(max_file_bytes=10))

    def test_host_limit_warns(self):
        hosts = b"".join(b'<host><status state="up"/><address addr="10.0.0.%d" addrtype="ipv4"/></host>' % i for i in range(1, 6))
        r = parse_nmap_xml(_write(b"<nmaprun>" + hosts + b"</nmaprun>"), Limits(max_hosts=2))
        self.assertEqual(len(r["hosts"]), 2)
        self.assertTrue(any("Host limit" in w for w in r["warnings"]))

    def test_depth_limit(self):
        deep = b"<nmaprun>" + b"<a>" * 60 + b"</a>" * 60 + b"</nmaprun>"
        with self.assertRaises(ParseError):
            parse_nmap_xml(_write(deep))

    def test_control_chars_stripped(self):
        x = b'<nmaprun><host><status state="up"/><address addr="10.0.0.1" addrtype="ipv4"/><hostnames><hostname name="a&#8238;b"/></hostnames></host></nmaprun>'
        r = parse_nmap_xml(_write(x))
        self.assertEqual(r["hosts"][0]["hostnames"][0], "ab")


class PcapTests(unittest.TestCase):
    def setUp(self):
        self.pk = [_eth(_ip("10.0.0.5", "10.0.0.9", 6, _tcp(40000, p, 2))) for p in range(1, 31)]
        self.pk.append(_eth(_ip("10.0.0.5", "10.0.0.9", 6, _tcp(40001, 23, 0x18, b"login:"))))
        q = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"
        self.pk.append(_eth(_ip("10.0.0.5", "8.8.8.8", 17, struct.pack("!HHHH", 5000, 53, 8 + len(q), 0) + q)))

    def _check(self, r):
        self.assertEqual(r["summary"]["packets"], 32)
        titles = {f["title"] for f in r["findings"]}
        self.assertIn("Possible port scan", titles)
        self.assertIn("Cleartext Telnet traffic", titles)
        self.assertEqual(r["dns"][0]["name"], "example.com")

    def test_pcap_le(self):
        self._check(analyze_pcap(_write(_pcap(self.pk))))

    def test_pcap_be(self):
        self._check(analyze_pcap(_write(_pcap(self.pk, ">", 0xA1B2C3D4))))

    def test_pcapng(self):
        self._check(analyze_pcap(_write(_pcapng(self.pk))))

    def test_bad_magic(self):
        with self.assertRaises(ParseError):
            analyze_pcap(_write(b"MZ" + b"\0" * 100))

    def test_truncated(self):
        data = _pcap(self.pk)[:-5]
        with self.assertRaises(ParseError):
            analyze_pcap(_write(data))

    def test_huge_record_rejected(self):
        data = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1) + struct.pack("<IIII", 0, 0, 10**8, 10**8)
        with self.assertRaises(ParseError):
            analyze_pcap(_write(data))

    def test_packet_limit_warns(self):
        r = analyze_pcap(_write(_pcap(self.pk)), Limits(max_packets=5))
        self.assertEqual(r["summary"]["packets"], 5)
        self.assertTrue(any("Packet limit" in w for w in r["warnings"]))

    def test_no_packets(self):
        with self.assertRaises(ParseError):
            analyze_pcap(_write(_pcap([])))

    def test_garbage_packets_do_not_crash(self):
        r = analyze_pcap(_write(_pcap([b"\xff" * 7, b"\0" * 20, os.urandom(60)])))
        self.assertEqual(r["summary"]["packets"], 3)

    def test_payload_not_stored(self):
        r = analyze_pcap(_write(_pcap(self.pk)))
        self.assertNotIn("login:", repr(r))

    def test_filter(self):
        r = analyze_pcap(_write(_pcap(self.pk)))
        self.assertEqual(len(filter_flows(r["flows"], port=40001)), 1)
        self.assertEqual(len(filter_flows(r["flows"], proto="udp")), 1)
        self.assertEqual(len(filter_flows(r["flows"], ip="8.8.8.8")), 1)


class DecodeTests(unittest.TestCase):
    def test_dns_compression_pointer_ignored(self):
        self.assertEqual(dns_query_name(b"\0" * 4 + b"\0\1" + b"\0" * 6 + b"\xc0\x0c"), "")

    def test_short_data(self):
        self.assertIsNone(decode_packet(1, b"\0" * 5))


if __name__ == "__main__":
    unittest.main()
