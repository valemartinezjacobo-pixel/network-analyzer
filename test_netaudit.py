#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests de netaudit (stdlib unittest, sin dependencias)."""
import http.server
import socket
import threading
import time
import unittest

import network_analyzer as na


class TestHelpers(unittest.TestCase):
    def test_parse_ports(self):
        self.assertEqual(na.parse_ports("22,80,443"), [22, 80, 443])
        self.assertEqual(na.parse_ports("1-3"), [1, 2, 3])
        self.assertEqual(na.parse_ports(""), na.TOP_PORTS)
        # fuera de rango se descarta
        self.assertNotIn(70000, na.parse_ports("70000"))

    def test_os_from_ttl(self):
        self.assertEqual(na.os_from_ttl(64), "Linux/Unix")
        self.assertEqual(na.os_from_ttl(128), "Windows")
        self.assertEqual(na.os_from_ttl(255), "Red/Router")
        self.assertIsNone(na.os_from_ttl(None))

    def test_oui_lookup(self):
        self.assertEqual(na.oui_lookup("b8:27:eb:11:22:33"), "Raspberry Pi")
        self.assertIsNone(na.oui_lookup("ff:ff:ff:00:00:00"))

    def test_human_secs(self):
        self.assertEqual(na.human_secs(90), "1m 30s")

    def test_guess_subnet(self):
        net = na.guess_subnet("192.168.1.0/24")
        self.assertEqual(str(net), "192.168.1.0/24")


class TestSecurity(unittest.TestCase):
    def test_dangerous_ports_lower_score(self):
        data = {
            "listening": [{"port": 23, "proto": "tcp", "addr": "*", "service": "Telnet"}],
            "lan": [{"ip": "10.0.0.5", "ports": [{"port": 445, "service": "SMB", "tls": None}]}],
            "arp_spoof": [], "public": {},
        }
        sc = na.security_score(data)
        self.assertLess(sc["score"], 100)
        self.assertTrue(any("Telnet" in f["detalle"] for f in sc["findings"]))

    def test_clean_is_100(self):
        sc = na.security_score({"listening": [], "lan": [], "arp_spoof": [], "public": {}})
        self.assertEqual(sc["score"], 100)
        self.assertEqual(sc["grade"], "A")


class TestPortScan(unittest.TestCase):
    def test_scan_detects_open_port(self):
        srv = http.server.HTTPServer(("127.0.0.1", 0), http.server.SimpleHTTPRequestHandler)
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        time.sleep(0.3)
        try:
            res = na.scan_host_ports("127.0.0.1", [port, port + 1], timeout=0.5)
            self.assertTrue(any(p["port"] == port for p in res))
        finally:
            srv.shutdown()


class TestHTML(unittest.TestCase):
    def test_build_html_minimal(self):
        data = {
            "host": na.collect_host(),
            "interfaces": {"lo": {"ipv4": ["127.0.0.1"], "ipv6": [], "mac": None,
                                  "mtu": 65536, "state": "UP", "flags": []}},
            "listening": [], "lan": [], "arp_spoof": [], "public": {},
            "dns_benchmark": [], "connectivity": {}, "ssdp": [], "wifi": {},
        }
        data["security"] = na.security_score(data)
        html = na.build_html(data)
        self.assertTrue(html.startswith("<!DOCTYPE"))
        self.assertTrue(html.strip().endswith("</html>"))
        self.assertIn("netaudit", html)


class TestSniffer(unittest.TestCase):
    @staticmethod
    def _eth(dst, src, etype, payload):
        import struct
        return (bytes.fromhex(dst.replace(":", "")) + bytes.fromhex(src.replace(":", "")) +
                struct.pack("!H", etype) + payload)

    def test_dissect_tcp(self):
        import struct, socket
        import netaudit_sniffer as sn
        tcp = struct.pack("!HHIIBBHHH", 52344, 443, 1000, 0, 0x50, 0x02, 64240, 0, 0)
        iph = (struct.pack("!BBHHHBBH", 0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0) +
               socket.inet_aton("192.168.1.10") + socket.inet_aton("93.184.216.34"))
        fr = self._eth("aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66", 0x0800, iph + tcp)
        p = sn.parse_packet(fr, number=1)
        self.assertEqual(p["proto"], "TCP")
        self.assertEqual(p["dst"], "93.184.216.34")
        self.assertIn("SYN", p["info"])

    def test_dissect_dns_and_arp(self):
        import struct, socket
        import netaudit_sniffer as sn
        dnsq = (struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) +
                bytes([7]) + b"example" + bytes([3]) + b"com" + bytes([0]) + struct.pack("!HH", 1, 1))
        udp = struct.pack("!HHHH", 51000, 53, 8 + len(dnsq), 0) + dnsq
        iph = (struct.pack("!BBHHHBBH", 0x45, 0, 20 + len(udp), 2, 0, 64, 17, 0) +
               socket.inet_aton("192.168.1.10") + socket.inet_aton("1.1.1.1"))
        fr = self._eth("aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66", 0x0800, iph + udp)
        p = sn.parse_packet(fr, number=2)
        self.assertIn("example.com", p["info"])
        arp = (struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1) + bytes.fromhex("112233445566") +
               socket.inet_aton("192.168.1.5") + bytes(6) + socket.inet_aton("192.168.1.1"))
        fr2 = self._eth("ff:ff:ff:ff:ff:ff", "11:22:33:44:55:66", 0x0806, arp)
        p2 = sn.parse_packet(fr2, number=3)
        self.assertEqual(p2["proto"], "ARP")
        self.assertIn("Who has 192.168.1.1", p2["info"])

    def test_pcap_roundtrip(self):
        import struct, socket, tempfile, os
        import netaudit_sniffer as sn
        tcp = struct.pack("!HHIIBBHHH", 1, 80, 0, 0, 0x50, 0x02, 0, 0, 0)
        iph = (struct.pack("!BBHHHBBH", 0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0) +
               socket.inet_aton("10.0.0.1") + socket.inet_aton("10.0.0.2"))
        fr = self._eth("aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66", 0x0800, iph + tcp)
        p = sn.parse_packet(fr, number=1); p["raw"] = fr
        tf = tempfile.mktemp(suffix=".pcap")
        sn.write_pcap(tf, [p])
        rd = sn.read_pcap(tf)
        os.unlink(tf)
        self.assertEqual(len(rd), 1)
        self.assertEqual(rd[0]["proto"], "TCP")

    def test_capture_html(self):
        import netaudit_sniffer as sn
        html = sn.build_capture_html([{"no": 1, "time": 1.5, "src": "a", "dst": "b",
                                       "proto": "TCP", "length": 60, "info": "x", "hex": "00"}])
        self.assertTrue(html.startswith("<!DOCTYPE"))


class TestScannerExtras(unittest.TestCase):
    def test_wol_magic_packet(self):
        import re
        clean = re.sub(r"[^0-9a-fA-F]", "", "aa:bb:cc:dd:ee:ff")
        magic = bytes.fromhex("FF" * 6 + clean * 16)
        self.assertEqual(len(magic), 102)
        self.assertEqual(magic[:6], b"\xff" * 6)

    def test_host_actions(self):
        h = {"ip": "192.168.1.5", "mac": "aa:bb:cc:dd:ee:ff",
             "ports": [{"port": 80, "service": "HTTP"}, {"port": 3389, "service": "RDP"}]}
        names = [a[0] for a in na.host_actions(h)]
        self.assertTrue(any("HTTP" in n for n in names))
        self.assertTrue(any("Wake" in n for n in names))


if __name__ == "__main__":
    unittest.main(verbosity=2)
