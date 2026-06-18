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


if __name__ == "__main__":
    unittest.main(verbosity=2)
