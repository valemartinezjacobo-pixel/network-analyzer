#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
 NETWORK ANALYZER  ·  netaudit v2.0  ·  Auditoría técnica de red multiplataforma
================================================================================
Recolecta el máximo de parámetros de la red local y de Internet, audita la IP
pública, descubre y escanea hosts de la LAN (puertos, banners, fingerprint),
inspecciona certificados TLS, descubre dispositivos UPnP/SSDP, lee el Wi-Fi,
hace benchmark de DNS y un test de velocidad, calcula un SCORE de seguridad
con recomendaciones, y genera un dashboard HTML interactivo con gráficas.

Sólo librería estándar de Python (no requiere pip install). Linux/macOS/Windows.
Con sudo/admin el descubrimiento ARP y algunos detalles son más completos.

USO BÁSICO:
    python3 network_analyzer.py                 # análisis completo + HTML
    python3 network_analyzer.py --fast          # rápido (menos pruebas)
    python3 network_analyzer.py --no-lan        # sin escaneo de LAN
    python3 network_analyzer.py --no-public     # sin consultas a Internet

OPCIONES ÚTILES:
    -o salida.html        nombre del HTML
    --json datos.json     vuelca JSON crudo
    --csv hosts.csv       exporta hosts de la LAN a CSV
    --target HOST         analiza/escanea un host o red concretos
    --subnet 10.0.0.0/24  red a escanear (por defecto se autodetecta /24)
    --ports 1-1024        rango/lista de puertos para el escaneo remoto
    --timeout 0.5         timeout por conexión (segundos)
    --no-portscan         no escanear puertos de los hosts de la LAN
    --no-speedtest        no medir velocidad
    --online-oui          resolver fabricantes desconocidos por Internet
    --compare a.json b.json   compara dos reportes JSON (diff) y sale
    --version             muestra la versión
    --no-color            desactiva el color en la terminal

AVISO LEGAL: úsalo SÓLO en redes propias o con permiso explícito. El escaneo de
redes ajenas puede ser ilegal en tu jurisdicción.
================================================================================
"""

__version__ = "2.2.1"

import argparse
import concurrent.futures
import datetime
import ipaddress
import json
import os
import platform
import re
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import time
import urllib.request
import uuid

IS_WIN = platform.system().lower().startswith("win")
IS_MAC = platform.system().lower() == "darwin"
IS_LINUX = platform.system().lower() == "linux"

# Sniffer (mini-Wireshark) y export PDF. Import explícito para PyInstaller.
try:
    import netaudit_sniffer
except Exception:
    netaudit_sniffer = None
try:
    import netaudit_pdf
except Exception:
    netaudit_pdf = None

# Salida UTF-8 robusta: evita UnicodeEncodeError en consolas Windows (cp1252).
for _stream in ("stdout", "stderr"):
    try:
        getattr(sys, _stream).reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# --------------------------------------------------------------------------- #
# Color / salida                                                              #
# --------------------------------------------------------------------------- #

class C:
    enabled = sys.stdout.isatty() and not IS_WIN
    @classmethod
    def w(cls, s, code):
        return f"\033[{code}m{s}\033[0m" if cls.enabled else s
    @classmethod
    def g(cls, s): return cls.w(s, "32")
    @classmethod
    def r(cls, s): return cls.w(s, "31")
    @classmethod
    def y(cls, s): return cls.w(s, "33")
    @classmethod
    def b(cls, s): return cls.w(s, "36")
    @classmethod
    def dim(cls, s): return cls.w(s, "90")
    @classmethod
    def bold(cls, s): return cls.w(s, "1")

def section(title):
    print("\n" + C.b("=" * 70))
    print(" " + C.bold(title))
    print(C.b("=" * 70))

# --------------------------------------------------------------------------- #
# Utilidades                                                                  #
# --------------------------------------------------------------------------- #

def run(cmd, timeout=8):
    try:
        out = subprocess.run(
            cmd, shell=isinstance(cmd, str),
            capture_output=True, text=True, timeout=timeout, errors="replace",
        )
        return (out.stdout or "") + (("\n" + out.stderr) if out.stderr else "")
    except Exception:
        return ""

def have(binname):
    return shutil.which(binname) is not None

def http_json(url, timeout=6, headers=None):
    try:
        h = {"User-Agent": "netaudit/2.0"}
        if headers:
            h.update(headers)
        req = urllib.request.Request(url, headers=h)
        ctx = ssl.create_default_context()
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return json.loads(r.read().decode("utf-8", "replace"))
    except Exception:
        return None

def http_text(url, timeout=6):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "netaudit/2.0"})
        ctx = ssl.create_default_context()
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.read().decode("utf-8", "replace").strip()
    except Exception:
        return None

def human_secs(s):
    s = int(s)
    d, s = divmod(s, 86400); h, s = divmod(s, 3600); m, s = divmod(s, 60)
    parts = []
    if d: parts.append(f"{d}d")
    if h: parts.append(f"{h}h")
    if m: parts.append(f"{m}m")
    parts.append(f"{s}s")
    return " ".join(parts)

# --------------------------------------------------------------------------- #
# 1. Host / sistema                                                           #
# --------------------------------------------------------------------------- #

def collect_host():
    info = {}
    info["hostname"] = socket.gethostname()
    try:
        info["fqdn"] = socket.getfqdn()
    except Exception:
        info["fqdn"] = info["hostname"]
    info["os"] = platform.system()
    info["os_release"] = platform.release()
    info["os_version"] = platform.version()
    info["arch"] = platform.machine()
    info["processor"] = platform.processor() or platform.machine()
    info["python"] = platform.python_version()
    info["user"] = os.environ.get("USER") or os.environ.get("USERNAME") or "?"
    info["netaudit"] = __version__
    try:
        if IS_LINUX and os.path.exists("/proc/uptime"):
            with open("/proc/uptime") as f:
                info["uptime"] = human_secs(float(f.read().split()[0]))
        elif IS_MAC:
            out = run(["sysctl", "-n", "kern.boottime"])
            m = re.search(r"sec\s*=\s*(\d+)", out)
            if m:
                info["uptime"] = human_secs(time.time() - int(m.group(1)))
        elif IS_WIN:
            out = run("net statistics workstation")
            m = re.search(r"since\s+(.+)", out)
            if m:
                info["uptime"] = "desde " + m.group(1).strip()
    except Exception:
        pass
    info["timestamp"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return info

# --------------------------------------------------------------------------- #
# 2. Interfaces                                                               #
# --------------------------------------------------------------------------- #

def primary_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80)); ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip

def mac_self():
    try:
        n = uuid.getnode()
        return ":".join(f"{(n >> i) & 0xff:02x}" for i in range(40, -8, -8))
    except Exception:
        return None

def collect_interfaces():
    ifaces = {}
    def ensure(name):
        ifaces.setdefault(name, {"ipv4": [], "ipv6": [], "mac": None,
                                 "mtu": None, "state": None, "flags": []})
        return ifaces[name]
    if IS_LINUX and have("ip"):
        for line in run(["ip", "-o", "addr"]).splitlines():
            parts = line.split()
            if len(parts) < 4:
                continue
            d = ensure(parts[1])
            if parts[2] == "inet": d["ipv4"].append(parts[3])
            elif parts[2] == "inet6": d["ipv6"].append(parts[3])
        for line in run(["ip", "-o", "link"]).splitlines():
            m = re.match(r"\d+:\s+([^:@]+)[:@]", line)
            if not m: continue
            d = ensure(m.group(1).strip())
            mtu = re.search(r"mtu (\d+)", line)
            if mtu: d["mtu"] = int(mtu.group(1))
            mac = re.search(r"link/\w+\s+([0-9a-f:]{17})", line)
            if mac: d["mac"] = mac.group(1)
            st = re.search(r"state (\w+)", line)
            if st: d["state"] = st.group(1)
            fl = re.search(r"<([^>]+)>", line)
            if fl: d["flags"] = fl.group(1).split(",")
    elif (IS_MAC or IS_LINUX) and have("ifconfig"):
        cur = None
        for line in run(["ifconfig"]).splitlines():
            if line and not line[0].isspace():
                cur = line.split(":")[0].split()[0]; d = ensure(cur)
                fl = re.search(r"<([^>]+)>", line)
                if fl: d["flags"] = fl.group(1).split(",")
                mtu = re.search(r"mtu (\d+)", line)
                if mtu: d["mtu"] = int(mtu.group(1))
            elif cur:
                d = ensure(cur)
                m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)(?:\s+netmask\s+(\S+))?", line)
                if m: d["ipv4"].append(m.group(1) + (f"  netmask {m.group(2)}" if m.group(2) else ""))
                m6 = re.search(r"inet6 ([0-9a-f:]+)", line)
                if m6: d["ipv6"].append(m6.group(1))
                mac = re.search(r"ether ([0-9a-f:]{17})", line)
                if mac: d["mac"] = mac.group(1)
                if "status:" in line: d["state"] = line.split("status:")[1].strip()
    elif IS_WIN:
        cur = None
        for line in run("ipconfig /all", timeout=12).splitlines():
            if line and not line[0].isspace() and "adapter" in line.lower():
                cur = line.split("adapter", 1)[-1].strip().rstrip(":"); ensure(cur)
            elif cur:
                d = ensure(cur)
                if "Physical Address" in line or "física" in line:
                    mac = re.search(r"([0-9A-Fa-f]{2}[-:]){5}[0-9A-Fa-f]{2}", line)
                    if mac: d["mac"] = mac.group(0).replace("-", ":").lower()
                elif "IPv4" in line:
                    ip = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
                    if ip: d["ipv4"].append(ip.group(1))
                elif "IPv6" in line and "::" in line:
                    ip = re.search(r"([0-9A-Fa-f:]+::[0-9A-Fa-f:]+)", line)
                    if ip: d["ipv6"].append(ip.group(1))
    if not ifaces:
        ensure("primary")["ipv4"].append(primary_ip())
        ifaces["primary"]["mac"] = mac_self()
    return ifaces

# --------------------------------------------------------------------------- #
# 3. Gateway / rutas / DNS / ARP (+ detección de spoofing)                    #
# --------------------------------------------------------------------------- #

def collect_gateway():
    gw = {"default": None, "raw": ""}
    if IS_LINUX and have("ip"):
        out = run(["ip", "route"]); gw["raw"] = out
        m = re.search(r"default via (\S+)", out)
        if m: gw["default"] = m.group(1)
    elif IS_MAC:
        out = run(["route", "-n", "get", "default"]); gw["raw"] = out
        m = re.search(r"gateway:\s+(\S+)", out)
        if m: gw["default"] = m.group(1)
    elif IS_WIN:
        out = run("route print 0.0.0.0"); gw["raw"] = out
        m = re.search(r"0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)", out)
        if m: gw["default"] = m.group(1)
    else:
        out = run(["netstat", "-rn"]); gw["raw"] = out
    return gw

def collect_routes():
    if IS_WIN: return run("route print")
    if have("ip"): return run(["ip", "route"])
    return run(["netstat", "-rn"])

def collect_dns():
    servers, raw = [], ""
    if IS_WIN:
        raw = run("ipconfig /all", timeout=12)
        for m in re.finditer(r"DNS Servers[^:]*:\s*(\d+\.\d+\.\d+\.\d+)", raw):
            servers.append(m.group(1))
    else:
        if os.path.exists("/etc/resolv.conf"):
            raw = open("/etc/resolv.conf").read()
            for m in re.finditer(r"nameserver\s+(\S+)", raw):
                servers.append(m.group(1))
        if IS_MAC and have("scutil"):
            extra = run("scutil --dns")
            for m in re.finditer(r"nameserver\[\d+\]\s*:\s*(\S+)", extra):
                if m.group(1) not in servers: servers.append(m.group(1))
            raw += "\n" + extra
    return {"servers": list(dict.fromkeys(servers)), "raw": raw.strip()}

def collect_arp():
    out = run("arp -a", timeout=8) or run(["ip", "neigh"])
    entries, seen = [], set()
    for line in out.splitlines():
        ip = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
        mac = re.search(r"([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}", line)
        if ip and mac and ip.group(1) not in seen:
            seen.add(ip.group(1))
            entries.append({"ip": ip.group(1),
                            "mac": mac.group(0).replace("-", ":").lower(),
                            "vendor": oui_lookup(mac.group(0))})
    return entries

def detect_arp_spoof(arp, gateway):
    """Marca MACs que aparecen en varias IPs (posible spoofing/NAT raro)."""
    by_mac = {}
    for e in arp:
        by_mac.setdefault(e["mac"], []).append(e["ip"])
    findings = []
    for mac, ips in by_mac.items():
        if len(ips) > 1:
            findings.append({"mac": mac, "ips": ips})
    return findings

# --------------------------------------------------------------------------- #
# OUI (fabricantes) - tabla ampliada + lookup online opcional                 #
# --------------------------------------------------------------------------- #

OUI = {
    "00:00:0c": "Cisco", "00:1b:63": "Apple", "00:1e:c2": "Apple",
    "00:25:00": "Apple", "3c:07:54": "Apple", "a4:5e:60": "Apple",
    "f0:18:98": "Apple", "ac:bc:32": "Apple", "dc:a9:04": "Apple",
    "00:50:56": "VMware", "00:0c:29": "VMware", "00:05:69": "VMware",
    "08:00:27": "VirtualBox", "52:54:00": "QEMU/KVM", "00:16:3e": "Xen",
    "b8:27:eb": "Raspberry Pi", "dc:a6:32": "Raspberry Pi",
    "e4:5f:01": "Raspberry Pi", "28:cd:c1": "Raspberry Pi",
    "00:1d:0f": "TP-Link", "ec:08:6b": "TP-Link", "90:9a:4a": "TP-Link",
    "50:c7:bf": "TP-Link", "a4:2b:b0": "TP-Link", "00:09:0f": "Fortinet",
    "00:1a:11": "Google", "f4:f5:e8": "Google", "3c:5a:b4": "Google",
    "a4:77:33": "Google", "d8:6c:63": "Google", "f8:8f:ca": "Google",
    "00:18:0a": "Cisco-Meraki", "00:0c:42": "MikroTik", "48:8f:5a": "MikroTik",
    "dc:2c:6e": "MikroTik", "64:d1:54": "MikroTik", "2c:c8:1b": "Routerboard",
    "00:24:b2": "Netgear", "a0:40:a0": "Netgear", "9c:3d:cf": "Netgear",
    "00:1f:33": "Netgear", "c0:3f:0e": "Netgear", "44:94:fc": "Netgear",
    "00:26:5a": "D-Link", "1c:bd:b9": "D-Link", "78:54:2e": "D-Link",
    "00:1c:df": "Belkin", "94:10:3e": "Belkin", "00:22:75": "Belkin",
    "fc:ec:da": "Ubiquiti", "24:a4:3c": "Ubiquiti", "78:8a:20": "Ubiquiti",
    "04:18:d6": "Ubiquiti", "68:d7:9a": "Ubiquiti", "e0:63:da": "Ubiquiti",
    "00:17:88": "Philips Hue", "ec:b5:fa": "Philips", "00:0b:82": "Grandstream",
    "b0:4e:26": "TP-Link", "00:1a:79": "Tonze", "18:fe:34": "Espressif/ESP",
    "24:0a:c4": "Espressif/ESP", "5c:cf:7f": "Espressif/ESP",
    "30:ae:a4": "Espressif/ESP", "84:f3:eb": "Espressif/ESP",
    "ac:de:48": "Private", "00:50:c2": "IEEE-Registration",
    "00:1a:2b": "Ayecom", "00:0f:b5": "Netgear", "c8:3a:35": "Tenda",
    "04:d4:c4": "Asus", "ac:9e:17": "Asus", "2c:fd:a1": "Asus",
    "08:60:6e": "Asus", "38:d5:47": "Asus", "1c:b7:2c": "Asus",
    "00:1d:7e": "Cisco-Linksys", "00:25:9c": "Cisco-Linksys",
    "58:ef:68": "Belkin/Wemo", "14:91:82": "Belkin/Wemo",
    "d0:52:a8": "SmartThings", "00:24:e4": "Withings", "00:04:20": "Slim Devices",
    "b8:27:eb ": "Raspberry Pi", "00:11:32": "Synology", "00:90:a9": "Western Digital",
    "00:1c:c4": "HP", "3c:d9:2b": "HP", "70:5a:0f": "HP", "a0:b3:cc": "HP",
    "00:21:5a": "HP", "ec:9a:74": "HP", "00:26:55": "HP",
    "00:80:77": "Brother", "00:1b:a9": "Brother", "30:05:5c": "Brother",
    "00:00:48": "Epson", "00:26:ab": "Epson", "a4:ee:57": "Epson",
    "9c:b6:54": "Canon", "00:1e:8f": "Canon", "2c:9e:fc": "Canon",
    "00:17:c8": "Kyocera", "00:21:b7": "Lexmark", "e0:91:f5": "Samsung",
    "5c:0a:5b": "Samsung", "78:bd:bc": "Samsung", "8c:77:12": "Samsung",
    "f0:25:b7": "Samsung", "1c:62:b8": "Samsung", "00:12:fb": "Samsung",
    "00:1d:25": "Samsung", "bc:54:51": "Xiaomi", "64:09:80": "Xiaomi",
    "28:6c:07": "Xiaomi", "f8:a4:5f": "Xiaomi", "78:11:dc": "Xiaomi",
    "50:8f:4c": "Xiaomi", "00:9e:c8": "Xiaomi", "34:ce:00": "Xiaomi",
    "00:1e:42": "Teltonika", "20:34:fb": "Xiaomi", "fc:64:ba": "Xiaomi",
    "00:1a:8c": "HID", "00:80:92": "Silex", "00:04:f2": "Polycom",
    "00:1d:a5": "Winbond", "00:14:22": "Dell", "18:db:f2": "Dell",
    "f8:bc:12": "Dell", "00:26:b9": "Dell", "d4:be:d9": "Dell",
    "f0:1f:af": "Dell", "00:21:9b": "Dell", "00:18:8b": "Dell",
    "b0:83:fe": "Dell", "00:c0:4f": "Dell", "44:a8:42": "Dell",
    "00:23:ae": "Dell", "00:13:72": "Dell", "00:50:ba": "D-Link",
    "fc:fb:fb": "Cisco", "00:1e:c9": "Dell", "00:21:70": "Dell",
}

_OUI_ONLINE_CACHE = {}

def oui_lookup(mac, online=False):
    pref = mac.lower().replace("-", ":")[:8]
    v = OUI.get(pref)
    if v:
        return v
    if online:
        if pref in _OUI_ONLINE_CACHE:
            return _OUI_ONLINE_CACHE[pref]
        name = http_text(f"https://api.macvendors.com/{mac}", timeout=3)
        if name and "errors" not in name and len(name) < 60:
            _OUI_ONLINE_CACHE[pref] = name
            return name
        _OUI_ONLINE_CACHE[pref] = None
    return None

# --------------------------------------------------------------------------- #
# 4. Puertos en escucha (local)                                              #
# --------------------------------------------------------------------------- #

WELL_KNOWN = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP", 80: "HTTP", 110: "POP3",
    111: "RPC", 123: "NTP", 135: "MS-RPC", 137: "NetBIOS", 138: "NetBIOS",
    139: "NetBIOS", 143: "IMAP", 161: "SNMP", 162: "SNMP", 389: "LDAP",
    443: "HTTPS", 445: "SMB", 465: "SMTPS", 514: "Syslog", 515: "LPD",
    587: "SMTP-sub", 631: "IPP/CUPS", 636: "LDAPS", 873: "rsync", 993: "IMAPS",
    995: "POP3S", 1080: "SOCKS", 1194: "OpenVPN", 1433: "MSSQL", 1521: "Oracle",
    1723: "PPTP", 1883: "MQTT", 1900: "SSDP/UPnP", 2049: "NFS", 2375: "Docker",
    2376: "Docker-TLS", 3000: "Dev/Grafana", 3306: "MySQL", 3389: "RDP",
    3478: "STUN", 5000: "UPnP/Dev", 5060: "SIP", 5353: "mDNS", 5432: "PostgreSQL",
    5555: "ADB", 5900: "VNC", 5984: "CouchDB", 6379: "Redis", 6443: "Kubernetes",
    7547: "TR-069", 8000: "HTTP-alt", 8080: "HTTP-proxy", 8443: "HTTPS-alt",
    8888: "HTTP-alt", 9000: "Dev", 9090: "Prometheus", 9200: "Elasticsearch",
    11211: "Memcached", 27017: "MongoDB", 32400: "Plex", 51820: "WireGuard",
}

def collect_listening():
    if have("ss"): out = run(["ss", "-tulnp"], timeout=8)
    elif IS_WIN: out = run("netstat -ano", timeout=10)
    else: out = run(["netstat", "-an"], timeout=10)
    ports, seen = [], set()
    for line in out.splitlines():
        up = line.upper()
        if "LISTEN" not in up and "udp" not in line.lower() and "LISTENING" not in up:
            continue
        proto = "tcp" if "tcp" in line.lower() else ("udp" if "udp" in line.lower() else "?")
        m = re.search(r"[\d\.\*]+[:\.](\d+)\s", line)
        addr = re.search(r"((?:\d+\.\d+\.\d+\.\d+|\[?::\]?|\*|0\.0\.0\.0)[:\.]\d+)", line)
        if m:
            port = int(m.group(1)); k = (proto, port, addr.group(1) if addr else "?")
            if k in seen: continue
            seen.add(k)
            ports.append({"proto": proto, "port": port,
                          "addr": addr.group(1) if addr else "?",
                          "service": WELL_KNOWN.get(port, "")})
    ports.sort(key=lambda x: (x["proto"], x["port"]))
    return ports

# --------------------------------------------------------------------------- #
# 5. IP pública / geo / ASN / blacklists (+ Shodan/AbuseIPDB si hay API key)  #
# --------------------------------------------------------------------------- #

DNSBLS = ["zen.spamhaus.org", "bl.spamcop.net", "b.barracudacentral.org",
          "dnsbl.sorbs.net", "cbl.abuseat.org"]

def check_blacklists(ip):
    results = []
    try:
        rev = ".".join(reversed(ip.split(".")))
    except Exception:
        return results
    for bl in DNSBLS:
        try:
            socket.setdefaulttimeout(3)
            socket.gethostbyname(f"{rev}.{bl}")
            results.append({"lista": bl, "estado": "LISTADO ⚠"})
        except socket.gaierror:
            results.append({"lista": bl, "estado": "limpio"})
        except Exception:
            results.append({"lista": bl, "estado": "sin respuesta"})
    socket.setdefaulttimeout(None)
    return results

def collect_public(fast=False):
    pub = {"ip": None, "geo": {}, "rdns": None, "blacklists": [],
           "shodan": None, "abuseipdb": None}
    pub["ip"] = (http_text("https://api.ipify.org") or
                 http_text("https://ifconfig.me/ip") or
                 http_text("https://icanhazip.com"))
    if not pub["ip"]:
        return pub
    data = http_json(f"http://ip-api.com/json/{pub['ip']}?fields=66846719")
    if data and data.get("status") == "success":
        pub["geo"] = {
            "país": data.get("country"), "código": data.get("countryCode"),
            "región": data.get("regionName"), "ciudad": data.get("city"),
            "código_postal": data.get("zip"), "lat": data.get("lat"),
            "lon": data.get("lon"), "zona_horaria": data.get("timezone"),
            "isp": data.get("isp"), "organización": data.get("org"),
            "asn": data.get("as"), "asname": data.get("asname"),
            "reverse": data.get("reverse"), "móvil": data.get("mobile"),
            "proxy": data.get("proxy"), "hosting": data.get("hosting"),
        }
    try:
        pub["rdns"] = socket.gethostbyaddr(pub["ip"])[0]
    except Exception:
        pub["rdns"] = None
    if not fast:
        pub["blacklists"] = check_blacklists(pub["ip"])
    # Integraciones opcionales con API key (variables de entorno)
    sk = os.environ.get("SHODAN_API_KEY")
    if sk:
        d = http_json(f"https://api.shodan.io/shodan/host/{pub['ip']}?key={sk}", timeout=8)
        if d:
            pub["shodan"] = {"puertos": d.get("ports"), "tags": d.get("tags"),
                             "vulns": list(d.get("vulns", []))[:10]}
    ak = os.environ.get("ABUSEIPDB_API_KEY")
    if ak:
        d = http_json(f"https://api.abuseipdb.com/api/v2/check?ipAddress={pub['ip']}",
                      timeout=8, headers={"Key": ak, "Accept": "application/json"})
        if d and "data" in d:
            pub["abuseipdb"] = {"score": d["data"].get("abuseConfidenceScore"),
                                "reports": d["data"].get("totalReports")}
    return pub

# --------------------------------------------------------------------------- #
# 6. Escaneo de la LAN (ping sweep + TTL fingerprint)                         #
# --------------------------------------------------------------------------- #

def guess_subnet(target=None):
    if target:
        try:
            if "/" in target:
                return ipaddress.ip_network(target, strict=False)
            return ipaddress.ip_network(target + "/24", strict=False)
        except Exception:
            pass
    try:
        return ipaddress.ip_network(primary_ip() + "/24", strict=False)
    except Exception:
        return None

def os_from_ttl(ttl):
    if ttl is None: return None
    if ttl <= 64: return "Linux/Unix"
    if ttl <= 128: return "Windows"
    return "Red/Router"

def ping_host(ip, timeout=1):
    if IS_WIN:
        cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(int(timeout)), ip]
    out = run(cmd, timeout=timeout + 2)
    if not out:
        return None
    low = out.lower()
    alive = ("ttl=" in low) or ("bytes from" in low) or ("reply from" in low and "unreachable" not in low)
    if not alive:
        return None
    rtt = re.search(r"time[=<]\s*([\d\.]+)\s*ms", out)
    ttl = re.search(r"ttl[=\s]*(\d+)", low)
    return {"ip": ip, "rtt_ms": float(rtt.group(1)) if rtt else None,
            "ttl": int(ttl.group(1)) if ttl else None}

def collect_lan(net, arp, fast=False, online_oui=False, workers=128, progress=True):
    if net is None:
        return []
    hosts = [str(h) for h in net.hosts()]
    if fast:
        hosts = hosts[:64]
    alive, arp_map = [], {e["ip"]: e for e in arp}
    done = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(ping_host, h): h for h in hosts}
        for f in concurrent.futures.as_completed(futs):
            done += 1
            if progress and done % 16 == 0:
                pct = int(done / len(hosts) * 100)
                print(f"\r   sweep {pct:3d}%  ({done}/{len(hosts)})", end="", flush=True)
            r = f.result()
            if not r:
                continue
            ip = r["ip"]
            try: hostname = socket.gethostbyaddr(ip)[0]
            except Exception: hostname = None
            a = arp_map.get(ip, {})
            alive.append({"ip": ip, "rtt_ms": r["rtt_ms"], "ttl": r["ttl"],
                          "os_guess": os_from_ttl(r["ttl"]), "hostname": hostname,
                          "mac": a.get("mac"),
                          "vendor": a.get("vendor") or (oui_lookup(a["mac"], online_oui) if a.get("mac") else None),
                          "ports": []})
    if progress:
        print("\r" + " " * 40 + "\r", end="")
    found = {h["ip"] for h in alive}
    for e in arp:
        try: in_net = ipaddress.ip_address(e["ip"]) in net
        except Exception: in_net = False
        if e["ip"] not in found and in_net:
            alive.append({"ip": e["ip"], "rtt_ms": None, "ttl": None, "os_guess": None,
                          "hostname": None, "mac": e["mac"], "vendor": e["vendor"], "ports": []})
    alive.sort(key=lambda x: tuple(int(p) for p in x["ip"].split(".")))
    return alive

# --------------------------------------------------------------------------- #
# 7. Escaneo de puertos remoto + banner + servicio + TLS                      #
# --------------------------------------------------------------------------- #

TOP_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 389, 443,
             445, 465, 587, 631, 993, 995, 1080, 1433, 1521, 1723, 1883, 1900,
             2049, 2375, 3000, 3306, 3389, 5000, 5060, 5353, 5432, 5900, 5984,
             6379, 8000, 8080, 8443, 8888, 9000, 9090, 9200, 11211, 27017, 32400]

def parse_ports(spec):
    if not spec:
        return TOP_PORTS
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            a, b = part.split("-", 1)
            try: ports.update(range(int(a), int(b) + 1))
            except Exception: pass
        elif part.isdigit():
            ports.add(int(part))
    return sorted(p for p in ports if 0 < p < 65536)

def grab_banner(ip, port, timeout=1.0):
    try:
        s = socket.create_connection((ip, port), timeout=timeout)
        s.settimeout(timeout)
        try:
            if port in (80, 8080, 8000, 8888, 9000):
                s.sendall(b"HEAD / HTTP/1.0\r\nHost: %b\r\n\r\n" % ip.encode())
            data = s.recv(256)
        except Exception:
            data = b""
        s.close()
        if data:
            txt = data.decode("latin-1", "replace").strip()
            txt = re.sub(r"\s+", " ", txt)
            return txt[:120]
    except Exception:
        pass
    return None

def tls_cert(ip, port, host=None, timeout=2.5):
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host or ip) as ss:
                der = ss.getpeercert(True)
                cipher = ss.cipher()
        pem = ssl.DER_cert_to_PEM_cert(der)
        info = {}
        try:
            tf = tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False)
            tf.write(pem); tf.close()
            decoded = ssl._ssl._test_decode_cert(tf.name)
            os.unlink(tf.name)
            subj = dict(x[0] for x in decoded.get("subject", []))
            iss = dict(x[0] for x in decoded.get("issuer", []))
            info["cn"] = subj.get("commonName")
            info["issuer"] = iss.get("commonName") or iss.get("organizationName")
            info["expira"] = decoded.get("notAfter")
            try:
                exp = ssl.cert_time_to_seconds(decoded["notAfter"])
                info["dias_restantes"] = int((exp - time.time()) / 86400)
            except Exception:
                info["dias_restantes"] = None
        except Exception:
            pass
        info["cipher"] = cipher[0] if cipher else None
        info["tls"] = cipher[1] if cipher else None
        return info
    except Exception:
        return None

def scan_host_ports(ip, ports, timeout=0.6, hostname=None):
    open_ports = []
    def check(port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) == 0:
                s.close()
                return port
            s.close()
        except Exception:
            pass
        return None
    with concurrent.futures.ThreadPoolExecutor(max_workers=64) as ex:
        for port in [p for p in ex.map(check, ports) if p]:
            entry = {"port": port, "service": WELL_KNOWN.get(port, ""),
                     "banner": grab_banner(ip, port, timeout), "tls": None}
            if port in (443, 8443, 993, 995, 465, 990):
                entry["tls"] = tls_cert(ip, port, hostname)
            open_ports.append(entry)
    open_ports.sort(key=lambda x: x["port"])
    return open_ports

def portscan_lan(hosts, ports, timeout=0.6, fast=False, progress=True):
    targets = [h for h in hosts if h.get("rtt_ms") is not None or h.get("mac")]
    if fast:
        targets = targets[:20]
    total = len(targets)
    for i, h in enumerate(targets, 1):
        if progress:
            print(f"\r   portscan {i}/{total}  {h['ip']:<16}", end="", flush=True)
        h["ports"] = scan_host_ports(h["ip"], ports, timeout, h.get("hostname"))
    if progress and total:
        print("\r" + " " * 50 + "\r", end="")
    return hosts

# --------------------------------------------------------------------------- #
# 8. SSDP / UPnP discovery                                                    #
# --------------------------------------------------------------------------- #

def collect_ssdp(timeout=3):
    msg = ("M-SEARCH * HTTP/1.1\r\n"
           "HOST:239.255.255.250:1900\r\n"
           'MAN:"ssdp:discover"\r\n'
           "MX:2\r\nST:ssdp:all\r\n\r\n").encode()
    devices, seen = [], set()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.settimeout(timeout)
        s.sendto(msg, ("239.255.255.250", 1900))
        t0 = time.time()
        while time.time() - t0 < timeout:
            try:
                data, addr = s.recvfrom(2048)
            except socket.timeout:
                break
            except Exception:
                break
            txt = data.decode("latin-1", "replace")
            srv = re.search(r"SERVER:\s*(.+)", txt, re.I)
            loc = re.search(r"LOCATION:\s*(.+)", txt, re.I)
            st = re.search(r"ST:\s*(.+)", txt, re.I)
            key = (addr[0], srv.group(1).strip() if srv else "")
            if key in seen:
                continue
            seen.add(key)
            devices.append({"ip": addr[0],
                            "server": srv.group(1).strip() if srv else None,
                            "location": loc.group(1).strip() if loc else None,
                            "st": st.group(1).strip() if st else None})
        s.close()
    except Exception:
        pass
    return devices

# --------------------------------------------------------------------------- #
# 9. Wi-Fi                                                                    #
# --------------------------------------------------------------------------- #

def collect_wifi():
    info = {}
    try:
        if IS_MAC:
            out = run(["/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport", "-I"])
            if "AirPort: Off" not in out and out.strip():
                for key, label in [("SSID", "ssid"), ("agrCtlRSSI", "rssi"),
                                   ("channel", "channel"), ("lastTxRate", "tx_rate")]:
                    m = re.search(rf"\b{key}:\s*(.+)", out)
                    if m: info[label] = m.group(1).strip()
            if not info:
                sp = run(["system_profiler", "SPAirPortDataType"], timeout=12)
                m = re.search(r"Current Network Information:\s*\n\s*(.+?):", sp)
                if m: info["ssid"] = m.group(1).strip()
        elif IS_LINUX:
            if have("nmcli"):
                out = run(["nmcli", "-t", "-f", "active,ssid,signal,chan", "dev", "wifi"])
                for line in out.splitlines():
                    if line.startswith("yes:") or line.startswith("sí:"):
                        p = line.split(":")
                        if len(p) >= 4:
                            info = {"ssid": p[1], "signal": p[2] + "%", "channel": p[3]}
                            break
            elif have("iwconfig"):
                out = run(["iwconfig"])
                m = re.search(r'ESSID:"([^"]+)"', out)
                if m: info["ssid"] = m.group(1)
                q = re.search(r"Signal level=(-?\d+)", out)
                if q: info["rssi"] = q.group(1) + " dBm"
        elif IS_WIN:
            out = run("netsh wlan show interfaces", timeout=8)
            for key, label in [("SSID", "ssid"), ("Signal", "signal"),
                               ("Channel", "channel"), ("Radio type", "radio")]:
                m = re.search(rf"^\s*{key}\s*:\s*(.+)$", out, re.M)
                if m and label not in info:
                    info[label] = m.group(1).strip()
    except Exception:
        pass
    return info

# --------------------------------------------------------------------------- #
# 10. Benchmark DNS (consulta a resolvers concretos)                          #
# --------------------------------------------------------------------------- #

def dns_query_time(server, domain="cloudflare.com", timeout=2):
    tid = os.urandom(2)
    pkt = tid + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    for part in domain.split("."):
        pkt += bytes([len(part)]) + part.encode()
    pkt += b"\x00\x00\x01\x00\x01"
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        t0 = time.time()
        s.sendto(pkt, (server, 53))
        s.recvfrom(512)
        ms = (time.time() - t0) * 1000
        s.close()
        return round(ms, 1)
    except Exception:
        return None

def dns_benchmark(extra_servers=None):
    resolvers = {"Cloudflare": "1.1.1.1", "Google": "8.8.8.8",
                 "Quad9": "9.9.9.9", "OpenDNS": "208.67.222.222"}
    if extra_servers:
        for s in extra_servers:
            if re.match(r"^\d+\.\d+\.\d+\.\d+$", s):
                resolvers.setdefault(f"Tuyo ({s})", s)
    results = []
    for name, ip in resolvers.items():
        times = [t for t in (dns_query_time(ip) for _ in range(3)) if t is not None]
        results.append({"resolver": name, "ip": ip,
                        "ms": round(sum(times) / len(times), 1) if times else None})
    results.sort(key=lambda x: (x["ms"] is None, x["ms"] or 9999))
    return results

# --------------------------------------------------------------------------- #
# 11. Speed test (descarga real)                                             #
# --------------------------------------------------------------------------- #

def speed_test(max_bytes=25_000_000, max_secs=6):
    url = f"https://speed.cloudflare.com/__down?bytes={max_bytes}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "netaudit/2.0"})
        ctx = ssl.create_default_context()
        t0 = time.time(); total = 0
        with urllib.request.urlopen(req, timeout=10, context=ctx) as r:
            while True:
                chunk = r.read(65536)
                if not chunk:
                    break
                total += len(chunk)
                if time.time() - t0 > max_secs:
                    break
        elapsed = time.time() - t0
        if elapsed > 0 and total > 0:
            mbps = (total * 8) / elapsed / 1_000_000
            return {"mbps": round(mbps, 1), "mb": round(total / 1e6, 1),
                    "segundos": round(elapsed, 2)}
    except Exception:
        pass
    return None

# --------------------------------------------------------------------------- #
# 12. Pruebas de conectividad                                                #
# --------------------------------------------------------------------------- #

def ping_stats(host, count=10, fast=False):
    if fast: count = 4
    cmd = ["ping", "-n", str(count), host] if IS_WIN else ["ping", "-c", str(count), host]
    out = run(cmd, timeout=count * 2 + 5)
    res = {"host": host, "loss": None, "min": None, "avg": None, "max": None, "mdev": None}
    ml = re.search(r"([\d\.]+)%\s*(packet )?loss", out)
    if ml: res["loss"] = float(ml.group(1))
    mr = re.search(r"=\s*([\d\.]+)/([\d\.]+)/([\d\.]+)(?:/([\d\.]+))?", out)
    if mr:
        res["min"], res["avg"], res["max"], res["mdev"] = mr.group(1), mr.group(2), mr.group(3), mr.group(4)
    else:
        mw = re.search(r"Minimum = (\d+)ms.*Maximum = (\d+)ms.*Average = (\d+)ms", out, re.S)
        if mw: res["min"], res["max"], res["avg"] = mw.group(1), mw.group(2), mw.group(3)
    return res

def traceroute(host, fast=False):
    if fast: return ""
    if IS_WIN: return run(["tracert", "-d", "-h", "20", host], timeout=40)
    if have("traceroute"): return run(["traceroute", "-n", "-m", "20", "-w", "1", host], timeout=40)
    return ""

def tcp_connect_ms(host, port=443, timeout=4):
    t0 = time.time()
    try:
        socket.create_connection((host, port), timeout=timeout).close()
        return round((time.time() - t0) * 1000, 1)
    except Exception:
        return None

def mtu_to(host, fast=False):
    if fast: return None
    for size in (1472, 1492, 1400, 1300):
        if IS_WIN: cmd = ["ping", "-n", "1", "-f", "-l", str(size), host]
        elif IS_MAC: cmd = ["ping", "-c", "1", "-D", "-s", str(size), host]
        else: cmd = ["ping", "-c", "1", "-M", "do", "-s", str(size), host]
        out = run(cmd, timeout=5).lower()
        if out and "ttl=" in out and "frag" not in out and "too long" not in out:
            return size + 28
    return None

def collect_connectivity(fast=False):
    conn = {}
    conn["ping"] = [ping_stats(t, fast=fast) for t in ("1.1.1.1", "8.8.8.8")]
    conn["dns"] = []
    for d in ("google.com", "cloudflare.com", "github.com", "wikipedia.org"):
        t0 = time.time()
        try:
            ip = socket.gethostbyname(d)
            conn["dns"].append({"dominio": d, "ip": ip, "ms": round((time.time() - t0) * 1000, 1)})
        except Exception:
            conn["dns"].append({"dominio": d, "ip": None, "ms": None})
    conn["tcp443"] = {h: tcp_connect_ms(h, 443) for h in ("google.com", "cloudflare.com", "github.com")}
    conn["mtu"] = mtu_to("1.1.1.1", fast=fast)
    conn["traceroute"] = traceroute("1.1.1.1", fast=fast)
    return conn

# --------------------------------------------------------------------------- #
# 13. Scoring de seguridad                                                    #
# --------------------------------------------------------------------------- #

RISK_PORTS = {
    23: ("Telnet sin cifrar", "alto", "Desactiva Telnet; usa SSH (22)."),
    21: ("FTP sin cifrar", "medio", "Usa SFTP/FTPS en lugar de FTP."),
    139: ("NetBIOS expuesto", "medio", "Restringe NetBIOS/SMB a la LAN o desactívalo."),
    445: ("SMB expuesto", "alto", "No expongas SMB; parchea (EternalBlue)."),
    3389: ("RDP expuesto", "alto", "Cierra RDP a Internet; usa VPN."),
    5900: ("VNC", "alto", "Protege VNC con contraseña fuerte y túnel."),
    1900: ("UPnP/SSDP activo", "medio", "Desactiva UPnP en el router si no lo necesitas."),
    161: ("SNMP", "medio", "Usa SNMPv3; evita 'public'."),
    2375: ("Docker API sin TLS", "alto", "No expongas el socket Docker sin TLS."),
    6379: ("Redis", "alto", "Redis sin auth es peligroso; añade contraseña/bind."),
    9200: ("Elasticsearch", "alto", "No expongas Elasticsearch sin auth."),
    27017: ("MongoDB", "alto", "Activa auth y no lo expongas."),
    11211: ("Memcached", "alto", "No expongas Memcached (amplificación DDoS)."),
    5555: ("ADB Android", "alto", "Desactiva la depuración ADB en red."),
    7547: ("TR-069", "medio", "Gestión remota del ISP; revisa exposición."),
}

def security_score(data):
    findings, score = [], 100
    sev_w = {"alto": 20, "medio": 10, "bajo": 4}
    # Puertos peligrosos (local + LAN)
    local_ports = {p["port"] for p in data.get("listening", [])}
    for port in local_ports:
        if port in RISK_PORTS:
            name, sev, rec = RISK_PORTS[port]
            findings.append({"sev": sev, "donde": "este equipo",
                             "detalle": f"{name} (puerto {port})", "rec": rec})
            score -= sev_w[sev]
    for h in data.get("lan", []):
        for p in h.get("ports", []):
            if p["port"] in RISK_PORTS:
                name, sev, rec = RISK_PORTS[p["port"]]
                findings.append({"sev": sev, "donde": h["ip"],
                                 "detalle": f"{name} (puerto {p['port']})", "rec": rec})
                score -= sev_w[sev] // 2
    # ARP spoofing
    for f in data.get("arp_spoof", []):
        findings.append({"sev": "alto", "donde": f["mac"],
                         "detalle": f"MAC en varias IPs: {', '.join(f['ips'])}",
                         "rec": "Posible ARP spoofing o NAT; verifica."})
        score -= 15
    # Blacklists de la IP pública
    pub = data.get("public") or {}
    listed = [b["lista"] for b in pub.get("blacklists", []) if "LISTADO" in b.get("estado", "")]
    if listed:
        findings.append({"sev": "medio", "donde": "IP pública",
                         "detalle": f"En listas negras: {', '.join(listed)}",
                         "rec": "Solicita la retirada (delisting) y revisa malware."})
        score -= 10
    # Certificados caducados / por caducar en LAN
    for h in data.get("lan", []):
        for p in h.get("ports", []):
            tls = p.get("tls") or {}
            dr = tls.get("dias_restantes")
            if isinstance(dr, int) and dr < 0:
                findings.append({"sev": "medio", "donde": f"{h['ip']}:{p['port']}",
                                 "detalle": f"Certificado TLS caducado ({tls.get('cn')})",
                                 "rec": "Renueva el certificado."})
                score -= 6
    # AbuseIPDB
    abuse = pub.get("abuseipdb") or {}
    if abuse.get("score") and abuse["score"] >= 25:
        findings.append({"sev": "alto", "donde": "IP pública",
                         "detalle": f"AbuseIPDB score {abuse['score']}",
                         "rec": "Tu IP tiene reportes de abuso; investiga."})
        score -= 15
    score = max(0, min(100, score))
    grade = ("A" if score >= 90 else "B" if score >= 75 else
             "C" if score >= 60 else "D" if score >= 40 else "F")
    order = {"alto": 0, "medio": 1, "bajo": 2}
    findings.sort(key=lambda x: order.get(x["sev"], 3))
    return {"score": score, "grade": grade, "findings": findings}

# --------------------------------------------------------------------------- #
# 14. Diff de reportes                                                        #
# --------------------------------------------------------------------------- #

def compare_reports(path_a, path_b):
    a = json.load(open(path_a, encoding="utf-8"))
    b = json.load(open(path_b, encoding="utf-8"))
    def hostmap(d):
        return {h["ip"]: h for h in d.get("lan", [])}
    ma, mb = hostmap(a), hostmap(b)
    added = sorted(set(mb) - set(ma))
    removed = sorted(set(ma) - set(mb))
    print(section.__doc__ or "")
    section("DIFF de reportes")
    print(f"   A: {path_a}  ({len(ma)} hosts)")
    print(f"   B: {path_b}  ({len(mb)} hosts)")
    print("\n   " + C.g(f"+ Nuevos hosts ({len(added)}):"))
    for ip in added:
        print(f"     + {ip}  {mb[ip].get('hostname') or ''}")
    print("\n   " + C.r(f"- Hosts desaparecidos ({len(removed)}):"))
    for ip in removed:
        print(f"     - {ip}  {ma[ip].get('hostname') or ''}")
    print("\n   Cambios de puertos en hosts comunes:")
    for ip in sorted(set(ma) & set(mb)):
        pa = {p["port"] for p in ma[ip].get("ports", [])}
        pb = {p["port"] for p in mb[ip].get("ports", [])}
        if pa != pb:
            print(f"     {ip}: +{sorted(pb - pa)}  -{sorted(pa - pb)}")
    print()

# --------------------------------------------------------------------------- #
# 15. Export CSV                                                              #
# --------------------------------------------------------------------------- #

def export_csv(path, hosts):
    import csv
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["ip", "hostname", "mac", "vendor", "os_guess", "rtt_ms", "puertos_abiertos"])
        for h in hosts:
            ports = ";".join(str(p["port"]) for p in h.get("ports", []))
            w.writerow([h["ip"], h.get("hostname") or "", h.get("mac") or "",
                        h.get("vendor") or "", h.get("os_guess") or "",
                        h.get("rtt_ms") if h.get("rtt_ms") is not None else "", ports])

# --------------------------------------------------------------------------- #
# 16. Dashboard HTML                                                          #
# --------------------------------------------------------------------------- #

def esc(x):
    if x is None or x == "":
        return "<span class='muted'>—</span>"
    return str(x).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

def kv_table(d):
    rows = "".join(f"<tr><th>{esc(k)}</th><td>{esc(v)}</td></tr>"
                   for k, v in d.items() if v not in (None, "", [], {}))
    return f"<table class='kv'>{rows}</table>"

def build_html(data):
    host = data["host"]; pub = data.get("public") or {}; geo = pub.get("geo") or {}
    sec = data.get("security") or {"score": "—", "grade": "—", "findings": []}
    lan = data.get("lan") or []
    n_open = sum(len(h.get("ports", [])) for h in lan)
    spd = data.get("speedtest") or {}

    gw = (data.get("gateway") or {}).get("default") or "—"
    score = sec.get("score", "—")
    grade = sec.get("grade", "—")
    grade_color = ("#37d39a" if grade in ("A", "B") else "#ffb454" if grade == "C" else "#ff5d6c")

    cards = f"""
    <div class="cards">
      <div class="card score" style="--gc:{grade_color}">
        <div class="lbl">Seguridad</div>
        <div class="gauge">{score}<span>/100</span></div>
        <div class="grade" style="color:{grade_color}">Grado {grade}</div>
      </div>
      <div class="card"><div class="lbl">IP pública</div><div class="val">{esc(pub.get('ip'))}</div></div>
      <div class="card"><div class="lbl">Ubicación</div><div class="val sm">{esc(', '.join(filter(None,[geo.get('ciudad'),geo.get('país')])) or '—')}</div></div>
      <div class="card"><div class="lbl">ISP / ASN</div><div class="val sm">{esc(geo.get('isp'))}<br><span class='muted'>{esc(geo.get('asn'))}</span></div></div>
      <div class="card"><div class="lbl">Gateway</div><div class="val">{esc(gw)}</div></div>
      <div class="card"><div class="lbl">Hosts LAN</div><div class="val">{len(lan)}</div></div>
      <div class="card"><div class="lbl">Puertos abiertos</div><div class="val">{n_open}</div></div>
      <div class="card"><div class="lbl">Velocidad ↓</div><div class="val sm">{esc(str(spd.get('mbps'))+' Mbps' if spd.get('mbps') else None)}</div></div>
    </div>"""

    # Hallazgos de seguridad
    sevcls = {"alto": "bad", "medio": "warn", "bajo": "muted"}
    find_rows = "".join(
        f"<tr><td><span class='pill {sevcls.get(f['sev'],'muted')}'>{esc(f['sev'])}</span></td>"
        f"<td>{esc(f['donde'])}</td><td>{esc(f['detalle'])}</td><td class='muted'>{esc(f['rec'])}</td></tr>"
        for f in sec.get("findings", []))
    find_html = (f"<table class='data'><thead><tr><th>Sev</th><th>Dónde</th><th>Detalle</th><th>Recomendación</th></tr></thead><tbody>{find_rows}</tbody></table>"
                 if find_rows else "<p class='ok'>Sin hallazgos de riesgo. 🎉</p>")

    # Interfaces
    iface_html = ""
    for name, d in data["interfaces"].items():
        iface_html += f"""<div class="iface"><h4>{esc(name)} <span class="badge">{esc(d.get('state') or '')}</span></h4>
          <table class="kv"><tr><th>IPv4</th><td>{'<br>'.join(esc(x) for x in d['ipv4']) or '—'}</td></tr>
          <tr><th>IPv6</th><td>{'<br>'.join(esc(x) for x in d['ipv6']) or '—'}</td></tr>
          <tr><th>MAC</th><td>{esc(d.get('mac'))}</td></tr><tr><th>MTU</th><td>{esc(d.get('mtu'))}</td></tr></table></div>"""

    # LAN con puertos
    lan_rows = ""
    for h in lan:
        ports = " ".join(f"<span class='chip sm'>{p['port']}{'·'+p['service'] if p['service'] else ''}</span>"
                         for p in h.get("ports", [])) or "<span class='muted'>—</span>"
        lan_rows += (f"<tr><td>{esc(h['ip'])}</td><td>{esc(h.get('hostname'))}</td>"
                     f"<td>{esc(h.get('mac'))}</td><td>{esc(h.get('vendor'))}</td>"
                     f"<td>{esc(h.get('os_guess'))}</td><td>{esc(h.get('rtt_ms'))}</td><td>{ports}</td></tr>")
    lan_html = (f"<table class='data sortable' id='lanTable'><thead><tr><th>IP</th><th>Hostname</th><th>MAC</th><th>Fabricante</th><th>SO (TTL)</th><th>RTT</th><th>Puertos</th></tr></thead><tbody>{lan_rows}</tbody></table>"
                if lan_rows else "<p class='muted'>Escaneo LAN omitido.</p>")

    # SSDP
    ssdp = data.get("ssdp") or []
    ssdp_rows = "".join(f"<tr><td>{esc(d['ip'])}</td><td>{esc(d.get('server'))}</td><td>{esc(d.get('st'))}</td></tr>" for d in ssdp)
    ssdp_html = (f"<table class='data'><thead><tr><th>IP</th><th>Server</th><th>Tipo</th></tr></thead><tbody>{ssdp_rows}</tbody></table>"
                 if ssdp_rows else "<p class='muted'>Sin dispositivos UPnP/SSDP detectados.</p>")

    # DNS benchmark
    dnsb = data.get("dns_benchmark") or []
    dnsb_rows = "".join(f"<tr><td>{esc(r['resolver'])}</td><td>{esc(r['ip'])}</td><td>{esc(r['ms'])}</td></tr>" for r in dnsb)
    dnsb_html = f"<table class='data'><thead><tr><th>Resolver</th><th>IP</th><th>ms</th></tr></thead><tbody>{dnsb_rows}</tbody></table>"

    # Wi-Fi
    wifi = data.get("wifi") or {}
    wifi_html = kv_table(wifi) if wifi else "<p class='muted'>Sin datos Wi-Fi (cable o no disponible).</p>"

    # Puertos locales
    lp = data.get("listening") or []
    lp_rows = "".join(f"<tr><td>{esc(p['proto'])}</td><td>{esc(p['port'])}</td><td>{esc(p['addr'])}</td><td>{esc(p['service'])}</td></tr>" for p in lp)
    lp_html = (f"<table class='data'><thead><tr><th>Proto</th><th>Puerto</th><th>Dirección</th><th>Servicio</th></tr></thead><tbody>{lp_rows}</tbody></table>"
               if lp_rows else "<p class='muted'>Sin puertos en escucha.</p>")

    # Conectividad
    conn = data.get("connectivity") or {}
    ping_rows = "".join(f"<tr><td>{esc(p['host'])}</td><td>{esc(p['loss'])}%</td><td>{esc(p['min'])}</td><td>{esc(p['avg'])}</td><td>{esc(p['max'])}</td></tr>" for p in conn.get("ping", []))
    ping_html = f"<table class='data'><thead><tr><th>Destino</th><th>Pérdida</th><th>Min</th><th>Avg</th><th>Max</th></tr></thead><tbody>{ping_rows}</tbody></table>"

    # Geo + mapa
    geo_html = kv_table(geo) if geo else "<p class='muted'>—</p>"
    map_html = ""
    if geo.get("lat") and geo.get("lon"):
        la, lo = geo["lat"], geo["lon"]
        d = 0.05
        bbox = f"{lo-d},{la-d},{lo+d},{la+d}"
        map_html = f"""<iframe class="map" loading="lazy" src="https://www.openstreetmap.org/export/embed.html?bbox={bbox}&layer=mapnik&marker={la},{lo}"></iframe>"""

    bl = pub.get("blacklists") or []
    bl_rows = "".join(f"<tr><td>{esc(b['lista'])}</td><td class='{'bad' if 'LISTADO' in b['estado'] else 'ok'}'>{esc(b['estado'])}</td></tr>" for b in bl)
    bl_html = f"<table class='data'><thead><tr><th>DNSBL</th><th>Estado</th></tr></thead><tbody>{bl_rows}</tbody></table>" if bl else "<p class='muted'>No evaluado.</p>"

    routes_html = f"<pre class='term'>{esc(data.get('routes'))}</pre>"
    tr_html = f"<pre class='term'>{esc(conn.get('traceroute'))}</pre>" if conn.get("traceroute") else "<p class='muted'>Traceroute omitido.</p>"

    # Datos para gráficas
    port_counter = {}
    for h in lan:
        for p in h.get("ports", []):
            lbl = f"{p['port']} {p['service']}".strip()
            port_counter[lbl] = port_counter.get(lbl, 0) + 1
    top_ports = sorted(port_counter.items(), key=lambda x: -x[1])[:10]
    chart_ports_labels = json.dumps([k for k, _ in top_ports])
    chart_ports_data = json.dumps([v for _, v in top_ports])
    rtt_pairs = [(h["ip"], h["rtt_ms"]) for h in lan if h.get("rtt_ms") is not None][:15]
    chart_rtt_labels = json.dumps([ip for ip, _ in rtt_pairs])
    chart_rtt_data = json.dumps([r for _, r in rtt_pairs])
    chart_dns_labels = json.dumps([r["resolver"] for r in dnsb])
    chart_dns_data = json.dumps([r["ms"] or 0 for r in dnsb])

    ts = host.get("timestamp")
    html = f"""<!DOCTYPE html><html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>netaudit · {esc(host.get('hostname'))}</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
<style>
:root{{--bg:#0b0f17;--panel:#121826;--panel2:#0e1420;--line:#1f2a3d;--txt:#dbe4f0;--muted:#6b7a93;--acc:#37d39a;--acc2:#4aa3ff;--bad:#ff5d6c;--warn:#ffb454;--mono:'SF Mono',ui-monospace,Menlo,Consolas,monospace}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--txt);font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;font-size:14px;line-height:1.5}}
header{{padding:26px 32px;border-bottom:1px solid var(--line);background:linear-gradient(180deg,#101725,#0b0f17)}}
header h1{{margin:0;font-size:22px}}header h1 .dot{{color:var(--acc)}}
header .meta{{color:var(--muted);margin-top:6px;font-family:var(--mono);font-size:12px}}
.wrap{{max-width:1180px;margin:0 auto;padding:0 32px 60px}}
.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:14px;margin:24px 0}}
.card{{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:16px 18px}}
.card .lbl{{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:1px}}
.card .val{{font-size:22px;font-weight:600;margin-top:6px;font-family:var(--mono);color:var(--acc)}}
.card .val.sm{{font-size:14px;color:var(--txt);font-family:inherit}}
.card.score{{background:radial-gradient(circle at 30% 20%,rgba(55,211,154,.08),var(--panel))}}
.card.score .gauge{{font-size:34px;font-weight:700;font-family:var(--mono);color:var(--gc)}}
.card.score .gauge span{{font-size:14px;color:var(--muted)}}
.card.score .grade{{font-weight:700;font-size:13px}}
section{{background:var(--panel);border:1px solid var(--line);border-radius:14px;margin:18px 0;overflow:hidden}}
section>h2{{margin:0;padding:15px 22px;font-size:15px;border-bottom:1px solid var(--line);background:var(--panel2);cursor:pointer;display:flex;justify-content:space-between}}
section>h2 .num{{color:var(--muted);font-family:var(--mono);font-size:12px}}
section .body{{padding:20px 22px}}.collapsed .body{{display:none}}
.grid2{{display:grid;grid-template-columns:1fr 1fr;gap:20px}}@media(max-width:860px){{.grid2{{grid-template-columns:1fr}}}}
table{{width:100%;border-collapse:collapse;font-size:13px}}
table.kv th{{text-align:left;color:var(--muted);font-weight:500;width:38%;padding:6px 8px;vertical-align:top}}
table.kv td{{padding:6px 8px;font-family:var(--mono);word-break:break-all}}
table.data th{{text-align:left;color:var(--muted);font-weight:600;padding:8px 10px;border-bottom:1px solid var(--line);font-size:11px;text-transform:uppercase}}
table.data td{{padding:7px 10px;border-bottom:1px solid #141d2c;font-family:var(--mono);vertical-align:top}}
table.data tr:hover td{{background:#0e1726}}table.sortable th{{cursor:pointer}}
.iface{{background:var(--panel2);border:1px solid var(--line);border-radius:10px;padding:14px;margin-bottom:12px}}
.iface h4{{margin:0 0 8px;font-family:var(--mono);color:var(--acc2)}}
.badge{{font-size:10px;background:#1d3a2e;color:var(--acc);padding:2px 8px;border-radius:20px;margin-left:6px}}
.chip{{display:inline-block;background:#152133;border:1px solid var(--line);color:var(--acc2);font-family:var(--mono);padding:3px 10px;border-radius:20px;margin:2px}}
.chip.sm{{padding:1px 7px;font-size:11px}}
.pill{{padding:2px 9px;border-radius:20px;font-size:11px;font-weight:700;text-transform:uppercase}}
.pill.bad{{background:#3a1620;color:var(--bad)}}.pill.warn{{background:#3a2c14;color:var(--warn)}}
.muted{{color:var(--muted)}}.bad{{color:var(--bad);font-weight:600}}.ok{{color:var(--acc)}}.warn{{color:var(--warn)}}
pre.term{{background:#070b12;border:1px solid var(--line);border-radius:10px;padding:14px;overflow:auto;font-family:var(--mono);font-size:12px;color:#9fd6c0;max-height:340px}}
.map{{width:100%;height:280px;border:1px solid var(--line);border-radius:10px}}
.chartbox{{position:relative;height:240px}}
input.filter{{background:var(--panel2);border:1px solid var(--line);color:var(--txt);border-radius:8px;padding:7px 12px;width:240px;margin-bottom:12px;font-family:var(--mono)}}
.btn{{background:#152133;border:1px solid var(--line);color:var(--acc2);border-radius:8px;padding:6px 14px;cursor:pointer;font-size:12px;margin-left:8px}}
.legal{{color:var(--muted);font-size:11px;text-align:center;margin-top:30px;line-height:1.6}}
</style></head><body>
<header><h1><span class="dot">▍</span> netaudit <span class="muted" style="font-weight:400">v{__version__} · auditoría de red</span></h1>
<div class="meta">host: {esc(host.get('hostname'))} · {esc(host.get('os'))} {esc(host.get('os_release'))} · {esc(host.get('arch'))} · {esc(ts)}</div></header>
<div class="wrap">
  {cards}

  <section><h2>🛡️ Hallazgos de seguridad <span class="num">score {score}/100 · {grade}</span></h2><div class="body">{find_html}</div></section>

  <section><h2>📊 Gráficas <span class="num">A</span></h2><div class="body"><div class="grid2">
    <div><h4 class="muted">Puertos abiertos más comunes (LAN)</h4><div class="chartbox"><canvas id="cPorts"></canvas></div></div>
    <div><h4 class="muted">Latencia por host (ms)</h4><div class="chartbox"><canvas id="cRtt"></canvas></div></div></div>
    <div style="margin-top:18px"><h4 class="muted">Benchmark de resolvers DNS (ms, menos es mejor)</h4><div class="chartbox"><canvas id="cDns"></canvas></div></div>
  </div></section>

  <section><h2>🖥️ Sistema / Host <span class="num">01</span></h2><div class="body">{kv_table(host)}</div></section>
  <section><h2>🔌 Interfaces <span class="num">02</span></h2><div class="body">{iface_html or '—'}</div></section>

  <section><h2>🌐 IP pública · Geo · ASN <span class="num">03</span></h2><div class="body"><div class="grid2">
    <div>{geo_html}{('<h4 class=muted style=margin-top:14px>Reputación (DNSBL)</h4>'+bl_html)}</div>
    <div>{map_html or '<p class=muted>Sin coordenadas.</p>'}</div></div></div></section>

  <section><h2>📡 Hosts de la LAN (puertos, banners, SO) <span class="num">04</span></h2><div class="body">
    <input class="filter" id="lanFilter" placeholder="filtrar IP / host / MAC…" onkeyup="filterTable('lanTable','lanFilter')">
    <button class="btn" onclick="exportCSV()">Exportar CSV</button>{lan_html}</div></section>

  <section><h2>🔎 Dispositivos UPnP / SSDP <span class="num">05</span></h2><div class="body">{ssdp_html}</div></section>
  <section><h2>📶 Wi-Fi <span class="num">06</span></h2><div class="body">{wifi_html}</div></section>
  <section><h2>🚪 Puertos en escucha (local) <span class="num">07</span></h2><div class="body">{lp_html}</div></section>

  <section><h2>⚡ Conectividad y DNS <span class="num">08</span></h2><div class="body"><div class="grid2">
    <div><h4 class="muted">Latencia ICMP</h4>{ping_html}<p style="margin-top:10px">MTU: <b>{esc(conn.get('mtu'))}</b> · Velocidad ↓: <b>{esc(str(spd.get('mbps'))+' Mbps' if spd.get('mbps') else None)}</b></p></div>
    <div><h4 class="muted">Benchmark DNS</h4>{dnsb_html}</div></div>
    <h4 class="muted" style="margin-top:18px">Traceroute → 1.1.1.1</h4>{tr_html}
    <h4 class="muted" style="margin-top:18px">Tabla de rutas</h4>{routes_html}</div></section>

  <div class="legal">Generado por netaudit v{__version__} · Úsalo sólo en redes propias o con autorización.</div>
</div>
<script>
const LAN={json.dumps(lan, default=str)};
document.querySelectorAll('section > h2').forEach(h=>h.addEventListener('click',()=>h.parentElement.classList.toggle('collapsed')));
function filterTable(tid,fid){{const q=document.getElementById(fid).value.toLowerCase();document.querySelectorAll('#'+tid+' tbody tr').forEach(tr=>{{tr.style.display=tr.innerText.toLowerCase().includes(q)?'':'none';}});}}
document.querySelectorAll('table.sortable').forEach(t=>{{t.querySelectorAll('th').forEach((th,i)=>th.addEventListener('click',()=>{{
  const rows=[...t.tBodies[0].rows];const asc=!(th.dataset.asc==='1');th.dataset.asc=asc?'1':'0';
  rows.sort((a,b)=>{{let x=a.cells[i].innerText,y=b.cells[i].innerText;const nx=parseFloat(x),ny=parseFloat(y);
  if(!isNaN(nx)&&!isNaN(ny))return asc?nx-ny:ny-nx;return asc?x.localeCompare(y):y.localeCompare(x);}});
  rows.forEach(r=>t.tBodies[0].appendChild(r));}})); }});
function exportCSV(){{let c='ip,hostname,mac,vendor,os,rtt,ports\\n';LAN.forEach(h=>{{const p=(h.ports||[]).map(x=>x.port).join(' ');c+=[h.ip,h.hostname||'',h.mac||'',h.vendor||'',h.os_guess||'',h.rtt_ms||'',p].join(',')+'\\n';}});
  const a=document.createElement('a');a.href=URL.createObjectURL(new Blob([c],{{type:'text/csv'}}));a.download='netaudit_hosts.csv';a.click();}}
const co={{plugins:{{legend:{{display:false}}}},scales:{{x:{{ticks:{{color:'#6b7a93'}},grid:{{color:'#1f2a3d'}}}},y:{{ticks:{{color:'#6b7a93'}},grid:{{color:'#1f2a3d'}}}}}}}};
function bar(id,labels,data,color){{const e=document.getElementById(id);if(!e||!labels.length)return;new Chart(e,{{type:'bar',data:{{labels:labels,datasets:[{{data:data,backgroundColor:color,borderRadius:4}}]}},options:co}});}}
bar('cPorts',{chart_ports_labels},{chart_ports_data},'#4aa3ff');
bar('cRtt',{chart_rtt_labels},{chart_rtt_data},'#37d39a');
bar('cDns',{chart_dns_labels},{chart_dns_data},'#ffb454');
</script></body></html>"""
    return html

# --------------------------------------------------------------------------- #
# Extras tipo "Advanced IP Scanner": Wake-on-LAN, SMB, acciones rápidas       #
# --------------------------------------------------------------------------- #

def wake_on_lan(mac, broadcast="255.255.255.255", port=9):
    """Envía un paquete mágico Wake-on-LAN a la MAC indicada."""
    clean = re.sub(r"[^0-9a-fA-F]", "", mac)
    if len(clean) != 12:
        raise ValueError("MAC inválida")
    data = bytes.fromhex("FF" * 6 + clean * 16)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.sendto(data, (broadcast, port))
        s.close()
        return True
    except Exception:
        return False


def smb_shares(ip, timeout=4):
    """Lista carpetas compartidas SMB del host (best-effort, según el sistema)."""
    shares = []
    try:
        if IS_WIN:
            out = run(["net", "view", f"\\\\{ip}"], timeout=timeout)
            for line in out.splitlines():
                m = re.match(r"^(\S+)\s+Disk", line)
                if m:
                    shares.append(m.group(1))
        elif IS_MAC and have("smbutil"):
            out = run(["smbutil", "view", "-g", f"//{ip}"], timeout=timeout)
            for line in out.splitlines():
                m = re.match(r"^(\S+)\s+Disk", line.strip())
                if m and m.group(1).lower() not in ("share", "-----"):
                    shares.append(m.group(1))
        elif have("smbclient"):
            out = run(["smbclient", "-L", f"//{ip}", "-N", "-g"], timeout=timeout)
            for line in out.splitlines():
                if line.startswith("Disk|"):
                    shares.append(line.split("|")[1])
    except Exception:
        pass
    return shares


def host_actions(host):
    """Devuelve las acciones/URLs disponibles para un host según sus puertos."""
    ip = host["ip"]
    ports = {p["port"] for p in host.get("ports", [])}
    actions = []
    if 80 in ports or 8080 in ports:
        actions.append(("Abrir web (HTTP)", f"http://{ip}"))
    if 443 in ports or 8443 in ports:
        actions.append(("Abrir web (HTTPS)", f"https://{ip}"))
    if 21 in ports:
        actions.append(("FTP", f"ftp://{ip}"))
    if 445 in ports or 139 in ports:
        actions.append(("Carpetas compartidas (SMB)", f"smb://{ip}"))
    if 3389 in ports:
        actions.append(("Escritorio remoto (RDP)", f"rdp://{ip}"))
    if 22 in ports:
        actions.append(("SSH", f"ssh://{ip}"))
    if 5900 in ports:
        actions.append(("VNC", f"vnc://{ip}"))
    actions.append(("Ping", ip))
    if host.get("mac"):
        actions.append(("Wake-on-LAN", host["mac"]))
    return actions


# --------------------------------------------------------------------------- #
# API reutilizable (la usa también la GUI)                                    #
# --------------------------------------------------------------------------- #

class Options:
    """Contenedor simple de opciones para analyze()."""
    def __init__(self, **kw):
        self.fast = kw.get("fast", False)
        self.no_lan = kw.get("no_lan", False)
        self.no_public = kw.get("no_public", False)
        self.no_portscan = kw.get("no_portscan", False)
        self.no_speedtest = kw.get("no_speedtest", False)
        self.online_oui = kw.get("online_oui", False)
        self.ports = kw.get("ports")
        self.subnet = kw.get("subnet")
        self.target = kw.get("target")
        self.timeout = kw.get("timeout", 0.6)
        self.output = kw.get("output", "network_report.html")
        self.json = kw.get("json")
        self.csv = kw.get("csv")


def analyze(opts, status=None):
    """Ejecuta el pipeline completo y devuelve el dict de datos.
    `status(msg)` se llama con el nombre de cada fase (para barras de progreso)."""
    def st(msg):
        if status:
            try: status(msg)
            except Exception: pass
    data = {}
    st("Sistema y host…"); data["host"] = collect_host()
    st("Interfaces de red…"); data["interfaces"] = collect_interfaces()
    st("Gateway, DNS y ARP…")
    data["gateway"] = collect_gateway(); data["routes"] = collect_routes()
    data["dns"] = collect_dns(); data["arp"] = collect_arp()
    data["arp_spoof"] = detect_arp_spoof(data["arp"], data["gateway"])
    st("Puertos en escucha…"); data["listening"] = collect_listening()
    st("Wi-Fi…"); data["wifi"] = collect_wifi()
    if not opts.no_public:
        st("IP pública y reputación…"); data["public"] = collect_public(fast=opts.fast)
    else:
        data["public"] = {}
    st("Dispositivos UPnP/SSDP…"); data["ssdp"] = collect_ssdp(timeout=2 if opts.fast else 3)
    if not opts.no_lan:
        net = guess_subnet(opts.subnet or opts.target)
        st(f"Escaneando la red {net}…")
        data["lan"] = collect_lan(net, data["arp"], fast=opts.fast,
                                  online_oui=opts.online_oui, progress=False)
        if not opts.no_portscan:
            st("Escaneando puertos de los hosts…")
            data["lan"] = portscan_lan(data["lan"], parse_ports(opts.ports),
                                       opts.timeout, fast=opts.fast, progress=False)
    else:
        data["lan"] = []
    st("Benchmark de DNS…"); data["dns_benchmark"] = dns_benchmark(data.get("dns", {}).get("servers"))
    st("Pruebas de conectividad…"); data["connectivity"] = collect_connectivity(fast=opts.fast)
    if not opts.no_speedtest and not opts.no_public:
        st("Midiendo velocidad…"); data["speedtest"] = speed_test(max_secs=4 if opts.fast else 6) or {}
    else:
        data["speedtest"] = {}
    st("Calculando score de seguridad…"); data["security"] = security_score(data)
    st("Generando informe…")
    with open(opts.output, "w", encoding="utf-8") as f:
        f.write(build_html(data))
    if opts.json:
        with open(opts.json, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2, default=str)
    if opts.csv:
        export_csv(opts.csv, data.get("lan", []))
    st("Listo")
    return data


# --------------------------------------------------------------------------- #
# Captura de paquetes por CLI (mini-Wireshark)                                #
# --------------------------------------------------------------------------- #

def run_capture_cli(args):
    sniff = netaudit_sniffer
    if sniff is None:
        try:
            import netaudit_sniffer as sniff
        except Exception as e:
            print(C.r(f"No se pudo cargar el módulo sniffer: {e}"))
            return
    if args.read_pcap:
        section(f"Leyendo {args.read_pcap}")
        pkts = sniff.read_pcap(args.read_pcap)
    else:
        ok, why = sniff.can_capture()
        if not ok:
            print(C.r(f"\n   No se puede capturar: {why}"))
            print("   Sugerencia: ejecútalo con sudo (Linux/macOS).\n")
            return
        section(f"Captura de paquetes ({args.capture}) · {why}")
        print(C.dim("   Necesita privilegios de administrador. Ctrl+C para parar.\n"))
        hdr = f"   {'No.':>4} {'Tiempo':>12}  {'Origen':>21} → {'Destino':<21} {'Proto':<6}{'Long':>6}  Info"
        print(C.dim(hdr))
        def show(p):
            import datetime as _dt
            t = _dt.datetime.fromtimestamp(p['time']).strftime("%H:%M:%S.%f")[:-3]
            print(f"   {p['no']:>4} {t:>12}  {p['src']:>21} → {p['dst']:<21} {p['proto']:<6}{p['length']:>6}  {p['info']}")
        try:
            pkts = sniff.capture(args.capture or 50, args.iface, args.filter, on_packet=show)
        except PermissionError as e:
            print(C.r(f"\n   {e}\n")); return
        except Exception as e:
            print(C.r(f"\n   Error de captura: {e}\n")); return

    out = args.output if args.output != "network_report.html" else "capture_report.html"
    with open(out, "w", encoding="utf-8") as f:
        f.write(sniff.build_capture_html(pkts))
    print(f"\n   {len(pkts)} paquetes · Reporte HTML: {os.path.abspath(out)}")
    if args.pcap:
        sniff.write_pcap(args.pcap, pkts)
        print(f"   pcap: {os.path.abspath(args.pcap)}  (ábrelo en Wireshark)")
    if args.pdf and netaudit_pdf:
        netaudit_pdf.pdf_capture_report(pkts, args.pdf)
        print(f"   PDF:  {os.path.abspath(args.pdf)}")
    print(C.g("   Listo. ✔\n"))


# --------------------------------------------------------------------------- #
# Orquestador (CLI)                                                           #
# --------------------------------------------------------------------------- #

def main():
    ap = argparse.ArgumentParser(description="netaudit · analizador/auditor de red multiplataforma")
    ap.add_argument("-o", "--output", default="network_report.html")
    ap.add_argument("--json", default=None)
    ap.add_argument("--csv", default=None)
    ap.add_argument("--target", default=None, help="host o red a analizar")
    ap.add_argument("--subnet", default=None, help="red a escanear, ej 192.168.1.0/24")
    ap.add_argument("--ports", default=None, help="puertos, ej 1-1024 o 22,80,443")
    ap.add_argument("--timeout", type=float, default=0.6)
    ap.add_argument("--no-lan", action="store_true")
    ap.add_argument("--no-public", action="store_true")
    ap.add_argument("--no-portscan", action="store_true")
    ap.add_argument("--no-speedtest", action="store_true")
    ap.add_argument("--online-oui", action="store_true")
    ap.add_argument("--fast", action="store_true")
    ap.add_argument("--no-color", action="store_true")
    ap.add_argument("--compare", nargs=2, metavar=("A.json", "B.json"))
    ap.add_argument("--version", action="version", version=f"netaudit {__version__}")
    # Captura de paquetes (mini-Wireshark) y Wake-on-LAN (Advanced IP Scanner)
    ap.add_argument("--capture", type=int, metavar="N", help="captura N paquetes (necesita sudo)")
    ap.add_argument("--iface", default=None, help="interfaz para la captura")
    ap.add_argument("--filter", default=None, help="filtro BPF para la captura, ej 'tcp port 443'")
    ap.add_argument("--pcap", default=None, help="guarda la captura en un .pcap (Wireshark)")
    ap.add_argument("--read-pcap", default=None, help="lee y diseca un .pcap existente")
    ap.add_argument("--pdf", default=None, help="exporta el informe a PDF (auditoría o captura)")
    ap.add_argument("--wol", default=None, metavar="MAC", help="envía Wake-on-LAN a una MAC")
    args = ap.parse_args()

    if args.no_color:
        C.enabled = False
    if args.compare:
        compare_reports(args.compare[0], args.compare[1])
        return
    if args.wol:
        ok = wake_on_lan(args.wol)
        print(C.g(f"   Wake-on-LAN enviado a {args.wol}") if ok
              else C.r(f"   No se pudo enviar WoL a {args.wol}"))
        return
    if args.capture is not None or args.read_pcap:
        run_capture_cli(args)
        return

    print(C.b(r"""
  ███╗   ██╗███████╗████████╗ █████╗ ██╗   ██╗██████╗ ██╗████████╗
  ████╗  ██║██╔════╝╚══██╔══╝██╔══██╗██║   ██║██╔══██╗██║╚══██╔══╝
  ██╔██╗ ██║█████╗     ██║   ███████║██║   ██║██║  ██║██║   ██║
  ██║╚██╗██║██╔══╝     ██║   ██╔══██║██║   ██║██║  ██║██║   ██║
  ██║ ╚████║███████╗   ██║   ██║  ██║╚██████╔╝██████╔╝██║   ██║
  ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝   ╚═╝""") +
          f"  v{__version__}")
    print(f"  SO: {platform.system()} {platform.release()} ({platform.machine()})\n")

    data = {}
    section("01 · Host / sistema")
    data["host"] = collect_host()
    print(f"   {data['host']['hostname']} · {data['host']['os']} {data['host']['os_release']}")

    section("02 · Interfaces de red")
    data["interfaces"] = collect_interfaces()
    for name, d in data["interfaces"].items():
        print(f"   {name}: ipv4={d['ipv4']} mac={d['mac']} mtu={d['mtu']}")

    section("03 · Gateway / Rutas / DNS / ARP")
    data["gateway"] = collect_gateway()
    data["routes"] = collect_routes()
    data["dns"] = collect_dns()
    data["arp"] = collect_arp()
    data["arp_spoof"] = detect_arp_spoof(data["arp"], data["gateway"])
    print(f"   Gateway: {data['gateway']['default']}  DNS: {data['dns']['servers']}  ARP: {len(data['arp'])}")
    if data["arp_spoof"]:
        print(C.y(f"   ⚠ MAC en varias IPs: {len(data['arp_spoof'])} (posible spoofing)"))

    section("04 · Puertos en escucha (local)")
    data["listening"] = collect_listening()
    print(f"   {len(data['listening'])} sockets en escucha")

    section("05 · Wi-Fi")
    data["wifi"] = collect_wifi()
    print(f"   {data['wifi'] or 'sin datos'}")

    if not args.no_public:
        section("06 · IP pública / Geo / ASN / Reputación")
        data["public"] = collect_public(fast=args.fast)
        g = (data["public"].get("geo") or {})
        print(f"   IP: {data['public'].get('ip')}  {g.get('ciudad')},{g.get('país')}  {g.get('isp')}")
    else:
        data["public"] = {}

    section("07 · UPnP / SSDP")
    data["ssdp"] = collect_ssdp(timeout=2 if args.fast else 3)
    print(f"   {len(data['ssdp'])} dispositivos UPnP")

    if not args.no_lan:
        net = guess_subnet(args.subnet or args.target)
        section(f"08 · Escaneo de la LAN  ({net})")
        data["lan"] = collect_lan(net, data["arp"], fast=args.fast, online_oui=args.online_oui)
        print(f"   {len(data['lan'])} hosts vivos")
        if not args.no_portscan:
            ports = parse_ports(args.ports)
            print(f"   Escaneando {len(ports)} puertos por host...")
            data["lan"] = portscan_lan(data["lan"], ports, args.timeout, fast=args.fast)
            tot = sum(len(h['ports']) for h in data['lan'])
            print(f"   {tot} puertos abiertos en total")
        for h in data["lan"]:
            pr = ",".join(str(p["port"]) for p in h.get("ports", []))
            print(f"   {h['ip']:<16}{(h.get('hostname') or '')[:24]:<25}{h.get('os_guess') or '':<12}{pr}")
    else:
        data["lan"] = []

    section("09 · Benchmark DNS")
    data["dns_benchmark"] = dns_benchmark(data.get("dns", {}).get("servers"))
    for r in data["dns_benchmark"][:3]:
        print(f"   {r['resolver']:<16}{r['ip']:<18}{r['ms']} ms")

    section("10 · Conectividad")
    data["connectivity"] = collect_connectivity(fast=args.fast)
    for p in data["connectivity"]["ping"]:
        print(f"   ping {p['host']}: loss={p['loss']}% avg={p['avg']}ms")

    if not args.no_speedtest and not args.no_public:
        section("11 · Test de velocidad")
        data["speedtest"] = speed_test(max_secs=4 if args.fast else 6) or {}
        if data["speedtest"]:
            print(f"   ↓ {data['speedtest']['mbps']} Mbps ({data['speedtest']['mb']} MB en {data['speedtest']['segundos']}s)")
    else:
        data["speedtest"] = {}

    section("12 · Scoring de seguridad")
    data["security"] = security_score(data)
    s = data["security"]
    col = C.g if s["grade"] in ("A", "B") else C.y if s["grade"] == "C" else C.r
    print(col(f"   Score: {s['score']}/100  (grado {s['grade']})  ·  {len(s['findings'])} hallazgos"))
    for f in s["findings"][:8]:
        print(f"   [{f['sev']:>5}] {f['donde']}: {f['detalle']}")

    # Salidas
    with open(args.output, "w", encoding="utf-8") as f:
        f.write(build_html(data))
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2, default=str)
    if args.csv:
        export_csv(args.csv, data.get("lan", []))
    if args.pdf and netaudit_pdf:
        netaudit_pdf.pdf_audit_report(data, args.pdf)

    section("Reporte generado")
    print(f"   HTML: {os.path.abspath(args.output)}")
    if args.json: print(f"   JSON: {os.path.abspath(args.json)}")
    if args.csv:  print(f"   CSV:  {os.path.abspath(args.csv)}")
    if args.pdf and netaudit_pdf:  print(f"   PDF:  {os.path.abspath(args.pdf)}")
    print(C.g("\n   Abre el HTML en tu navegador. ✔\n"))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[interrumpido]")
        sys.exit(1)
