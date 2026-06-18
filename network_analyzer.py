#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
 NETWORK ANALYZER  ·  Auditoría técnica de red multiplataforma
================================================================================
Recolecta el máximo de parámetros posibles de la red local y la conexión a
Internet, audita la IP pública (geo / ASN / ISP / blacklists), descubre hosts
vivos en la LAN y mide la conectividad. Genera un dashboard HTML interactivo.

Sólo usa la librería estándar de Python (no requiere pip install).
Funciona en Linux, macOS y Windows. Sin privilegios suele cubrir el ~90%;
con sudo/admin el escaneo ARP y algunos detalles son más completos.

USO:
    python3 network_analyzer.py                  # análisis completo + HTML
    python3 network_analyzer.py --no-lan         # omite el escaneo de la LAN
    python3 network_analyzer.py --no-public      # omite consultas a Internet
    python3 network_analyzer.py --fast           # menos pruebas, más rápido
    python3 network_analyzer.py -o reporte.html  # nombre de salida
    python3 network_analyzer.py --json datos.json# vuelca también JSON crudo

AVISO LEGAL: usa esta herramienta SÓLO en redes propias o donde tengas permiso
explícito. El escaneo de redes ajenas puede ser ilegal en tu jurisdicción.
================================================================================
"""

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
import time
import urllib.request
import uuid

IS_WIN = platform.system().lower().startswith("win")
IS_MAC = platform.system().lower() == "darwin"
IS_LINUX = platform.system().lower() == "linux"

# Salida UTF-8 robusta: evita UnicodeEncodeError en consolas Windows (cp1252)
# al imprimir el banner y símbolos como ✔ / ⚠ / caracteres de caja.
for _stream in ("stdout", "stderr"):
    try:
        getattr(sys, _stream).reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# --------------------------------------------------------------------------- #
# Utilidades                                                                   #
# --------------------------------------------------------------------------- #

def run(cmd, timeout=8):
    """Ejecuta un comando del sistema y devuelve stdout (o '' si falla)."""
    try:
        out = subprocess.run(
            cmd, shell=isinstance(cmd, str),
            capture_output=True, text=True, timeout=timeout,
            errors="replace",
        )
        return (out.stdout or "") + (("\n" + out.stderr) if out.stderr else "")
    except Exception:
        return ""

def have(binname):
    return shutil.which(binname) is not None

def http_json(url, timeout=6):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "net-analyzer/1.0"})
        ctx = ssl.create_default_context()
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return json.loads(r.read().decode("utf-8", "replace"))
    except Exception:
        return None

def http_text(url, timeout=6):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "net-analyzer/1.0"})
        ctx = ssl.create_default_context()
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.read().decode("utf-8", "replace").strip()
    except Exception:
        return None

def section(title):
    print("\n" + "=" * 70)
    print(" " + title)
    print("=" * 70)

# --------------------------------------------------------------------------- #
# 1. Información del host / sistema                                            #
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
    # uptime / boot (best effort)
    try:
        if IS_LINUX and os.path.exists("/proc/uptime"):
            with open("/proc/uptime") as f:
                up = float(f.read().split()[0])
            info["uptime"] = human_secs(up)
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

def human_secs(s):
    s = int(s)
    d, s = divmod(s, 86400)
    h, s = divmod(s, 3600)
    m, s = divmod(s, 60)
    parts = []
    if d: parts.append(f"{d}d")
    if h: parts.append(f"{h}h")
    if m: parts.append(f"{m}m")
    parts.append(f"{s}s")
    return " ".join(parts)

# --------------------------------------------------------------------------- #
# 2. Interfaces de red                                                         #
# --------------------------------------------------------------------------- #

def primary_ip():
    """IP de la interfaz usada para salir a Internet (truco del socket UDP)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
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
    """Parsea ip/ifconfig/ipconfig para enumerar interfaces, IPs y MACs."""
    ifaces = {}

    def ensure(name):
        ifaces.setdefault(name, {"ipv4": [], "ipv6": [], "mac": None,
                                 "mtu": None, "state": None, "flags": []})
        return ifaces[name]

    if IS_LINUX and have("ip"):
        out = run(["ip", "-o", "addr"])
        for line in out.splitlines():
            parts = line.split()
            if len(parts) < 4:
                continue
            name = parts[1]
            d = ensure(name)
            if parts[2] == "inet":
                d["ipv4"].append(parts[3])
            elif parts[2] == "inet6":
                d["ipv6"].append(parts[3])
        link = run(["ip", "-o", "link"])
        for line in link.splitlines():
            m = re.match(r"\d+:\s+([^:@]+)[:@]", line)
            if not m:
                continue
            name = m.group(1).strip()
            d = ensure(name)
            mtu = re.search(r"mtu (\d+)", line)
            if mtu: d["mtu"] = int(mtu.group(1))
            mac = re.search(r"link/\w+\s+([0-9a-f:]{17})", line)
            if mac: d["mac"] = mac.group(1)
            st = re.search(r"state (\w+)", line)
            if st: d["state"] = st.group(1)
            fl = re.search(r"<([^>]+)>", line)
            if fl: d["flags"] = fl.group(1).split(",")

    elif (IS_MAC or IS_LINUX) and have("ifconfig"):
        out = run(["ifconfig"])
        cur = None
        for line in out.splitlines():
            if line and not line[0].isspace():
                cur = line.split(":")[0].split()[0]
                d = ensure(cur)
                fl = re.search(r"<([^>]+)>", line)
                if fl: d["flags"] = fl.group(1).split(",")
                mtu = re.search(r"mtu (\d+)", line)
                if mtu: d["mtu"] = int(mtu.group(1))
            elif cur:
                d = ensure(cur)
                m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)(?:\s+netmask\s+(\S+))?", line)
                if m:
                    addr = m.group(1)
                    nm = m.group(2)
                    d["ipv4"].append(addr + (f"  netmask {nm}" if nm else ""))
                m6 = re.search(r"inet6 ([0-9a-f:]+)", line)
                if m6: d["ipv6"].append(m6.group(1))
                mac = re.search(r"ether ([0-9a-f:]{17})", line)
                if mac: d["mac"] = mac.group(1)
                if "status:" in line:
                    d["state"] = line.split("status:")[1].strip()

    elif IS_WIN:
        out = run("ipconfig /all", timeout=12)
        cur = None
        for line in out.splitlines():
            if line and not line[0].isspace() and "adapter" in line.lower():
                cur = line.split("adapter", 1)[-1].strip().rstrip(":")
                ensure(cur)
            elif cur:
                d = ensure(cur)
                if "Physical Address" in line or "Dirección física" in line:
                    mac = re.search(r"([0-9A-Fa-f]{2}[-:]){5}[0-9A-Fa-f]{2}", line)
                    if mac: d["mac"] = mac.group(0).replace("-", ":").lower()
                elif "IPv4" in line:
                    ip = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
                    if ip: d["ipv4"].append(ip.group(1))
                elif "IPv6" in line and "::" in line:
                    ip = re.search(r"([0-9A-Fa-f:]+::[0-9A-Fa-f:]+)", line)
                    if ip: d["ipv6"].append(ip.group(1))

    # Fallback mínimo
    if not ifaces:
        ensure("primary")["ipv4"].append(primary_ip())
        ifaces["primary"]["mac"] = mac_self()
    return ifaces

# --------------------------------------------------------------------------- #
# 3. Gateway / rutas / DNS / ARP                                              #
# --------------------------------------------------------------------------- #

def collect_gateway():
    gw = {"default": None, "raw": ""}
    if IS_LINUX and have("ip"):
        out = run(["ip", "route"])
        gw["raw"] = out
        m = re.search(r"default via (\S+)", out)
        if m: gw["default"] = m.group(1)
    elif IS_MAC or (not IS_WIN and have("route")):
        out = run(["route", "-n", "get", "default"]) if IS_MAC else run("ip route")
        gw["raw"] = out
        m = re.search(r"gateway:\s+(\S+)", out)
        if m: gw["default"] = m.group(1)
    elif IS_WIN:
        out = run("route print 0.0.0.0")
        gw["raw"] = out
        m = re.search(r"0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)", out)
        if m: gw["default"] = m.group(1)
    return gw

def collect_routes():
    if IS_WIN:
        return run("route print")
    if have("ip"):
        return run(["ip", "route"])
    return run(["netstat", "-rn"])

def collect_dns():
    servers = []
    raw = ""
    if IS_WIN:
        raw = run("ipconfig /all", timeout=12)
        for m in re.finditer(r"DNS Servers[^:]*:\s*(\d+\.\d+\.\d+\.\d+)", raw):
            servers.append(m.group(1))
        for line in raw.splitlines():
            ip = re.match(r"\s+(\d+\.\d+\.\d+\.\d+)\s*$", line)
            if ip and len(servers) and ip.group(1) not in servers:
                servers.append(ip.group(1))
    else:
        if os.path.exists("/etc/resolv.conf"):
            raw = open("/etc/resolv.conf").read()
            for m in re.finditer(r"nameserver\s+(\S+)", raw):
                servers.append(m.group(1))
        if IS_MAC and have("scutil"):
            extra = run("scutil --dns")
            for m in re.finditer(r"nameserver\[\d+\]\s*:\s*(\S+)", extra):
                if m.group(1) not in servers:
                    servers.append(m.group(1))
            raw = raw + "\n" + extra
    return {"servers": list(dict.fromkeys(servers)), "raw": raw.strip()}

def collect_arp():
    out = run("arp -a", timeout=8) or run(["ip", "neigh"])
    entries = []
    for line in out.splitlines():
        ip = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
        mac = re.search(r"([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}", line)
        if ip and mac:
            entries.append({
                "ip": ip.group(1),
                "mac": mac.group(0).replace("-", ":").lower(),
                "vendor": oui_lookup(mac.group(0)),
            })
    # dedup
    seen, uniq = set(), []
    for e in entries:
        if e["ip"] not in seen:
            seen.add(e["ip"]); uniq.append(e)
    return uniq

# Mini base OUI (prefijos comunes). Para fabricantes desconocidos -> None.
OUI = {
    "00:00:0c": "Cisco", "00:1a:11": "Google", "00:1b:63": "Apple",
    "00:50:56": "VMware", "00:0c:29": "VMware", "08:00:27": "VirtualBox",
    "52:54:00": "QEMU/KVM", "b8:27:eb": "Raspberry Pi", "dc:a6:32": "Raspberry Pi",
    "00:1d:0f": "TP-Link", "ec:08:6b": "TP-Link", "00:18:e7": "Cameo/Netgear",
    "fc:fb:fb": "Cisco", "00:25:9c": "Cisco-Linksys", "ac:de:48": "Private",
    "f4:f5:e8": "Google", "3c:5a:b4": "Google", "a4:77:33": "Google",
    "00:09:0f": "Fortinet", "90:9a:4a": "TP-Link", "e4:5f:01": "Raspberry Pi",
}
def oui_lookup(mac):
    pref = mac.lower().replace("-", ":")[:8]
    return OUI.get(pref)

# --------------------------------------------------------------------------- #
# 4. Puertos / sockets en escucha                                             #
# --------------------------------------------------------------------------- #

def collect_listening():
    ports = []
    if have("ss"):
        out = run(["ss", "-tulnp"], timeout=8)
    elif IS_WIN:
        out = run("netstat -ano", timeout=10)
    else:
        out = run(["netstat", "-an"], timeout=10)
    for line in out.splitlines():
        if "LISTEN" not in line.upper() and "udp" not in line.lower():
            if not (IS_WIN and ("LISTENING" in line)):
                continue
        proto = "tcp" if "tcp" in line.lower() else ("udp" if "udp" in line.lower() else "?")
        m = re.search(r"[\d\.\*]+[:\.](\d+)\s", line)
        addr = re.search(r"((?:\d+\.\d+\.\d+\.\d+|\[?::\]?|\*|0\.0\.0\.0)[:\.]\d+)", line)
        if m:
            port = int(m.group(1))
            ports.append({
                "proto": proto, "port": port,
                "addr": addr.group(1) if addr else "?",
                "service": WELL_KNOWN.get(port, ""),
            })
    # dedup por (proto, port, addr)
    seen, uniq = set(), []
    for p in ports:
        k = (p["proto"], p["port"], p["addr"])
        if k not in seen:
            seen.add(k); uniq.append(p)
    uniq.sort(key=lambda x: (x["proto"], x["port"]))
    return uniq

WELL_KNOWN = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP", 80: "HTTP",
    110: "POP3", 111: "RPC", 123: "NTP", 135: "MS-RPC", 137: "NetBIOS",
    138: "NetBIOS", 139: "NetBIOS", 143: "IMAP", 161: "SNMP", 162: "SNMP",
    389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS", 514: "Syslog",
    515: "LPD", 587: "SMTP-sub", 631: "IPP/CUPS", 636: "LDAPS", 873: "rsync",
    993: "IMAPS", 995: "POP3S", 1080: "SOCKS", 1194: "OpenVPN", 1433: "MSSQL",
    1521: "Oracle", 1723: "PPTP", 1883: "MQTT", 2049: "NFS", 2375: "Docker",
    2376: "Docker-TLS", 3000: "Dev/Grafana", 3306: "MySQL", 3389: "RDP",
    3478: "STUN", 5000: "UPnP/Dev", 5060: "SIP", 5353: "mDNS", 5432: "PostgreSQL",
    5555: "ADB", 5900: "VNC", 5984: "CouchDB", 6379: "Redis", 6443: "Kubernetes",
    7547: "TR-069", 8000: "HTTP-alt", 8080: "HTTP-proxy", 8443: "HTTPS-alt",
    8888: "HTTP-alt", 9000: "Dev", 9090: "Prometheus", 9200: "Elasticsearch",
    11211: "Memcached", 27017: "MongoDB", 32400: "Plex", 51820: "WireGuard",
}

# --------------------------------------------------------------------------- #
# 5. Auditoría de IP pública                                                   #
# --------------------------------------------------------------------------- #

def collect_public(fast=False):
    pub = {"ip": None, "geo": {}, "rdns": None, "blacklists": [], "open": []}
    # Varios proveedores como fallback
    pub["ip"] = (http_text("https://api.ipify.org")
                 or http_text("https://ifconfig.me/ip")
                 or http_text("https://icanhazip.com"))
    if not pub["ip"]:
        return pub
    # Geolocalización + ASN/ISP
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
    # rDNS
    try:
        pub["rdns"] = socket.gethostbyaddr(pub["ip"])[0]
    except Exception:
        pub["rdns"] = None
    # Blacklists DNSBL
    if not fast:
        pub["blacklists"] = check_blacklists(pub["ip"])
    return pub

DNSBLS = [
    "zen.spamhaus.org", "bl.spamcop.net", "b.barracudacentral.org",
    "dnsbl.sorbs.net", "cbl.abuseat.org",
]
def check_blacklists(ip):
    results = []
    try:
        rev = ".".join(reversed(ip.split(".")))
    except Exception:
        return results
    for bl in DNSBLS:
        host = f"{rev}.{bl}"
        try:
            socket.setdefaulttimeout(3)
            socket.gethostbyname(host)
            results.append({"lista": bl, "estado": "LISTADO ⚠"})
        except socket.gaierror:
            results.append({"lista": bl, "estado": "limpio"})
        except Exception:
            results.append({"lista": bl, "estado": "sin respuesta"})
    socket.setdefaulttimeout(None)
    return results

# --------------------------------------------------------------------------- #
# 6. Escaneo de la LAN (ping sweep concurrente + cruce con ARP)               #
# --------------------------------------------------------------------------- #

def guess_subnet(ifaces):
    """Devuelve una red /24 razonable a partir de la IP primaria."""
    ip = primary_ip()
    try:
        net = ipaddress.ip_network(ip + "/24", strict=False)
        return net
    except Exception:
        return None

def ping_host(ip, timeout=1):
    if IS_WIN:
        cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(int(timeout)), ip]
    out = run(cmd, timeout=timeout + 2)
    if not out:
        return None
    alive = ("ttl=" in out.lower()) or ("bytes from" in out.lower()) or \
            ("Reply from" in out and "unreachable" not in out.lower())
    if not alive:
        return None
    m = re.search(r"time[=<]\s*([\d\.]+)\s*ms", out)
    rtt = float(m.group(1)) if m else None
    return {"ip": ip, "rtt_ms": rtt}

def collect_lan(net, arp, fast=False, workers=128):
    if net is None:
        return []
    hosts = [str(h) for h in net.hosts()]
    if fast:
        hosts = hosts[:64]
    alive = []
    arp_map = {e["ip"]: e for e in arp}
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(ping_host, h): h for h in hosts}
        for f in concurrent.futures.as_completed(futs):
            r = f.result()
            if r:
                ip = r["ip"]
                hostname = None
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                except Exception:
                    pass
                a = arp_map.get(ip, {})
                alive.append({
                    "ip": ip, "rtt_ms": r["rtt_ms"], "hostname": hostname,
                    "mac": a.get("mac"), "vendor": a.get("vendor"),
                })
    # incluir vecinos ARP que no respondieron a ping
    found = {h["ip"] for h in alive}
    for e in arp:
        if e["ip"] not in found and ipaddress.ip_address(e["ip"]) in net:
            alive.append({"ip": e["ip"], "rtt_ms": None, "hostname": None,
                          "mac": e["mac"], "vendor": e["vendor"]})
    alive.sort(key=lambda x: tuple(int(p) for p in x["ip"].split(".")))
    return alive

# --------------------------------------------------------------------------- #
# 7. Pruebas de conectividad                                                   #
# --------------------------------------------------------------------------- #

def ping_stats(host, count=10, fast=False):
    if fast:
        count = 4
    if IS_WIN:
        cmd = ["ping", "-n", str(count), host]
    else:
        cmd = ["ping", "-c", str(count), host]
    out = run(cmd, timeout=count * 2 + 5)
    res = {"host": host, "raw": out.strip(), "loss": None,
           "min": None, "avg": None, "max": None, "mdev": None}
    mloss = re.search(r"([\d\.]+)%\s*(packet )?loss", out)
    if mloss: res["loss"] = float(mloss.group(1))
    mr = re.search(r"=\s*([\d\.]+)/([\d\.]+)/([\d\.]+)(?:/([\d\.]+))?", out)
    if mr:
        res["min"], res["avg"], res["max"] = mr.group(1), mr.group(2), mr.group(3)
        res["mdev"] = mr.group(4)
    else:  # Windows
        mw = re.search(r"Minimum = (\d+)ms.*Maximum = (\d+)ms.*Average = (\d+)ms",
                       out, re.S)
        if mw:
            res["min"], res["max"], res["avg"] = mw.group(1), mw.group(2), mw.group(3)
    return res

def dns_timing(domains):
    out = []
    for d in domains:
        t0 = time.time()
        try:
            ip = socket.gethostbyname(d)
            ms = (time.time() - t0) * 1000
            out.append({"dominio": d, "ip": ip, "ms": round(ms, 1)})
        except Exception:
            out.append({"dominio": d, "ip": None, "ms": None})
    return out

def traceroute(host, fast=False):
    if fast:
        return ""
    if IS_WIN:
        return run(["tracert", "-d", "-h", "20", host], timeout=40)
    if have("traceroute"):
        return run(["traceroute", "-n", "-m", "20", "-w", "1", host], timeout=40)
    return ""

def tcp_connect_ms(host, port=443, timeout=4):
    t0 = time.time()
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.close()
        return round((time.time() - t0) * 1000, 1)
    except Exception:
        return None

def mtu_to(host, fast=False):
    """Path MTU discovery aproximado con ping y bit DF."""
    if fast:
        return None
    lo, hi, best = 1200, 1500, None
    for size in (1472, 1492, 1400, 1300):  # payloads típicos
        if IS_WIN:
            cmd = ["ping", "-n", "1", "-f", "-l", str(size), host]
        elif IS_MAC:
            cmd = ["ping", "-c", "1", "-D", "-s", str(size), host]
        else:
            cmd = ["ping", "-c", "1", "-M", "do", "-s", str(size), host]
        out = run(cmd, timeout=5).lower()
        if out and "ttl=" in out and "frag" not in out and "too long" not in out:
            best = size + 28  # + cabeceras IP(20)+ICMP(8)
            break
    return best

def collect_connectivity(fast=False):
    targets = ["1.1.1.1", "8.8.8.8"]
    conn = {}
    conn["ping"] = [ping_stats(t, fast=fast) for t in targets]
    conn["dns"] = dns_timing(["google.com", "cloudflare.com", "github.com",
                              "wikipedia.org"])
    conn["tcp443"] = {h: tcp_connect_ms(h, 443)
                      for h in ["google.com", "cloudflare.com", "github.com"]}
    conn["mtu"] = mtu_to("1.1.1.1", fast=fast)
    conn["traceroute"] = traceroute("1.1.1.1", fast=fast)
    return conn

# --------------------------------------------------------------------------- #
# 8. Dashboard HTML                                                            #
# --------------------------------------------------------------------------- #

def esc(x):
    if x is None:
        return "<span class='muted'>—</span>"
    return (str(x).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))

def kv_table(d):
    rows = "".join(
        f"<tr><th>{esc(k)}</th><td>{esc(v)}</td></tr>"
        for k, v in d.items() if v not in (None, "", [], {}))
    return f"<table class='kv'>{rows}</table>"

def build_html(data):
    host = data["host"]
    pub = data.get("public") or {}
    geo = pub.get("geo") or {}
    ts = host.get("timestamp")

    # --- header stat cards ---
    pub_ip = pub.get("ip") or "—"
    loc = ", ".join(filter(None, [geo.get("ciudad"), geo.get("país")])) or "—"
    isp = geo.get("isp") or "—"
    asn = geo.get("asn") or "—"
    n_ifaces = len(data["interfaces"])
    n_lan = len(data.get("lan") or [])
    n_ports = len(data.get("listening") or [])
    gw = (data.get("gateway") or {}).get("default") or "—"

    cards = f"""
    <div class="cards">
      <div class="card"><div class="lbl">IP pública</div><div class="val">{esc(pub_ip)}</div></div>
      <div class="card"><div class="lbl">Ubicación</div><div class="val sm">{esc(loc)}</div></div>
      <div class="card"><div class="lbl">ISP / ASN</div><div class="val sm">{esc(isp)}<br><span class='muted'>{esc(asn)}</span></div></div>
      <div class="card"><div class="lbl">Gateway</div><div class="val">{esc(gw)}</div></div>
      <div class="card"><div class="lbl">Interfaces</div><div class="val">{n_ifaces}</div></div>
      <div class="card"><div class="lbl">Hosts LAN</div><div class="val">{n_lan}</div></div>
      <div class="card"><div class="lbl">Puertos escucha</div><div class="val">{n_ports}</div></div>
    </div>"""

    # --- interfaces ---
    iface_html = ""
    for name, d in data["interfaces"].items():
        v4 = "<br>".join(esc(x) for x in d["ipv4"]) or "—"
        v6 = "<br>".join(esc(x) for x in d["ipv6"]) or "—"
        iface_html += f"""
        <div class="iface">
          <h4>{esc(name)} <span class="badge">{esc(d.get('state') or '')}</span></h4>
          <table class="kv">
            <tr><th>IPv4</th><td>{v4}</td></tr>
            <tr><th>IPv6</th><td>{v6}</td></tr>
            <tr><th>MAC</th><td>{esc(d.get('mac'))}</td></tr>
            <tr><th>MTU</th><td>{esc(d.get('mtu'))}</td></tr>
            <tr><th>Flags</th><td>{esc(', '.join(d.get('flags') or []))}</td></tr>
          </table>
        </div>"""

    # --- public detail ---
    geo_html = kv_table(geo) if geo else "<p class='muted'>Sin datos públicos.</p>"
    bl = pub.get("blacklists") or []
    bl_rows = "".join(
        f"<tr><td>{esc(b['lista'])}</td><td class='{ 'bad' if 'LISTADO' in b['estado'] else 'ok'}'>{esc(b['estado'])}</td></tr>"
        for b in bl)
    bl_html = (f"<table class='data'><thead><tr><th>DNSBL</th><th>Estado</th></tr></thead><tbody>{bl_rows}</tbody></table>"
               if bl else "<p class='muted'>No evaluado.</p>")

    # --- DNS ---
    dns = data.get("dns") or {}
    dns_html = "".join(f"<span class='chip'>{esc(s)}</span>" for s in dns.get("servers", [])) or "<span class='muted'>—</span>"

    # --- listening ports ---
    lp = data.get("listening") or []
    lp_rows = "".join(
        f"<tr><td>{esc(p['proto'])}</td><td>{esc(p['port'])}</td><td>{esc(p['addr'])}</td><td>{esc(p['service'])}</td></tr>"
        for p in lp)
    lp_html = (f"<table class='data'><thead><tr><th>Proto</th><th>Puerto</th><th>Dirección</th><th>Servicio</th></tr></thead><tbody>{lp_rows}</tbody></table>"
               if lp else "<p class='muted'>Sin puertos en escucha detectados.</p>")

    # --- LAN ---
    lan = data.get("lan") or []
    lan_rows = "".join(
        f"<tr><td>{esc(h['ip'])}</td><td>{esc(h.get('hostname'))}</td><td>{esc(h.get('mac'))}</td><td>{esc(h.get('vendor'))}</td><td>{esc(h.get('rtt_ms'))}</td></tr>"
        for h in lan)
    lan_html = (f"<table class='data'><thead><tr><th>IP</th><th>Hostname</th><th>MAC</th><th>Fabricante</th><th>RTT (ms)</th></tr></thead><tbody>{lan_rows}</tbody></table>"
                if lan else "<p class='muted'>Escaneo LAN omitido o sin hosts.</p>")

    # --- ARP ---
    arp = data.get("arp") or []
    arp_rows = "".join(
        f"<tr><td>{esc(a['ip'])}</td><td>{esc(a['mac'])}</td><td>{esc(a.get('vendor'))}</td></tr>"
        for a in arp)
    arp_html = (f"<table class='data'><thead><tr><th>IP</th><th>MAC</th><th>Fabricante</th></tr></thead><tbody>{arp_rows}</tbody></table>"
                if arp else "<p class='muted'>Tabla ARP vacía.</p>")

    # --- connectivity ---
    conn = data.get("connectivity") or {}
    ping_rows = "".join(
        f"<tr><td>{esc(p['host'])}</td><td>{esc(p['loss'])}%</td><td>{esc(p['min'])}</td><td>{esc(p['avg'])}</td><td>{esc(p['max'])}</td><td>{esc(p.get('mdev'))}</td></tr>"
        for p in conn.get("ping", []))
    ping_html = (f"<table class='data'><thead><tr><th>Destino</th><th>Pérdida</th><th>Min</th><th>Avg</th><th>Max</th><th>Jitter</th></tr></thead><tbody>{ping_rows}</tbody></table>"
                 if ping_rows else "")
    dnsT_rows = "".join(
        f"<tr><td>{esc(d['dominio'])}</td><td>{esc(d['ip'])}</td><td>{esc(d['ms'])}</td></tr>"
        for d in conn.get("dns", []))
    dnsT_html = f"<table class='data'><thead><tr><th>Dominio</th><th>Resuelto</th><th>ms</th></tr></thead><tbody>{dnsT_rows}</tbody></table>"
    tcp_rows = "".join(f"<tr><td>{esc(h)}:443</td><td>{esc(v)}</td></tr>" for h, v in (conn.get("tcp443") or {}).items())
    tcp_html = f"<table class='data'><thead><tr><th>Destino</th><th>Handshake TCP (ms)</th></tr></thead><tbody>{tcp_rows}</tbody></table>"
    mtu_html = f"<p>MTU estimada hacia Internet: <b>{esc(conn.get('mtu'))}</b> bytes</p>"
    tr_html = f"<pre class='term'>{esc(conn.get('traceroute'))}</pre>" if conn.get("traceroute") else "<p class='muted'>Traceroute omitido.</p>"

    routes_html = f"<pre class='term'>{esc(data.get('routes'))}</pre>"

    html = f"""<!DOCTYPE html>
<html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Network Analyzer · {esc(host.get('hostname'))}</title>
<style>
:root {{
  --bg:#0b0f17; --panel:#121826; --panel2:#0e1420; --line:#1f2a3d;
  --txt:#dbe4f0; --muted:#6b7a93; --acc:#37d39a; --acc2:#4aa3ff;
  --bad:#ff5d6c; --ok:#37d39a; --warn:#ffb454; --mono:'SF Mono',ui-monospace,Menlo,Consolas,monospace;
}}
*{{box-sizing:border-box}}
body{{margin:0;background:var(--bg);color:var(--txt);font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;font-size:14px;line-height:1.5}}
header{{padding:28px 32px;border-bottom:1px solid var(--line);background:linear-gradient(180deg,#101725,#0b0f17)}}
header h1{{margin:0;font-size:22px;letter-spacing:.5px}}
header h1 .dot{{color:var(--acc)}}
header .meta{{color:var(--muted);margin-top:6px;font-family:var(--mono);font-size:12px}}
.wrap{{max-width:1180px;margin:0 auto;padding:0 32px 60px}}
.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:14px;margin:26px 0}}
.card{{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:16px 18px}}
.card .lbl{{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:1px}}
.card .val{{font-size:22px;font-weight:600;margin-top:6px;font-family:var(--mono);color:var(--acc)}}
.card .val.sm{{font-size:14px;color:var(--txt);font-family:inherit}}
section{{background:var(--panel);border:1px solid var(--line);border-radius:14px;margin:18px 0;overflow:hidden}}
section>h2{{margin:0;padding:16px 22px;font-size:15px;border-bottom:1px solid var(--line);background:var(--panel2);cursor:pointer;display:flex;justify-content:space-between;align-items:center}}
section>h2 .num{{color:var(--muted);font-family:var(--mono);font-size:12px;font-weight:400}}
section .body{{padding:20px 22px}}
.grid2{{display:grid;grid-template-columns:1fr 1fr;gap:20px}}
@media(max-width:860px){{.grid2{{grid-template-columns:1fr}}}}
table{{width:100%;border-collapse:collapse;font-size:13px}}
table.kv th{{text-align:left;color:var(--muted);font-weight:500;width:38%;padding:6px 8px;vertical-align:top}}
table.kv td{{padding:6px 8px;font-family:var(--mono);word-break:break-all}}
table.data th{{text-align:left;color:var(--muted);font-weight:600;padding:8px 10px;border-bottom:1px solid var(--line);font-size:11px;text-transform:uppercase;letter-spacing:.5px}}
table.data td{{padding:7px 10px;border-bottom:1px solid #141d2c;font-family:var(--mono)}}
table.data tr:hover td{{background:#0e1726}}
.iface{{background:var(--panel2);border:1px solid var(--line);border-radius:10px;padding:14px;margin-bottom:12px}}
.iface h4{{margin:0 0 8px;font-family:var(--mono);color:var(--acc2)}}
.badge{{font-size:10px;background:#1d3a2e;color:var(--acc);padding:2px 8px;border-radius:20px;margin-left:6px;vertical-align:middle}}
.chip{{display:inline-block;background:#152133;border:1px solid var(--line);color:var(--acc2);font-family:var(--mono);padding:3px 10px;border-radius:20px;margin:3px}}
.muted{{color:var(--muted)}}
.bad{{color:var(--bad);font-weight:600}} .ok{{color:var(--ok)}}
pre.term{{background:#070b12;border:1px solid var(--line);border-radius:10px;padding:14px;overflow:auto;font-family:var(--mono);font-size:12px;color:#9fd6c0;max-height:340px}}
.legal{{color:var(--muted);font-size:11px;text-align:center;margin-top:30px;line-height:1.6}}
.collapsed .body{{display:none}}
</style></head>
<body>
<header>
  <h1><span class="dot">▍</span> Network Analyzer <span class="muted" style="font-weight:400">· auditoría técnica</span></h1>
  <div class="meta">host: {esc(host.get('hostname'))} · {esc(host.get('os'))} {esc(host.get('os_release'))} · {esc(host.get('arch'))} · generado {esc(ts)}</div>
</header>
<div class="wrap">
  {cards}

  <section><h2>Sistema / Host <span class="num">01</span></h2><div class="body">{kv_table(host)}</div></section>

  <section><h2>Interfaces de red <span class="num">02</span></h2><div class="body">{iface_html or "<p class='muted'>—</p>"}</div></section>

  <section><h2>Gateway · DNS · Rutas <span class="num">03</span></h2><div class="body">
    <div class="grid2">
      <div>
        <p><b>Gateway por defecto:</b> <span class="chip">{esc(gw)}</span></p>
        <p><b>Servidores DNS:</b><br>{dns_html}</p>
      </div>
      <div>{kv_table({'Reverse público': geo.get('reverse'), 'rDNS': pub.get('rdns')})}</div>
    </div>
    <h4 class="muted" style="margin-top:18px">Tabla de rutas</h4>
    {routes_html}
  </div></section>

  <section><h2>IP pública · Geo · ASN <span class="num">04</span></h2><div class="body">
    <div class="grid2">
      <div>{geo_html}</div>
      <div>
        <h4 class="muted">Reputación (DNSBL)</h4>
        {bl_html}
      </div>
    </div>
  </div></section>

  <section><h2>Puertos en escucha (local) <span class="num">05</span></h2><div class="body">{lp_html}</div></section>

  <section><h2>Hosts en la LAN <span class="num">06</span></h2><div class="body">{lan_html}</div></section>

  <section><h2>Tabla ARP / vecinos <span class="num">07</span></h2><div class="body">{arp_html}</div></section>

  <section><h2>Pruebas de conectividad <span class="num">08</span></h2><div class="body">
    <div class="grid2">
      <div><h4 class="muted">Latencia ICMP</h4>{ping_html}</div>
      <div><h4 class="muted">Resolución DNS</h4>{dnsT_html}</div>
    </div>
    <div class="grid2" style="margin-top:18px">
      <div><h4 class="muted">Handshake TCP/443</h4>{tcp_html}</div>
      <div><h4 class="muted">Path MTU</h4>{mtu_html}</div>
    </div>
    <h4 class="muted" style="margin-top:18px">Traceroute → 1.1.1.1</h4>
    {tr_html}
  </div></section>

  <div class="legal">
    Generado por network_analyzer.py · Úsalo sólo en redes propias o con autorización explícita.<br>
    El escaneo de redes de terceros sin permiso puede infringir la ley.
  </div>
</div>
<script>
document.querySelectorAll('section > h2').forEach(h=>{{
  h.addEventListener('click',()=>h.parentElement.classList.toggle('collapsed'));
}});
</script>
</body></html>"""
    return html

# --------------------------------------------------------------------------- #
# Orquestador                                                                  #
# --------------------------------------------------------------------------- #

def main():
    ap = argparse.ArgumentParser(description="Analizador / auditor de red multiplataforma")
    ap.add_argument("-o", "--output", default="network_report.html", help="archivo HTML de salida")
    ap.add_argument("--json", default=None, help="vuelca también los datos crudos en JSON")
    ap.add_argument("--no-lan", action="store_true", help="omite el escaneo de la LAN")
    ap.add_argument("--no-public", action="store_true", help="omite consultas a Internet")
    ap.add_argument("--fast", action="store_true", help="modo rápido (menos pruebas)")
    args = ap.parse_args()

    print("""
  ███╗   ██╗███████╗████████╗  ANALYZER
  ████╗  ██║██╔════╝╚══██╔══╝  auditoría técnica de red
  ██╔██╗ ██║█████╗     ██║     multiplataforma · stdlib
  ██║╚██╗██║██╔══╝     ██║
  ██║ ╚████║███████╗   ██║
  ╚═╝  ╚═══╝╚══════╝   ╚═╝""")
    print(f"  SO detectado: {platform.system()} {platform.release()}  ({platform.machine()})\n")

    data = {}

    section("01 · Host / sistema")
    data["host"] = collect_host()
    for k, v in data["host"].items():
        print(f"   {k:14}: {v}")

    section("02 · Interfaces de red")
    data["interfaces"] = collect_interfaces()
    for name, d in data["interfaces"].items():
        print(f"   {name}: ipv4={d['ipv4']} mac={d['mac']} mtu={d['mtu']} state={d['state']}")

    section("03 · Gateway / Rutas / DNS / ARP")
    data["gateway"] = collect_gateway()
    data["routes"] = collect_routes()
    data["dns"] = collect_dns()
    data["arp"] = collect_arp()
    print(f"   Gateway: {data['gateway']['default']}")
    print(f"   DNS:     {data['dns']['servers']}")
    print(f"   ARP:     {len(data['arp'])} entradas")

    section("04 · Puertos en escucha (local)")
    data["listening"] = collect_listening()
    print(f"   {len(data['listening'])} sockets en escucha")
    for p in data["listening"][:25]:
        print(f"   {p['proto']:4} {p['port']:>6}  {p['addr']:<24} {p['service']}")

    if not args.no_public:
        section("05 · Auditoría IP pública")
        data["public"] = collect_public(fast=args.fast)
        pub = data["public"]
        print(f"   IP pública: {pub.get('ip')}")
        g = pub.get("geo") or {}
        print(f"   Geo: {g.get('ciudad')}, {g.get('país')}  ISP: {g.get('isp')}  ASN: {g.get('asn')}")
        if pub.get("blacklists"):
            listados = [b['lista'] for b in pub['blacklists'] if 'LISTADO' in b['estado']]
            print(f"   Blacklists: {'⚠ ' + ', '.join(listados) if listados else 'limpio'}")
    else:
        data["public"] = {}

    if not args.no_lan:
        section("06 · Escaneo de la LAN")
        net = guess_subnet(data["interfaces"])
        print(f"   Subred objetivo: {net}")
        print("   Ping sweep en curso...")
        data["lan"] = collect_lan(net, data["arp"], fast=args.fast)
        print(f"   {len(data['lan'])} hosts detectados")
        for h in data["lan"]:
            print(f"   {h['ip']:<16} {h.get('hostname') or '':<28} {h.get('mac') or '':<18} {h.get('vendor') or ''}")
    else:
        data["lan"] = []

    section("07 · Pruebas de conectividad")
    data["connectivity"] = collect_connectivity(fast=args.fast)
    for p in data["connectivity"]["ping"]:
        print(f"   ping {p['host']}: loss={p['loss']}% avg={p['avg']}ms")
    print(f"   MTU estimada: {data['connectivity']['mtu']}")

    # ---- salida ----
    html = build_html(data)
    with open(args.output, "w", encoding="utf-8") as f:
        f.write(html)
    section("Reporte generado")
    print(f"   HTML: {os.path.abspath(args.output)}")
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2, default=str)
        print(f"   JSON: {os.path.abspath(args.json)}")
    print("\n   Abre el HTML en tu navegador. ✔\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[interrumpido]")
        sys.exit(1)
