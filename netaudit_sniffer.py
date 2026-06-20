#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
netaudit · sniffer  —  capturador y disector de paquetes (estilo Wireshark).

- Captura en vivo: raw sockets nativos en Linux (AF_PACKET, sin dependencias)
  o vía `tcpdump` del sistema (macOS y como respaldo en Linux).
- Disector: Ethernet / VLAN / ARP / IPv4 / IPv6 / TCP / UDP / ICMP / DNS.
- Lee y escribe ficheros .pcap estándar (abribles en el Wireshark de verdad).

Capturar tráfico en vivo requiere privilegios de administrador (sudo/root),
igual que Wireshark. El disector y el pcap se pueden usar sin privilegios.

Solo librería estándar de Python.
"""

import os
import platform
import re
import socket
import struct
import subprocess
import sys
import tempfile
import time

IS_WIN = platform.system().lower().startswith("win")
IS_MAC = platform.system().lower() == "darwin"
IS_LINUX = platform.system().lower() == "linux"

ETH_P_ALL = 0x0003
LINKTYPE_NULL = 0
LINKTYPE_ETHERNET = 1
LINKTYPE_LOOP = 108
LINKTYPE_RAW = 101

ETHERTYPES = {0x0800: "IPv4", 0x86DD: "IPv6", 0x0806: "ARP", 0x8100: "802.1Q"}
IP_PROTOS = {1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP", 41: "IPv6", 58: "ICMPv6", 89: "OSPF"}
DNS_TYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX",
             16: "TXT", 28: "AAAA", 33: "SRV", 35: "NAPTR", 257: "CAA"}
TCP_FLAGS = [(0x01, "FIN"), (0x02, "SYN"), (0x04, "RST"), (0x08, "PSH"),
             (0x10, "ACK"), (0x20, "URG"), (0x40, "ECE"), (0x80, "CWR")]

WELL_KNOWN = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP", 53: "DNS",
    67: "DHCP", 68: "DHCP", 80: "HTTP", 110: "POP3", 123: "NTP", 143: "IMAP",
    161: "SNMP", 443: "HTTPS", 445: "SMB", 587: "SMTP", 993: "IMAPS",
    995: "POP3S", 1900: "SSDP", 3306: "MySQL", 3389: "RDP", 5353: "mDNS",
    5432: "PostgreSQL", 8080: "HTTP", 8443: "HTTPS",
}


# --------------------------------------------------------------------------- #
# Utilidades                                                                  #
# --------------------------------------------------------------------------- #

def mac_str(b):
    return ":".join("%02x" % x for x in b)


def hexdump(data, width=16):
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i:i + width]
        hexpart = " ".join("%02x" % b for b in chunk)
        asciipart = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{i:04x}  {hexpart:<{width*3}}  {asciipart}")
    return "\n".join(lines)


def _svc(port):
    return WELL_KNOWN.get(port, "")


def _port_label(port):
    s = _svc(port)
    return f"{port}({s})" if s else str(port)


# --------------------------------------------------------------------------- #
# Disector                                                                    #
# --------------------------------------------------------------------------- #

def _parse_dns(payload):
    try:
        if len(payload) < 12:
            return None
        tid, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", payload[:12])
        qr = (flags >> 15) & 1
        off = 12
        labels = []
        while off < len(payload):
            ln = payload[off]
            if ln == 0:
                off += 1
                break
            if ln & 0xC0:  # puntero de compresión
                off += 2
                break
            off += 1
            labels.append(payload[off:off + ln].decode("latin-1", "replace"))
            off += ln
        qname = ".".join(labels) or "<root>"
        qtype = "?"
        if off + 4 <= len(payload):
            qt, qc = struct.unpack("!HH", payload[off:off + 4])
            qtype = DNS_TYPES.get(qt, str(qt))
        kind = "response" if qr else "query"
        return {"tid": tid, "kind": kind, "name": qname, "qtype": qtype,
                "info": f"DNS Standard {kind} 0x{tid:04x} {qtype} {qname}"}
    except Exception:
        return None


def _parse_transport(proto, data, src, dst):
    layer = {"proto": IP_PROTOS.get(proto, str(proto)), "info": ""}
    try:
        if proto == 6 and len(data) >= 20:  # TCP
            sport, dport, seq, ack = struct.unpack("!HHII", data[:12])
            offflags = struct.unpack("!H", data[12:14])[0]
            dataoff = (offflags >> 12) * 4
            flags = data[13]
            fl = [name for bit, name in TCP_FLAGS if flags & bit]
            layer.update({"sport": sport, "dport": dport, "seq": seq, "ack": ack,
                          "flags": fl, "service": _svc(dport) or _svc(sport)})
            payload = data[dataoff:]
            base = f"TCP {sport} → {dport} [{', '.join(fl) or '·'}] Seq={seq}"
            if 53 in (sport, dport):
                d = _parse_dns(payload)
                if d:
                    layer["dns"] = d; layer["info"] = d["info"]; return layer
            svc = _svc(dport) or _svc(sport)
            layer["info"] = (f"{svc}  " if svc else "") + base
            return layer
        if proto == 17 and len(data) >= 8:  # UDP
            sport, dport, ln, _ = struct.unpack("!HHHH", data[:8])
            layer.update({"sport": sport, "dport": dport,
                          "service": _svc(dport) or _svc(sport)})
            payload = data[8:]
            if 53 in (sport, dport) or 5353 in (sport, dport):
                d = _parse_dns(payload)
                if d:
                    layer["dns"] = d; layer["info"] = d["info"]; return layer
            svc = _svc(dport) or _svc(sport)
            layer["info"] = (f"{svc}  " if svc else "") + f"UDP {sport} → {dport} Len={ln}"
            return layer
        if proto in (1, 58):  # ICMP / ICMPv6
            t = data[0] if data else 0
            c = data[1] if len(data) > 1 else 0
            names = {8: "Echo (ping) request", 0: "Echo (ping) reply",
                     3: "Destination unreachable", 11: "Time exceeded",
                     5: "Redirect", 128: "Echo request", 129: "Echo reply"}
            layer["info"] = f"ICMP {names.get(t, 'Type %d' % t)} (type={t} code={c})"
            return layer
    except Exception:
        pass
    layer["info"] = f"{layer['proto']} {src} → {dst}"
    return layer


def _parse_ipv4(data):
    if len(data) < 20:
        return None
    ihl = (data[0] & 0x0F) * 4
    proto = data[9]
    src = socket.inet_ntoa(data[12:16])
    dst = socket.inet_ntoa(data[16:20])
    ttl = data[8]
    tl = struct.unpack("!H", data[2:4])[0]
    tr = _parse_transport(proto, data[ihl:], src, dst)
    return {"l3": "IPv4", "src": src, "dst": dst, "ttl": ttl, "len": tl, "transport": tr}


def _parse_ipv6(data):
    if len(data) < 40:
        return None
    nh = data[6]
    src = socket.inet_ntop(socket.AF_INET6, data[8:24])
    dst = socket.inet_ntop(socket.AF_INET6, data[24:40])
    hop = data[7]
    tr = _parse_transport(nh, data[40:], src, dst)
    return {"l3": "IPv6", "src": src, "dst": dst, "ttl": hop, "transport": tr}


def _parse_arp(data):
    try:
        htype, ptype, hlen, plen, op = struct.unpack("!HHBBH", data[:8])
        smac = mac_str(data[8:14]); sip = socket.inet_ntoa(data[14:18])
        tmac = mac_str(data[18:24]); tip = socket.inet_ntoa(data[24:28])
        if op == 1:
            info = f"ARP Who has {tip}? Tell {sip}"
        elif op == 2:
            info = f"ARP {sip} is at {smac}"
        else:
            info = f"ARP op={op}"
        return {"l3": "ARP", "src": sip, "dst": tip, "sender_mac": smac,
                "target_mac": tmac, "op": op, "transport": {"proto": "ARP", "info": info}}
    except Exception:
        return None


def parse_packet(raw, link_type=LINKTYPE_ETHERNET, ts=None, number=0):
    """Disecciona un frame en bruto y devuelve un dict listo para mostrar."""
    pkt = {"no": number, "time": ts or time.time(), "length": len(raw),
           "src": "?", "dst": "?", "proto": "?", "info": "",
           "eth_src": None, "eth_dst": None, "l3": None, "hex": hexdump(raw)}
    try:
        l3data, etype = None, None
        if link_type == LINKTYPE_ETHERNET:
            if len(raw) < 14:
                return pkt
            pkt["eth_dst"] = mac_str(raw[0:6]); pkt["eth_src"] = mac_str(raw[6:12])
            etype = struct.unpack("!H", raw[12:14])[0]
            off = 14
            if etype == 0x8100 and len(raw) >= 18:  # VLAN
                etype = struct.unpack("!H", raw[16:18])[0]; off = 18
            l3data = raw[off:]
        elif link_type in (LINKTYPE_NULL, LINKTYPE_LOOP):
            if len(raw) < 4:
                return pkt
            l3data = raw[4:]
            etype = 0x0800 if (l3data and (l3data[0] >> 4) == 4) else 0x86DD
        elif link_type == LINKTYPE_RAW:
            l3data = raw
            etype = 0x0800 if (raw and (raw[0] >> 4) == 4) else 0x86DD
        else:
            l3data = raw
            etype = 0x0800 if (raw and (raw[0] >> 4) == 4) else 0x86DD

        l3 = None
        if etype == 0x0800:
            l3 = _parse_ipv4(l3data)
        elif etype == 0x86DD:
            l3 = _parse_ipv6(l3data)
        elif etype == 0x0806:
            l3 = _parse_arp(l3data)

        if l3:
            pkt["l3"] = l3.get("l3")
            pkt["src"] = l3.get("src", pkt["eth_src"] or "?")
            pkt["dst"] = l3.get("dst", pkt["eth_dst"] or "?")
            tr = l3.get("transport") or {}
            pkt["proto"] = tr.get("proto", pkt["l3"] or "?")
            pkt["info"] = tr.get("info") or ""
            pkt["detail"] = l3
        else:
            pkt["proto"] = ETHERTYPES.get(etype, hex(etype) if etype else "?")
            pkt["src"] = pkt["eth_src"] or "?"
            pkt["dst"] = pkt["eth_dst"] or "?"
            pkt["info"] = f"{pkt['proto']} frame"
    except Exception as e:
        pkt["info"] = f"(no disecado: {e})"
    return pkt


# --------------------------------------------------------------------------- #
# pcap (lectura / escritura)                                                  #
# --------------------------------------------------------------------------- #

def write_pcap(path, packets, link_type=LINKTYPE_ETHERNET):
    """Guarda los frames en bruto en un .pcap estándar (abrible en Wireshark)."""
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, link_type))
        for p in packets:
            raw = p.get("raw")
            if raw is None:
                continue
            ts = p.get("time", time.time())
            sec = int(ts); usec = int((ts - sec) * 1_000_000)
            f.write(struct.pack("<IIII", sec, usec, len(raw), len(raw)))
            f.write(raw)


def _read_exact(stream, n):
    buf = b""
    while len(buf) < n:
        chunk = stream.read(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf


def read_pcap(path):
    """Lee un .pcap y devuelve la lista de paquetes disecados."""
    out = []
    with open(path, "rb") as f:
        gh = f.read(24)
        if len(gh) < 24:
            return out
        magic = struct.unpack("<I", gh[:4])[0]
        endian = "<" if magic == 0xA1B2C3D4 else ">"
        link_type = struct.unpack(endian + "I", gh[20:24])[0]
        n = 0
        while True:
            rh = f.read(16)
            if len(rh) < 16:
                break
            sec, usec, caplen, _ = struct.unpack(endian + "IIII", rh)
            data = f.read(caplen)
            if len(data) < caplen:
                break
            n += 1
            pkt = parse_packet(data, link_type, ts=sec + usec / 1e6, number=n)
            pkt["raw"] = data
            out.append(pkt)
    return out


# --------------------------------------------------------------------------- #
# Captura en vivo                                                             #
# --------------------------------------------------------------------------- #

def default_iface():
    """Interfaz de la ruta por defecto (la que de verdad tiene tráfico)."""
    try:
        if IS_MAC:
            out = subprocess.run(["route", "-n", "get", "default"],
                                 capture_output=True, text=True, timeout=4).stdout
            m = re.search(r"interface:\s*(\w+)", out)
            if m:
                return m.group(1)
            return "en0"
        if IS_LINUX:
            out = subprocess.run(["ip", "route", "get", "8.8.8.8"],
                                 capture_output=True, text=True, timeout=4).stdout
            m = re.search(r"dev\s+(\w+)", out)
            if m:
                return m.group(1)
            return "any"
    except Exception:
        pass
    return "en0" if IS_MAC else ("any" if IS_LINUX else None)


def _tcpdump_bin():
    for p in ("/usr/sbin/tcpdump", "/sbin/tcpdump"):
        if os.path.exists(p):
            return p
    return "tcpdump"


def cap_log_path():
    if IS_WIN:
        return os.path.join(tempfile.gettempdir(), "netaudit_capture.log")
    return "/tmp/netaudit_capture.log"


def get_capture_error():
    """Devuelve el último error de tcpdump (para diagnóstico en la GUI)."""
    try:
        p = cap_log_path()
        if os.path.exists(p):
            t = open(p, encoding="latin-1", errors="replace").read().strip()
            return t[-400:]
    except Exception:
        pass
    return ""


def _capture_afpacket(count, iface, on_packet, stop_event, duration):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    if iface and iface != "any":
        try:
            s.bind((iface, 0))
        except Exception:
            pass
    s.settimeout(1.0)
    pkts, n, t0 = [], 0, time.time()
    try:
        while (count == 0 or n < count):
            if stop_event is not None and stop_event.is_set():
                break
            if duration and time.time() - t0 > duration:
                break
            try:
                raw = s.recv(65535)
            except socket.timeout:
                continue
            n += 1
            pkt = parse_packet(raw, LINKTYPE_ETHERNET, ts=time.time(), number=n)
            pkt["raw"] = raw
            pkts.append(pkt)
            if on_packet:
                on_packet(pkt)
    finally:
        s.close()
    return pkts


def _capture_tcpdump(count, iface, bpf, on_packet, stop_event, duration):
    cmd = ["tcpdump", "-i", iface or default_iface() or "any",
           "-U", "-w", "-", "-n", "-s", "65535"]
    if count:
        cmd += ["-c", str(count)]
    if bpf:
        cmd += bpf.split()
    try:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    except FileNotFoundError:
        raise RuntimeError("tcpdump no está disponible en el sistema.")
    gh = _read_exact(p.stdout, 24)
    if len(gh) < 24:
        p.kill()
        raise PermissionError("No se pudo capturar (¿faltan permisos de administrador?).")
    magic = struct.unpack("<I", gh[:4])[0]
    endian = "<" if magic == 0xA1B2C3D4 else ">"
    link_type = struct.unpack(endian + "I", gh[20:24])[0]
    pkts, n, t0 = [], 0, time.time()
    try:
        while count == 0 or n < count:
            if stop_event is not None and stop_event.is_set():
                break
            if duration and time.time() - t0 > duration:
                break
            rh = _read_exact(p.stdout, 16)
            if len(rh) < 16:
                break
            sec, usec, caplen, _ = struct.unpack(endian + "IIII", rh)
            data = _read_exact(p.stdout, caplen)
            if len(data) < caplen:
                break
            n += 1
            pkt = parse_packet(data, link_type, ts=sec + usec / 1e6, number=n)
            pkt["raw"] = data
            pkts.append(pkt)
            if on_packet:
                on_packet(pkt)
    finally:
        try:
            p.terminate()
        except Exception:
            pass
    return pkts


def capture(count=50, iface=None, bpf=None, on_packet=None, stop_event=None, duration=None):
    """Captura `count` paquetes (0 = ilimitado hasta stop/duración).
    Selecciona el mejor backend disponible. Lanza PermissionError si no hay permisos."""
    if IS_LINUX and hasattr(socket, "AF_PACKET"):
        try:
            return _capture_afpacket(count, iface, on_packet, stop_event, duration)
        except PermissionError:
            raise PermissionError(
                "La captura necesita permisos de administrador. Ejecuta con sudo.")
        except Exception:
            pass  # caer a tcpdump
    return _capture_tcpdump(count, iface, bpf, on_packet, stop_event, duration)


def can_capture():
    """Devuelve (bool, motivo) indicando si se puede capturar en este sistema."""
    if IS_LINUX and hasattr(socket, "AF_PACKET"):
        try:
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
            s.close()
            return True, "raw socket nativo"
        except PermissionError:
            return False, "necesita sudo/root"
        except Exception as e:
            return False, str(e)
    if shutil_which("tcpdump"):
        return True, "tcpdump (puede pedir sudo)"
    return False, "sin backend de captura (instala tcpdump)"


def shutil_which(name):
    import shutil
    return shutil.which(name) is not None


# --------------------------------------------------------------------------- #
# Elevación de privilegios con diálogo nativo (1 botón) + captura a fichero   #
# --------------------------------------------------------------------------- #

def is_root():
    return hasattr(os, "geteuid") and os.geteuid() == 0


def privileged_backend():
    """Cómo capturar según el sistema:
    'root'         -> ya somos root, captura directa sin pedir nada
    'macos'        -> diálogo nativo de macOS (contraseña/Touch ID, 1 botón)
    'linux-pkexec' -> diálogo gráfico de Linux (pkexec)
    None           -> sin método disponible (usar CLI con sudo)"""
    if is_root():
        return "root"
    if IS_MAC and (os.path.exists("/usr/sbin/tcpdump") or shutil_which("tcpdump")):
        return "macos"
    if IS_LINUX and shutil_which("pkexec") and (shutil_which("tcpdump") or os.path.exists("/usr/sbin/tcpdump")):
        return "linux-pkexec"
    return None


def live_pcap_path():
    if IS_WIN:
        return os.path.join(tempfile.gettempdir(), "netaudit_live.pcap")
    return "/tmp/netaudit_live.pcap"


def stop_sentinel_path():
    if IS_WIN:
        return os.path.join(tempfile.gettempdir(), "netaudit_stop")
    return "/tmp/netaudit_stop"


def start_privileged_capture(iface, pcap_path, sentinel_path, bpf=None):
    """Lanza tcpdump como administrador en segundo plano, mostrando el diálogo
    nativo del sistema (un solo botón). Devuelve (ok, mensaje_error).
    La captura escribe en `pcap_path` hasta que aparezca `sentinel_path`."""
    iface = iface or default_iface() or "en0"
    log = cap_log_path()
    for p in (pcap_path, sentinel_path, log):
        try:
            os.remove(p)
        except OSError:
            pass
    flt = ""
    if bpf and re.match(r"^[\w\.\s]+$", bpf):  # solo filtros simples y seguros
        flt = " " + bpf.strip()
    user = os.environ.get("USER") or os.environ.get("LOGNAME") or ""
    zflag = f" -Z {user}" if re.match(r"^[\w.\-]+$", user or "") else ""
    tcp = _tcpdump_bin()
    # tcpdump escribe el pcap (legible por el usuario gracias a -Z) y su stderr al log
    inner = (f"{tcp} -i {iface}{zflag} -U -s 65535 -n -w {pcap_path}{flt} 2>{log} & "
             f"T=$!; while [ ! -f {sentinel_path} ]; do sleep 0.4; done; kill $T 2>/dev/null")
    shell = f"nohup sh -c '{inner}' </dev/null >/dev/null 2>&1 &"
    try:
        if IS_MAC:
            apple = f'do shell script "{shell}" with administrator privileges'
            r = subprocess.run(["osascript", "-e", apple], capture_output=True, text=True)
            return r.returncode == 0, (r.stderr or "").strip()
        if shutil_which("pkexec"):
            r = subprocess.run(["pkexec", "sh", "-c", shell], capture_output=True, text=True)
            return r.returncode == 0, (r.stderr or "").strip()
    except Exception as e:
        return False, str(e)
    return False, "sin método de elevación disponible"


def stop_privileged_capture(sentinel_path):
    try:
        open(sentinel_path, "w").close()
        return True
    except Exception:
        return False


def run_privileged_capture_sync(iface, pcap_path, count=1000, bpf=None):
    """Captura SÍNCRONA y robusta: tcpdump corre en primer plano bajo el diálogo
    nativo (sin '&', que macOS mataba). Bloquea hasta capturar `count` paquetes;
    mientras tanto, otro hilo va leyendo el .pcap en vivo. Devuelve (ok, error)."""
    iface = iface or default_iface() or "en0"
    log = cap_log_path()
    for p in (pcap_path, log):
        try:
            os.remove(p)
        except OSError:
            pass
    flt = ""
    if bpf and re.match(r"^[\w\.\s]+$", bpf):
        flt = " " + bpf.strip()
    user = os.environ.get("USER") or os.environ.get("LOGNAME") or ""
    zflag = f" -Z {user}" if re.match(r"^[\w.\-]+$", user or "") else ""
    tcp = _tcpdump_bin()
    inner = f"{tcp} -i {iface}{zflag} -U -s 65535 -n -c {count} -w {pcap_path}{flt} 2>{log}"
    try:
        if IS_MAC:
            apple = f'do shell script "{inner}" with administrator privileges'
            r = subprocess.run(["osascript", "-e", apple], capture_output=True, text=True)
            err = (r.stderr or "").strip() or get_capture_error()
            return r.returncode == 0, err
        if shutil_which("pkexec"):
            r = subprocess.run(["pkexec", "sh", "-c", inner], capture_output=True, text=True)
            err = (r.stderr or "").strip() or get_capture_error()
            return r.returncode == 0, err
    except Exception as e:
        return False, str(e)
    return False, "sin método de elevación disponible"


def read_pcap_stream(path, on_packet, stop_event, ready_timeout=14):
    """Lee un .pcap mientras se va escribiendo (captura en vivo a fichero)."""
    t0 = time.time()
    while not (os.path.exists(path) and os.path.getsize(path) >= 24):
        if (stop_event and stop_event.is_set()) or time.time() - t0 > ready_timeout:
            return
        time.sleep(0.2)
    f = open(path, "rb")
    try:
        gh = f.read(24)
        magic = struct.unpack("<I", gh[:4])[0]
        endian = "<" if magic == 0xA1B2C3D4 else ">"
        link_type = struct.unpack(endian + "I", gh[20:24])[0]
        n = 0
        idle = 0.0
        while not (stop_event and stop_event.is_set()):
            pos = f.tell()
            rh = f.read(16)
            if len(rh) < 16:
                f.seek(pos); time.sleep(0.2); idle += 0.2
                if idle > 30:
                    break
                continue
            sec, usec, caplen, _ = struct.unpack(endian + "IIII", rh)
            data = f.read(caplen)
            if len(data) < caplen:
                f.seek(pos); time.sleep(0.2); continue
            idle = 0.0
            n += 1
            pkt = parse_packet(data, link_type, ts=sec + usec / 1e6, number=n)
            pkt["raw"] = data
            if on_packet:
                on_packet(pkt)
    finally:
        f.close()


# --------------------------------------------------------------------------- #
# Reporte HTML de la captura (estilo Wireshark)                               #
# --------------------------------------------------------------------------- #

def _h(x):
    return (str(x).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


PROTO_COLOR = {"TCP": "#4aa3ff", "UDP": "#37d39a", "ARP": "#ffb454",
               "ICMP": "#c98bff", "DNS": "#37d39a", "IPv6": "#7aa2ff"}


def build_capture_html(packets, title="Captura de paquetes"):
    rows = ""
    import datetime as _dt
    for p in packets:
        col = PROTO_COLOR.get(p["proto"], "#9fb0c8")
        t = _dt.datetime.fromtimestamp(p["time"]).strftime("%H:%M:%S.%f")[:-3]
        detail = _h(p.get("hex", ""))
        rows += (f"<tr class='pk' onclick=\"this.nextElementSibling.classList.toggle('show')\">"
                 f"<td>{p['no']}</td><td>{t}</td><td>{_h(p['src'])}</td>"
                 f"<td>{_h(p['dst'])}</td><td style='color:{col};font-weight:600'>{_h(p['proto'])}</td>"
                 f"<td>{p['length']}</td><td>{_h(p['info'])}</td></tr>"
                 f"<tr class='det'><td colspan='7'><pre>{detail}</pre></td></tr>")
    return f"""<!DOCTYPE html><html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>{_h(title)}</title>
<style>
body{{margin:0;background:#0b0f17;color:#dbe4f0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;font-size:13px}}
header{{padding:20px 28px;border-bottom:1px solid #1f2a3d}}header h1{{margin:0;font-size:19px}}header h1 .d{{color:#37d39a}}
.meta{{color:#6b7a93;font-family:ui-monospace,Menlo,monospace;font-size:12px;margin-top:4px}}
.wrap{{padding:0 28px 50px}}
input{{background:#0e1420;border:1px solid #1f2a3d;color:#dbe4f0;border-radius:8px;padding:8px 12px;width:280px;margin:16px 0;font-family:ui-monospace,monospace}}
table{{width:100%;border-collapse:collapse;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12.5px}}
th{{text-align:left;color:#6b7a93;text-transform:uppercase;font-size:10px;letter-spacing:.5px;padding:8px 10px;border-bottom:1px solid #1f2a3d;position:sticky;top:0;background:#0b0f17}}
td{{padding:5px 10px;border-bottom:1px solid #121a28}}
tr.pk{{cursor:pointer}}tr.pk:hover td{{background:#0e1726}}
tr.det{{display:none}}tr.det.show{{display:table-row}}
tr.det pre{{background:#070b12;border:1px solid #1f2a3d;border-radius:8px;padding:12px;color:#9fd6c0;overflow:auto;margin:6px 0}}
.legal{{color:#6b7a93;font-size:11px;text-align:center;margin-top:24px}}
</style></head><body>
<header><h1><span class="d">▍</span> netaudit · {_h(title)}</h1>
<div class="meta">{len(packets)} paquetes · haz clic en una fila para ver el detalle/hex</div></header>
<div class="wrap">
<input id="f" placeholder="filtrar (IP, protocolo, puerto…)" onkeyup="flt()">
<table id="t"><thead><tr><th>No.</th><th>Tiempo</th><th>Origen</th><th>Destino</th><th>Proto</th><th>Long</th><th>Info</th></tr></thead>
<tbody>{rows}</tbody></table>
<div class="legal">netaudit sniffer · captura solo en redes propias o con autorización.</div></div>
<script>
function flt(){{const q=document.getElementById('f').value.toLowerCase();
document.querySelectorAll('#t tbody tr.pk').forEach(tr=>{{const m=tr.innerText.toLowerCase().includes(q);
tr.style.display=m?'':'none';if(!m)tr.nextElementSibling.classList.remove('show');}});}}
</script></body></html>"""


# --------------------------------------------------------------------------- #
# CLI mínima de prueba                                                        #
# --------------------------------------------------------------------------- #

def _main():
    import argparse
    ap = argparse.ArgumentParser(description="netaudit sniffer (mini-Wireshark)")
    ap.add_argument("-c", "--count", type=int, default=20)
    ap.add_argument("-i", "--iface", default=None)
    ap.add_argument("-f", "--filter", default=None)
    ap.add_argument("-w", "--pcap", default=None)
    ap.add_argument("-r", "--read", default=None, help="leer un .pcap")
    args = ap.parse_args()

    if args.read:
        pkts = read_pcap(args.read)
    else:
        ok, why = can_capture()
        if not ok:
            print(f"No se puede capturar: {why}")
            print("Sugerencia: ejecútalo con sudo (Linux/macOS).")
            return
        print(f"Capturando {args.count} paquetes... (Ctrl+C para parar)\n")
        def show(p):
            print(f"{p['no']:>4} {p['time']:.3f}  {p['src']:>22} → {p['dst']:<22} "
                  f"{p['proto']:<6} {p['length']:>5}  {p['info']}")
        pkts = capture(args.count, args.iface, args.filter, on_packet=show)

    if args.read:
        for p in pkts:
            print(f"{p['no']:>4} {p['time']:.3f}  {p['src']} → {p['dst']} "
                  f"{p['proto']} {p['length']}  {p['info']}")
    if args.pcap and pkts:
        write_pcap(args.pcap, pkts)
        print(f"\nGuardado en {args.pcap} ({len(pkts)} paquetes). Ábrelo en Wireshark.")


if __name__ == "__main__":
    _main()
