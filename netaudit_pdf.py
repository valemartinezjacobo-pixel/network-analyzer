#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
netaudit · generador de PDF en Python puro (sin dependencias).

Crea PDFs multipágina con título, secciones, pares clave/valor y tablas, usando
las fuentes base (Helvetica / Helvetica-Bold / Courier), sin incrustar nada.
Expone tres exportadores listos:

    pdf_audit_report(data, path)     -> informe de auditoría de red
    pdf_scan_report(hosts, path)     -> datos del escáner de red
    pdf_capture_report(packets, path)-> captura de paquetes (estilo Wireshark)
"""

import datetime

A4 = (595.0, 842.0)
TEAL = (0.13, 0.55, 0.45)
BLUE = (0.18, 0.45, 0.78)
DARK = (0.12, 0.14, 0.18)
GREY = (0.42, 0.47, 0.57)
RED = (0.85, 0.20, 0.27)
ORANGE = (0.78, 0.52, 0.10)


def _esc(s):
    s = str(s).encode("latin-1", "replace").decode("latin-1")
    return s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _trunc(s, width, size, mono=False):
    s = str(s)
    factor = 0.62 if mono else 0.52
    maxch = max(1, int(width / (size * factor)))
    if len(s) <= maxch:
        return s
    return s[:max(1, maxch - 2)] + ".."


class PDFDoc:
    def __init__(self, title="", page=A4, margin=50):
        self.w, self.h = page
        self.margin = margin
        self.pages = []
        self.cur = []
        self.y = self.h - margin
        self.title_text = title
        self._page_no = 0
        self._new_page()

    # ---- primitivas ---- #
    def _new_page(self):
        if self.cur:
            self.pages.append("".join(self.cur))
        self.cur = []
        self.y = self.h - self.margin
        self._page_no += 1
        # pie de página
        self._raw_text(self.margin, self.margin - 24,
                       f"netaudit · {self.title_text} · pág. {self._page_no}",
                       "F1", 8, GREY)

    def _raw_text(self, x, y, s, font, size, color):
        r, g, b = color
        self.cur.append(
            f"BT /{font} {size} Tf {r:.3f} {g:.3f} {b:.3f} rg "
            f"1 0 0 1 {x:.1f} {y:.1f} Tm ({_esc(s)}) Tj ET\n")

    def _rect(self, x, y, w, h, color):
        r, g, b = color
        self.cur.append(f"{r:.3f} {g:.3f} {b:.3f} rg {x:.1f} {y:.1f} {w:.1f} {h:.1f} re f\n")

    def _ensure(self, need):
        if self.y - need < self.margin + 6:
            self._new_page()

    # ---- API de alto nivel ---- #
    def title(self, s):
        self._ensure(40)
        self._rect(self.margin - 6, self.y - 4, 4, 26, TEAL)
        self._raw_text(self.margin + 6, self.y - 20, s, "F2", 20, DARK)
        self.y -= 40

    def heading(self, s, color=TEAL):
        self._ensure(26)
        self._raw_text(self.margin, self.y - 14, s, "F2", 13, color)
        self.y -= 24

    def line(self, s, size=10, font="F1", color=DARK):
        self._ensure(size + 5)
        self._raw_text(self.margin, self.y - size, s, font, size, color)
        self.y -= (size + 5)

    def spacer(self, h=8):
        self.y -= h

    def table(self, headers, rows, widths, size=9, mono_cols=None):
        mono_cols = mono_cols or set()
        x0 = self.margin
        self._ensure(size + 10)
        # cabecera con fondo
        self._rect(x0 - 4, self.y - size - 2, sum(widths) + 8, size + 8, (0.93, 0.95, 0.98))
        x = x0
        for h, w in zip(headers, widths):
            self._raw_text(x, self.y - size, _trunc(h, w, size), "F2", size, GREY)
            x += w
        self.y -= (size + 8)
        for ri, row in enumerate(rows):
            self._ensure(size + 4)
            if ri % 2 == 1:
                self._rect(x0 - 4, self.y - size - 1, sum(widths) + 8, size + 4, (0.97, 0.98, 0.99))
            x = x0
            for ci, (c, w) in enumerate(zip(row, widths)):
                mono = ci in mono_cols
                self._raw_text(x, self.y - size, _trunc(c, w, size, mono),
                               "F3" if mono else "F1", size, DARK)
                x += w
            self.y -= (size + 4)

    # ---- guardar ---- #
    def save(self, path):
        if self.cur:
            self.pages.append("".join(self.cur))
            self.cur = []
        n = len(self.pages)
        page_ids = [6 + 2 * i for i in range(n)]
        content_ids = [7 + 2 * i for i in range(n)]
        objs = {}
        objs[1] = "<< /Type /Catalog /Pages 2 0 R >>"
        kids = " ".join(f"{pid} 0 R" for pid in page_ids)
        objs[2] = f"<< /Type /Pages /Kids [{kids}] /Count {n} >>"
        objs[3] = "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>"
        objs[4] = "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>"
        objs[5] = "<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>"
        res = "<< /Font << /F1 3 0 R /F2 4 0 R /F3 5 0 R >> >>"
        for i, content in enumerate(self.pages):
            pid, cid = page_ids[i], content_ids[i]
            objs[pid] = (f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {self.w:.0f} {self.h:.0f}] "
                         f"/Resources {res} /Contents {cid} 0 R >>")
            body = content
            length = len(body.encode("latin-1", "replace"))
            objs[cid] = f"<< /Length {length} >>\nstream\n{body}\nendstream"
        out = b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n"
        offsets = {}
        maxid = max(objs)
        for oid in range(1, maxid + 1):
            offsets[oid] = len(out)
            body = objs.get(oid, "<< >>")
            out += f"{oid} 0 obj\n".encode("latin-1")
            out += body.encode("latin-1", "replace")
            out += b"\nendobj\n"
        xref_pos = len(out)
        out += f"xref\n0 {maxid + 1}\n".encode("latin-1")
        out += b"0000000000 65535 f \n"
        for oid in range(1, maxid + 1):
            out += f"{offsets[oid]:010d} 00000 n \n".encode("latin-1")
        out += (f"trailer\n<< /Size {maxid + 1} /Root 1 0 R >>\n"
                f"startxref\n{xref_pos}\n%%EOF").encode("latin-1")
        with open(path, "wb") as f:
            f.write(out)
        return path


# --------------------------------------------------------------------------- #
# Exportadores                                                                #
# --------------------------------------------------------------------------- #

def _ports_str(h):
    return " ".join(str(p["port"]) for p in h.get("ports", []))


def pdf_audit_report(data, path):
    host = data.get("host", {})
    doc = PDFDoc(title="Auditoría de red")
    doc.title("Auditoría de red")
    doc.line(f"Equipo: {host.get('hostname','-')}   ·   {host.get('os','')} {host.get('os_release','')}"
             f"   ·   {host.get('timestamp','')}", size=9, color=GREY)
    doc.spacer(6)

    sec = data.get("security") or {}
    grade = sec.get("grade", "-")
    gcol = TEAL if grade in ("A", "B") else ORANGE if grade == "C" else RED
    doc.heading(f"Seguridad:  {sec.get('score','-')}/100   ·   grado {grade}", color=gcol)
    findings = sec.get("findings", [])
    if findings:
        doc.table(["Sev", "Dónde", "Detalle", "Recomendación"],
                  [[f.get("sev", ""), f.get("donde", ""), f.get("detalle", ""), f.get("rec", "")]
                   for f in findings],
                  [45, 85, 150, 195], size=8)
    else:
        doc.line("Sin hallazgos de riesgo.", color=TEAL)
    doc.spacer(8)

    pub = data.get("public") or {}
    geo = pub.get("geo") or {}
    doc.heading("Internet")
    doc.line(f"IP pública: {pub.get('ip','-')}    rDNS: {pub.get('rdns','-')}")
    doc.line(f"Ubicación: {geo.get('ciudad','-')}, {geo.get('país','-')}    "
             f"ISP: {geo.get('isp','-')}    ASN: {geo.get('asn','-')}")
    spd = data.get("speedtest") or {}
    if spd.get("mbps"):
        doc.line(f"Velocidad de descarga: {spd['mbps']} Mbps")
    conn = data.get("connectivity") or {}
    if conn.get("ping"):
        p0 = conn["ping"][0]
        doc.line(f"Latencia {p0.get('host','')}: {p0.get('avg','-')} ms (pérdida {p0.get('loss','-')}%)")
    doc.spacer(8)

    iface = data.get("interfaces") or {}
    doc.heading("Interfaces")
    for name, d in iface.items():
        ipv4 = ", ".join(d.get("ipv4", [])) or "-"
        doc.line(f"{name}: {ipv4}   MAC {d.get('mac','-')}   MTU {d.get('mtu','-')}", size=9)
    doc.spacer(8)

    lan = data.get("lan") or []
    doc.heading(f"Hosts en la red ({len(lan)})")
    if lan:
        doc.table(["IP", "Hostname", "MAC", "Fabricante", "SO", "Puertos"],
                  [[h["ip"], h.get("hostname") or "", h.get("mac") or "",
                    h.get("vendor") or "", h.get("os_guess") or "", _ports_str(h)] for h in lan],
                  [72, 90, 105, 75, 45, 100], size=8, mono_cols={0, 2})
    else:
        doc.line("Escaneo de LAN no realizado.")
    return doc.save(path)


def pdf_scan_report(hosts, path):
    doc = PDFDoc(title="Escáner de red")
    doc.title("Escáner de red")
    doc.line(f"{len(hosts)} dispositivos · {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
             size=9, color=GREY)
    doc.spacer(8)
    if hosts:
        doc.table(["IP", "Nombre", "MAC", "Fabricante", "SO", "RTT", "Puertos"],
                  [[h["ip"], h.get("hostname") or "", h.get("mac") or "", h.get("vendor") or "",
                    h.get("os_guess") or "", (str(h.get("rtt_ms")) if h.get("rtt_ms") is not None else ""),
                    _ports_str(h)] for h in hosts],
                  [70, 80, 100, 70, 42, 38, 95], size=8, mono_cols={0, 2})
    else:
        doc.line("Sin dispositivos.")
    return doc.save(path)


def pdf_capture_report(packets, path, max_rows=600):
    doc = PDFDoc(title="Captura de paquetes")
    doc.title("Captura de paquetes")
    extra = "" if len(packets) <= max_rows else f"  (se muestran los primeros {max_rows})"
    doc.line(f"{len(packets)} paquetes · {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{extra}",
             size=9, color=GREY)
    doc.spacer(8)
    rows = []
    for p in packets[:max_rows]:
        t = datetime.datetime.fromtimestamp(p.get("time", 0)).strftime("%H:%M:%S.%f")[:-3]
        rows.append([p.get("no", ""), t, p.get("src", ""), p.get("dst", ""),
                     p.get("proto", ""), p.get("length", ""), p.get("info", "")])
    doc.table(["No.", "Tiempo", "Origen", "Destino", "Proto", "Long", "Info"],
              rows, [30, 62, 105, 105, 42, 32, 119], size=7.5, mono_cols={0, 1, 2, 3})
    return doc.save(path)
