#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
netaudit · interfaz Qt (PySide6) — diseño moderno, limpio, estilo macOS.

Tres herramientas en una app, con barra lateral:
  • Análisis de red      -> auditoría completa + dashboard HTML
  • Escáner de red        -> estilo Advanced IP Scanner (hosts, puertos, WoL)
  • Captura de paquetes   -> estilo Wireshark (sniffer + disector + pcap)

Fondo con motivo de red LAN (nodos y enlaces). Reutiliza el motor de
network_analyzer / netaudit_sniffer / netaudit_pdf.

Requiere PySide6 (se instala en el empaquetado de CI).
"""

import os
import queue
import random
import threading
import webbrowser

from PySide6.QtCore import Qt, QTimer, QPointF
from PySide6.QtGui import (QColor, QFont, QPainter, QPen, QBrush, QPalette,
                           QFontDatabase)
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QHBoxLayout, QVBoxLayout, QLabel,
    QPushButton, QStackedWidget, QTableWidget, QTableWidgetItem, QProgressBar,
    QTextEdit, QFileDialog, QMessageBox, QHeaderView, QFrame, QCheckBox,
    QAbstractItemView, QSizePolicy)

import network_analyzer as na
import netaudit_sniffer as sniff
import netaudit_pdf as pdfx

# ---- Paleta estilo macOS (clara, neutra, sin colores raros) ---------------- #
BG      = "#f5f5f7"
CARD    = "#ffffff"
LINE    = "#e3e3e8"
TXT     = "#1d1d1f"
MUTED   = "#86868b"
BLUE    = "#007aff"   # azul de sistema de macOS
BLUE_D  = "#0a84ff"
GREEN   = "#34c759"
ORANGE  = "#ff9f0a"
RED     = "#ff3b30"
SIDEBAR = "#ececee"

MONO = "SF Mono, Menlo, Consolas, monospace"

QSS = f"""
* {{ font-family: -apple-system, "SF Pro Text", "Helvetica Neue", Arial, sans-serif; font-size: 13px; color: {TXT}; }}
QMainWindow, QWidget {{ background: {BG}; }}
#Sidebar {{ background: {SIDEBAR}; border: none; }}
#SideBtn {{ text-align: left; padding: 10px 14px; border: none; border-radius: 8px;
           background: transparent; color: {TXT}; font-size: 14px; }}
#SideBtn:hover {{ background: rgba(0,0,0,0.05); }}
#SideBtn:checked {{ background: {BLUE}; color: white; font-weight: 600; }}
#Title {{ font-size: 24px; font-weight: 700; }}
#H2 {{ font-size: 17px; font-weight: 600; }}
#Muted {{ color: {MUTED}; }}
QPushButton {{ background: {CARD}; border: 1px solid #d2d2d7; border-radius: 8px;
               padding: 7px 16px; }}
QPushButton:hover {{ background: #fbfbfd; }}
QPushButton:disabled {{ color: {MUTED}; background: #ededf0; }}
QPushButton#primary {{ background: {BLUE}; color: white; border: none; font-weight: 600; }}
QPushButton#primary:hover {{ background: {BLUE_D}; }}
QPushButton#primary:disabled {{ background: #b9b9c0; color: #f0f0f0; }}
QFrame#Card {{ background: {CARD}; border: 1px solid {LINE}; border-radius: 14px; }}
QTableWidget {{ background: {CARD}; border: 1px solid {LINE}; border-radius: 10px;
                gridline-color: #eeeef1; }}
QTableWidget::item {{ padding: 3px 6px; }}
QTableWidget::item:selected {{ background: #e6f0ff; color: {TXT}; }}
QHeaderView::section {{ background: #f3f3f6; color: {MUTED}; border: none;
                        border-bottom: 1px solid {LINE}; padding: 7px 6px;
                        font-size: 11px; }}
QProgressBar {{ border: none; background: #e6e6eb; border-radius: 5px; height: 8px; text-align: center; }}
QProgressBar::chunk {{ background: {BLUE}; border-radius: 5px; }}
QTextEdit {{ background: #fbfbfd; border: 1px solid {LINE}; border-radius: 10px; }}
QCheckBox {{ color: {MUTED}; }}
QScrollBar:vertical {{ background: transparent; width: 10px; }}
QScrollBar::handle:vertical {{ background: #c7c7cc; border-radius: 5px; min-height: 30px; }}
"""


# --------------------------------------------------------------------------- #
# Fondo con motivo de red LAN                                                 #
# --------------------------------------------------------------------------- #

class NetworkBg(QWidget):
    """Dibuja un grafo de red tenue (nodos + enlaces) como fondo decorativo."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAttribute(Qt.WA_TransparentForMouseEvents, True)
        rnd = random.Random(7)
        self.nodes = [(rnd.random(), rnd.random()) for _ in range(16)]
        self.edges = []
        for i in range(len(self.nodes)):
            for j in range(i + 1, len(self.nodes)):
                dx = self.nodes[i][0] - self.nodes[j][0]
                dy = self.nodes[i][1] - self.nodes[j][1]
                if (dx * dx + dy * dy) ** 0.5 < 0.28:
                    self.edges.append((i, j))

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        w, h = self.width(), self.height()
        pts = [QPointF(x * w, y * h) for x, y in self.nodes]
        p.setPen(QPen(QColor(0, 122, 255, 26), 1.2))
        for i, j in self.edges:
            p.drawLine(pts[i], pts[j])
        for pt in pts:
            p.setBrush(QBrush(QColor(0, 122, 255, 40)))
            p.setPen(Qt.NoPen)
            p.drawEllipse(pt, 4, 4)
            p.setBrush(QBrush(QColor(0, 122, 255, 18)))
            p.drawEllipse(pt, 9, 9)


# --------------------------------------------------------------------------- #
# Utilidades de tabla                                                          #
# --------------------------------------------------------------------------- #

def make_table(headers, widths):
    t = QTableWidget(0, len(headers))
    t.setHorizontalHeaderLabels(headers)
    t.setEditTriggers(QAbstractItemView.NoEditTriggers)
    t.setSelectionBehavior(QAbstractItemView.SelectRows)
    t.setSelectionMode(QAbstractItemView.SingleSelection)
    t.verticalHeader().setVisible(False)
    t.setShowGrid(False)
    t.setAlternatingRowColors(False)
    for i, w in enumerate(widths):
        if w:
            t.setColumnWidth(i, w)
    t.horizontalHeader().setStretchLastSection(True)
    return t


def cell(text, mono=False):
    it = QTableWidgetItem("" if text is None else str(text))
    if mono:
        it.setFont(QFont("Menlo", 11))
    return it


# --------------------------------------------------------------------------- #
# Vistas                                                                       #
# --------------------------------------------------------------------------- #

class AnalyzeView(QWidget):
    def __init__(self, app):
        super().__init__()
        self.app = app
        self.report_path = os.path.join(_tmp(), "netaudit_report.html")
        self.q = None
        self.bg = NetworkBg(self)

        root = QVBoxLayout(self)
        root.setContentsMargins(36, 30, 36, 30)
        root.setSpacing(14)
        title = QLabel("Análisis de red"); title.setObjectName("Title")
        sub = QLabel("Auditoría completa de tu red y un informe visual"); sub.setObjectName("Muted")
        root.addWidget(title); root.addWidget(sub)
        root.addSpacing(8)

        self.fast = QCheckBox("Análisis rápido (menos pruebas)")
        root.addWidget(self.fast)

        self.btn = QPushButton("Analizar mi red"); self.btn.setObjectName("primary")
        self.btn.setMinimumHeight(44); self.btn.clicked.connect(self.start)
        root.addWidget(self.btn)

        self.bar = QProgressBar(); self.bar.setRange(0, 100); self.bar.setValue(0)
        self.bar.setVisible(False)
        root.addWidget(self.bar)
        self.status = QLabel(""); self.status.setObjectName("Muted")
        root.addWidget(self.status)

        self.result = QFrame(); self.result.setObjectName("Card"); self.result.setVisible(False)
        rl = QVBoxLayout(self.result); rl.setContentsMargins(22, 20, 22, 20)
        self.score_lbl = QLabel(""); self.score_lbl.setObjectName("H2")
        self.stats_lbl = QLabel(""); self.stats_lbl.setObjectName("Muted")
        self.open_btn = QPushButton("Ver informe completo"); self.open_btn.setObjectName("primary")
        self.open_btn.clicked.connect(lambda: webbrowser.open("file://" + os.path.abspath(self.report_path)))
        self.pdf_btn = QPushButton("Exportar a PDF"); self.pdf_btn.clicked.connect(self.export_pdf)
        rl.addWidget(self.score_lbl); rl.addWidget(self.stats_lbl)
        rl.addSpacing(6); rl.addWidget(self.open_btn); rl.addWidget(self.pdf_btn)
        root.addWidget(self.result)
        root.addStretch(1)

    def resizeEvent(self, e):
        self.bg.setGeometry(0, 0, self.width(), self.height())
        self.bg.lower()
        super().resizeEvent(e)

    def start(self):
        self.btn.setEnabled(False); self.btn.setText("Analizando…")
        self.bar.setVisible(True); self.bar.setRange(0, 0)
        self.result.setVisible(False)
        self.data = None
        self.q = queue.Queue()
        opts = na.Options(fast=self.fast.isChecked(), output=self.report_path,
                          json=os.path.join(_tmp(), "netaudit_report.json"))
        threading.Thread(target=self._work, args=(opts,), daemon=True).start()
        QTimer.singleShot(80, self._poll)

    def _work(self, opts):
        try:
            c = {"n": 0}
            def st(msg):
                c["n"] += 1
                self.q.put(("status", msg))
            data = na.analyze(opts, status=st)
            self.q.put(("done", data))
        except Exception as e:
            self.q.put(("error", str(e)))

    def _poll(self):
        try:
            while True:
                kind, payload = self.q.get_nowait()
                if kind == "status":
                    self.status.setText(payload)
                elif kind == "done":
                    self._show(payload); return
                elif kind == "error":
                    self.status.setText("Error: " + payload)
                    self.btn.setEnabled(True); self.btn.setText("Analizar mi red")
                    self.bar.setVisible(False); return
        except queue.Empty:
            pass
        QTimer.singleShot(80, self._poll)

    def _show(self, data):
        self.data = data
        self.bar.setVisible(False)
        self.btn.setEnabled(True); self.btn.setText("Analizar mi red")
        self.status.setText("")
        sec = data.get("security") or {}
        score, grade = sec.get("score", 0), sec.get("grade", "-")
        col = GREEN if grade in ("A", "B") else ORANGE if grade == "C" else RED
        self.score_lbl.setText(f"Seguridad: <b style='color:{col}'>{score}/100 · grado {grade}</b>")
        lan = data.get("lan") or []
        n_ports = sum(len(h.get("ports", [])) for h in lan)
        pub = (data.get("public") or {}).get("ip") or "—"
        spd = (data.get("speedtest") or {}).get("mbps")
        self.stats_lbl.setText(f"{len(lan)} hosts · {n_ports} puertos abiertos · IP pública {pub}"
                               + (f" · ↓ {spd} Mbps" if spd else ""))
        self.result.setVisible(True)

    def export_pdf(self):
        if not getattr(self, "data", None):
            return
        path, _ = QFileDialog.getSaveFileName(self, "Guardar PDF", "netaudit_auditoria.pdf", "PDF (*.pdf)")
        if path:
            try:
                pdfx.pdf_audit_report(self.data, path)
                QMessageBox.information(self, "PDF", f"Guardado en:\n{path}")
            except Exception as e:
                QMessageBox.critical(self, "PDF", str(e))


class ScannerView(QWidget):
    def __init__(self, app):
        super().__init__()
        self.app = app
        self.q = None
        self.stop = None
        self.rows = {}

        root = QVBoxLayout(self); root.setContentsMargins(28, 24, 28, 24); root.setSpacing(12)
        head = QHBoxLayout()
        t = QLabel("Escáner de red"); t.setObjectName("Title")
        head.addWidget(t); head.addStretch(1)
        self.rescan = QPushButton("Reescanear"); self.rescan.setObjectName("primary")
        self.rescan.clicked.connect(self.start)
        self.wol = QPushButton("Wake-on-LAN"); self.wol.clicked.connect(self._wol)
        self.openb = QPushButton("Abrir"); self.openb.clicked.connect(self._open)
        self.pdf = QPushButton("PDF"); self.pdf.clicked.connect(self._pdf)
        for b in (self.openb, self.wol, self.pdf, self.rescan):
            head.addWidget(b)
        root.addLayout(head)
        self.status = QLabel("Listo"); self.status.setObjectName("Muted")
        root.addWidget(self.status)
        self.table = make_table(["IP", "Nombre", "MAC", "Fabricante", "SO", "RTT", "Puertos"],
                                 [120, 150, 150, 110, 80, 60, 0])
        root.addWidget(self.table, 1)

    def showEvent(self, e):
        super().showEvent(e)
        if not self.rows:
            self.start()

    def start(self):
        self.table.setRowCount(0); self.rows = {}
        self.status.setText("Descubriendo hosts…")
        self.q = queue.Queue(); self.stop = threading.Event()
        threading.Thread(target=self._work, args=(self.stop,), daemon=True).start()
        QTimer.singleShot(100, self._poll)

    def _work(self, stop):
        try:
            import socket as _s
            arp = na.collect_arp(); amap = {e["ip"]: e for e in arp}
            net = na.guess_subnet()
            if net is None:
                self.q.put(("done", 0)); return
            self.q.put(("net", str(net)))
            hosts = [str(h) for h in net.hosts()]
            if self.app.fast_global:
                hosts = hosts[:256]
            import concurrent.futures as cf
            alive = []
            with cf.ThreadPoolExecutor(max_workers=160) as ex:
                for r in ex.map(na.ping_host, hosts):
                    if stop.is_set():
                        break
                    if not r:
                        continue
                    ip = r["ip"]
                    try:
                        hn = _s.gethostbyaddr(ip)[0]
                    except Exception:
                        hn = None
                    a = amap.get(ip, {})
                    host = {"ip": ip, "rtt_ms": r["rtt_ms"], "ttl": r["ttl"],
                            "os_guess": na.os_from_ttl(r["ttl"]), "hostname": hn,
                            "mac": a.get("mac"), "vendor": a.get("vendor"), "ports": []}
                    alive.append(host); self.q.put(("host", host))
            self.q.put(("sweep", len(alive)))
            ports = na.parse_ports(None)
            for h in alive:
                if stop.is_set():
                    break
                h["ports"] = na.scan_host_ports(h["ip"], ports, 0.5, h.get("hostname"))
                self.q.put(("ports", h))
            self.q.put(("done", len(alive)))
        except Exception as e:
            self.q.put(("err", str(e)))

    def _poll(self):
        try:
            while True:
                kind, payload = self.q.get_nowait()
                if kind == "net":
                    self.status.setText(f"Red {payload} · descubriendo…")
                elif kind == "host":
                    self._add(payload)
                elif kind == "ports":
                    self._ports(payload)
                elif kind == "sweep":
                    self.status.setText(f"{payload} hosts · escaneando puertos…")
                elif kind == "done":
                    self.status.setText(f"Completado · {payload or len(self.rows)} hosts"); return
                elif kind == "err":
                    self.status.setText("Error: " + payload); return
        except queue.Empty:
            pass
        QTimer.singleShot(120, self._poll)

    def _add(self, h):
        r = self.table.rowCount(); self.table.insertRow(r)
        vals = [h["ip"], h.get("hostname") or "", h.get("mac") or "", h.get("vendor") or "",
                h.get("os_guess") or "", (str(h["rtt_ms"]) if h.get("rtt_ms") is not None else ""), ""]
        for c, v in enumerate(vals):
            self.table.setItem(r, c, cell(v, mono=c in (0, 2)))
        self.rows[h["ip"]] = (r, h)

    def _ports(self, h):
        if h["ip"] in self.rows:
            r, _ = self.rows[h["ip"]]
            self.rows[h["ip"]] = (r, h)
            self.table.setItem(r, 6, cell(" ".join(str(p["port"]) for p in h["ports"]), mono=True))

    def _sel(self):
        items = self.table.selectedItems()
        if not items:
            return None
        ip = self.table.item(items[0].row(), 0).text()
        rec = self.rows.get(ip)
        return rec[1] if rec else None

    def _wol(self):
        h = self._sel()
        if not h or not h.get("mac"):
            QMessageBox.information(self, "Wake-on-LAN", "Selecciona un host con MAC.")
            return
        ok = na.wake_on_lan(h["mac"])
        QMessageBox.information(self, "Wake-on-LAN",
                               f"Enviado a {h['mac']}" if ok else "No se pudo enviar.")

    def _open(self):
        h = self._sel()
        if not h:
            return
        url = next((u for n, u in na.host_actions(h) if u.startswith("http")), None)
        if url:
            webbrowser.open(url)
        else:
            QMessageBox.information(self, "Abrir", "Este host no tiene web (HTTP/HTTPS).")

    def _pdf(self):
        hosts = [rec[1] for rec in self.rows.values()]
        if not hosts:
            QMessageBox.information(self, "PDF", "No hay dispositivos.")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Guardar PDF", "netaudit_escaner.pdf", "PDF (*.pdf)")
        if path:
            try:
                pdfx.pdf_scan_report(hosts, path)
                QMessageBox.information(self, "PDF", f"Guardado en:\n{path}")
            except Exception as e:
                QMessageBox.critical(self, "PDF", str(e))


class SnifferView(QWidget):
    def __init__(self, app):
        super().__init__()
        self.app = app
        self.q = None
        self.stop = None
        self.pkts = []

        root = QVBoxLayout(self); root.setContentsMargins(28, 24, 28, 24); root.setSpacing(12)
        head = QHBoxLayout()
        t = QLabel("Captura de paquetes"); t.setObjectName("Title")
        head.addWidget(t); head.addStretch(1)
        self.start_b = QPushButton("▶ Iniciar"); self.start_b.setObjectName("primary"); self.start_b.clicked.connect(self.start)
        self.stop_b = QPushButton("■ Parar"); self.stop_b.clicked.connect(self._stop)
        self.save_b = QPushButton("Guardar .pcap"); self.save_b.clicked.connect(self._save)
        self.pdf_b = QPushButton("PDF"); self.pdf_b.clicked.connect(self._pdf)
        for b in (self.save_b, self.pdf_b, self.stop_b, self.start_b):
            head.addWidget(b)
        root.addLayout(head)
        self.priv = sniff.privileged_backend()
        if self.priv == "root":
            msg = "Listo · captura directa"
        elif self.priv:
            msg = "Pulsa Iniciar · pide contraseña y captura ~1000 paquetes"
        else:
            msg = "Sin backend de captura (instala tcpdump)"
            self.start_b.setEnabled(False)
        self.status = QLabel(msg); self.status.setObjectName("Muted")
        root.addWidget(self.status)
        self.table = make_table(["No.", "Tiempo", "Origen", "Destino", "Proto", "Long", "Info"],
                                 [50, 95, 135, 135, 60, 55, 0])
        root.addWidget(self.table, 3)
        self.table.itemSelectionChanged.connect(self._detail)
        self.detail = QTextEdit(); self.detail.setReadOnly(True)
        self.detail.setFont(QFont("Menlo", 11)); self.detail.setMaximumHeight(180)
        self.detail.setPlainText("Selecciona un paquete para ver su detalle y hex…")
        root.addWidget(self.detail, 1)

    def start(self):
        self.pkts = []; self.table.setRowCount(0)
        self.q = queue.Queue(); self.stop = threading.Event()
        if self.priv == "root":
            self.status.setText("Capturando…")
            threading.Thread(target=self._work_root, args=(self.stop,), daemon=True).start()
        else:
            self.status.setText("Solicitando permiso…")
            threading.Thread(target=self._work_priv, args=(self.stop,), daemon=True).start()
        QTimer.singleShot(100, self._poll)

    def _work_root(self, stop):
        try:
            sniff.capture(count=0, on_packet=lambda p: self.q.put(("pkt", p)), stop_event=stop)
            self.q.put(("done", None))
        except Exception as e:
            self.q.put(("err", str(e)))

    def _work_priv(self, stop):
        try:
            pcap = sniff.live_pcap_path()
            reader = threading.Thread(
                target=lambda: sniff.read_pcap_stream(pcap, lambda p: self.q.put(("pkt", p)), stop, ready_timeout=180),
                daemon=True)
            reader.start()
            self.q.put(("status", "Permiso + capturando ~1000 paquetes…"))
            ok, err = sniff.run_privileged_capture_sync(sniff.default_iface(), pcap, count=1000)
            stop.set()
            captured = os.path.exists(pcap) and os.path.getsize(pcap) > 24
            if not ok and not captured:
                self.q.put(("err", err or "permiso cancelado o sin captura"))
                return
            self.q.put(("done", None))
        except Exception as e:
            self.q.put(("err", str(e)))

    def _poll(self):
        try:
            while True:
                kind, payload = self.q.get_nowait()
                if kind == "status":
                    self.status.setText(payload)
                elif kind == "pkt":
                    self._add(payload)
                elif kind == "done":
                    self._finish(); return
                elif kind == "err":
                    self.status.setText("Error: " + payload); return
        except queue.Empty:
            pass
        QTimer.singleShot(120, self._poll)

    def _add(self, p):
        import datetime as _dt
        self.pkts.append(p)
        r = self.table.rowCount(); self.table.insertRow(r)
        t = _dt.datetime.fromtimestamp(p["time"]).strftime("%H:%M:%S.%f")[:-3]
        vals = [p["no"], t, p["src"], p["dst"], p["proto"], p["length"], p["info"][:90]]
        for c, v in enumerate(vals):
            self.table.setItem(r, c, cell(v, mono=c in (0, 1, 2, 3)))
        if len(self.pkts) % 10 == 0:
            self.table.scrollToBottom()

    def _finish(self):
        n = len(self.pkts)
        if n == 0:
            err = ""
            try:
                err = sniff.get_capture_error()
            except Exception:
                pass
            last = err.strip().splitlines()[-1] if err.strip() else ""
            self.status.setText("Sin paquetes. " + (last or "Prueba otra interfaz o revisa el permiso."))
        else:
            self.status.setText(f"Detenido · {n} paquetes")

    def _stop(self):
        if self.stop:
            self.stop.set()
        s = sniff.stop_sentinel_path()
        try:
            sniff.stop_privileged_capture(s)
        except Exception:
            pass

    def _detail(self):
        items = self.table.selectedItems()
        if not items:
            return
        try:
            p = self.pkts[items[0].row()]
        except Exception:
            return
        d = p.get("detail") or {}
        lines = [f"Paquete #{p['no']}  ·  {p['proto']}  ·  {p['length']} bytes",
                 f"Origen: {p['src']}   Destino: {p['dst']}",
                 f"Ethernet: {p.get('eth_src')} → {p.get('eth_dst')}", ""]
        if d.get("transport"):
            lines.append("Info: " + d["transport"].get("info", ""))
        lines += ["", p.get("hex", "")]
        self.detail.setPlainText("\n".join(lines))

    def _save(self):
        if not self.pkts:
            QMessageBox.information(self, "Guardar", "No hay paquetes.")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Guardar pcap", "netaudit_capture.pcap", "pcap (*.pcap)")
        if path:
            sniff.write_pcap(path, self.pkts)
            QMessageBox.information(self, "Guardado", f"Guardado en:\n{path}\nÁbrelo en Wireshark.")

    def _pdf(self):
        if not self.pkts:
            QMessageBox.information(self, "PDF", "No hay paquetes.")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Guardar PDF", "netaudit_captura.pdf", "PDF (*.pdf)")
        if path:
            try:
                pdfx.pdf_capture_report(self.pkts, path)
                QMessageBox.information(self, "PDF", f"Guardado en:\n{path}")
            except Exception as e:
                QMessageBox.critical(self, "PDF", str(e))


# --------------------------------------------------------------------------- #
# Ventana principal                                                           #
# --------------------------------------------------------------------------- #

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.fast_global = False
        self.setWindowTitle("netaudit")
        self.resize(940, 680)
        self.setMinimumSize(820, 560)

        central = QWidget(); self.setCentralWidget(central)
        lay = QHBoxLayout(central); lay.setContentsMargins(0, 0, 0, 0); lay.setSpacing(0)

        # Barra lateral
        side = QWidget(); side.setObjectName("Sidebar"); side.setFixedWidth(210)
        sl = QVBoxLayout(side); sl.setContentsMargins(14, 20, 14, 20); sl.setSpacing(4)
        brand = QLabel("  netaudit"); brand.setStyleSheet("font-size:18px; font-weight:700;")
        sl.addWidget(brand); sl.addSpacing(14)

        self.stack = QStackedWidget()
        self.views = [AnalyzeView(self), ScannerView(self), SnifferView(self)]
        for v in self.views:
            self.stack.addWidget(v)

        self.btns = []
        for i, (label, ic) in enumerate([("  Análisis de red", "◉"),
                                         ("  Escáner de red", "▦"),
                                         ("  Captura de paquetes", "≋")]):
            b = QPushButton(ic + label); b.setObjectName("SideBtn"); b.setCheckable(True)
            b.clicked.connect(lambda _=False, idx=i: self._go(idx))
            sl.addWidget(b); self.btns.append(b)
        sl.addStretch(1)
        ver = QLabel(f"  v{na.__version__}"); ver.setObjectName("Muted")
        sl.addWidget(ver)

        lay.addWidget(side)
        lay.addWidget(self.stack, 1)
        self._go(0)

    def _go(self, idx):
        self.stack.setCurrentIndex(idx)
        for i, b in enumerate(self.btns):
            b.setChecked(i == idx)


def _tmp():
    import tempfile
    return tempfile.gettempdir()


def main():
    app = QApplication.instance() or QApplication([])
    app.setStyleSheet(QSS)
    app.setStyle("Fusion")
    w = MainWindow()
    w.show()
    app.exec()


if __name__ == "__main__":
    main()
