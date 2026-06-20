#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
netaudit · interfaz gráfica (estilo Apple, oscura y cuidada).

Tres herramientas en una app:
  • Análisis de red        -> auditoría completa + dashboard HTML
  • Escáner de red         -> estilo Advanced IP Scanner (hosts, puertos, WoL)
  • Captura de paquetes    -> estilo Wireshark (sniffer + disector + pcap)

Pensada para empaquetarse como app de macOS (.app dentro de un .dmg); también
funciona en Windows/Linux. La captura en vivo necesita permisos de administrador.
"""

import concurrent.futures
import os
import queue
import tempfile
import threading
import webbrowser

import tkinter as tk
import tkinter.font as tkfont
from tkinter import ttk, filedialog, messagebox

import network_analyzer as na
import netaudit_sniffer as sniff
import netaudit_pdf as pdfx

# ---- Paleta ---- #
BG, PANEL, PANEL2, LINE = "#0b0f17", "#121826", "#0e1420", "#1f2a3d"
TXT, MUTED, ACC, ACC2, BAD, WARN = "#e7edf5", "#6b7a93", "#37d39a", "#4aa3ff", "#ff5d6c", "#ffb454"
W, H = 560, 680


def pick_font(root, candidates, size, weight="normal"):
    fams = set(tkfont.families(root))
    for c in candidates:
        if c in fams:
            return tkfont.Font(root=root, family=c, size=size, weight=weight)
    return tkfont.Font(root=root, size=size, weight=weight)


class RoundButton:
    """Botón redondeado dibujado en un canvas (look Apple, multiplataforma)."""
    def __init__(self, cv, x, y, w, h, text, font, fill, fg, command, radius=14):
        self.cv, self.command, self.enabled, self.fill, self.fg = cv, command, True, fill, fg
        self.items = []
        pts = [x+radius, y, x+w-radius, y, x+w, y, x+w, y+radius, x+w, y+h-radius, x+w, y+h,
               x+w-radius, y+h, x+radius, y+h, x, y+h, x, y+h-radius, x, y+radius, x, y]
        self.items.append(cv.create_polygon(pts, smooth=True, fill=fill, outline=fill))
        self.txt = cv.create_text(x+w/2, y+h/2, text=text, fill=fg, font=font)
        for it in self.items + [self.txt]:
            cv.tag_bind(it, "<Button-1>", self._click)
            cv.tag_bind(it, "<Enter>", lambda e: cv.config(cursor="hand2"))
            cv.tag_bind(it, "<Leave>", lambda e: cv.config(cursor=""))

    def _click(self, _):
        if self.enabled and self.command:
            self.command()

    def set_enabled(self, on):
        c = self.fill if on else "#243047"
        for it in self.items:
            self.cv.itemconfig(it, fill=c, outline=c)
        self.cv.itemconfig(self.txt, fill=self.fg if on else MUTED)

    def set_text(self, t):
        self.cv.itemconfig(self.txt, text=t)


class App:
    def __init__(self, root):
        self.root = root
        root.title("netaudit")
        root.geometry(f"{W}x{H}")
        root.minsize(W, H)
        root.configure(bg=BG)
        self.q = queue.Queue()
        self.report_path = os.path.join(tempfile.gettempdir(), "netaudit_report.html")
        self.data = None
        self.stop_event = None
        self.capture_pkts = []

        self.f_title = pick_font(root, ["SF Pro Display", "Helvetica Neue", "Helvetica", "Arial"], 30, "bold")
        self.f_h2 = pick_font(root, ["SF Pro Display", "Helvetica Neue", "Helvetica"], 20, "bold")
        self.f_sub = pick_font(root, ["SF Pro Text", "Helvetica Neue", "Helvetica", "Arial"], 13)
        self.f_btn = pick_font(root, ["SF Pro Text", "Helvetica Neue", "Helvetica", "Arial"], 15, "bold")
        self.f_small = pick_font(root, ["SF Pro Text", "Helvetica Neue", "Helvetica", "Arial"], 11)
        self.f_gauge = pick_font(root, ["SF Pro Display", "Helvetica Neue", "Helvetica"], 50, "bold")
        self.f_mono = pick_font(root, ["SF Mono", "Menlo", "Consolas", "Courier"], 11)

        self._init_ttk_style()
        self.show_home()

    def _init_ttk_style(self):
        st = ttk.Style()
        try:
            st.theme_use("clam")
        except Exception:
            pass
        st.configure("Dark.Treeview", background=PANEL, fieldbackground=PANEL,
                     foreground=TXT, bordercolor=LINE, borderwidth=0, rowheight=24,
                     font=self.f_mono)
        st.configure("Dark.Treeview.Heading", background=PANEL2, foreground=MUTED,
                     relief="flat", font=self.f_small)
        st.map("Dark.Treeview", background=[("selected", "#1d3a2e")],
               foreground=[("selected", ACC)])
        st.configure("Vertical.TScrollbar", background=PANEL2, troughcolor=BG,
                     bordercolor=BG, arrowcolor=MUTED)

    def _clear(self):
        if self.stop_event:
            self.stop_event.set()
            self.stop_event = None
        for w in self.root.winfo_children():
            w.destroy()

    # =================================================================== #
    # HOME
    # =================================================================== #
    def show_home(self):
        self._clear()
        cv = tk.Canvas(self.root, width=W, height=H, bg=BG, highlightthickness=0)
        cv.pack(fill="both", expand=True)
        self.cv = cv
        self._logo(W/2, 88, 32)
        cv.create_text(W/2, 156, text="netaudit", fill=TXT, font=self.f_title)
        cv.create_text(W/2, 186, text="Suite de red · análisis · escáner · sniffer",
                       fill=MUTED, font=self.f_sub)

        self.fast_var = tk.BooleanVar(value=False)
        self.chk = cv.create_text(W/2, 224, fill=MUTED, font=self.f_small,
                                  text="☐  Modo rápido", tags=("chk",))
        cv.tag_bind("chk", "<Button-1>", self._toggle_fast)

        def tool(y, title, desc, color, fg, cmd):
            self._panel(56, y, W-56, y+86)
            cv.create_text(80, y+30, anchor="w", text=title, fill=TXT, font=self.f_btn)
            cv.create_text(80, y+56, anchor="w", text=desc, fill=MUTED, font=self.f_small)
            RoundButton(cv, W-176, y+24, 110, 40, "Abrir", self.f_small, color, fg, cmd, radius=12)

        tool(262, "Análisis de red", "Auditoría completa + dashboard HTML", ACC, "#06231a", self.start_analyze)
        tool(362, "Escáner de red", "Hosts, MAC, fabricante, puertos, Wake-on-LAN", ACC2, "#04203f", self.show_scanner)
        tool(462, "Captura de paquetes", "Sniffer estilo Wireshark · exporta .pcap", WARN, "#3a2606", self.show_sniffer)

        self.status_id = cv.create_text(W/2, 580, text="", fill=ACC, font=self.f_mono)
        self.bar = None
        cv.create_text(W/2, H-26, fill=MUTED, font=self.f_small,
                       text=f"netaudit v{na.__version__} · úsalo solo en redes propias o con permiso")

    def _toggle_fast(self, _):
        self.fast_var.set(not self.fast_var.get())
        m = "☑" if self.fast_var.get() else "☐"
        self.cv.itemconfig(self.chk, text=f"{m}  Modo rápido", fill=ACC if self.fast_var.get() else MUTED)

    def _logo(self, cx, cy, r):
        cv = self.cv
        self._squircle(cx-r-14, cy-r-14, cx+r+14, cy+r+14, 22, PANEL, LINE)
        for i, rr in enumerate((r, r*0.66, r*0.33)):
            col = ACC if i == 0 else ACC2 if i == 1 else "#2b6f5a"
            cv.create_oval(cx-rr, cy-rr, cx+rr, cy+rr, outline=col, width=2)
        cv.create_line(cx, cy, cx+r*0.92, cy-r*0.55, fill=ACC, width=2)
        cv.create_oval(cx-3, cy-3, cx+3, cy+3, fill=ACC, outline=ACC)
        cv.create_oval(cx+r*0.55-4, cy-r*0.30-4, cx+r*0.55+4, cy-r*0.30+4, fill=ACC2, outline=ACC2)
        cv.create_oval(cx-r*0.5-3, cy+r*0.45-3, cx-r*0.5+3, cy+r*0.45+3, fill=WARN, outline=WARN)

    def _squircle(self, x1, y1, x2, y2, r, fill, outline):
        pts = [x1+r, y1, x2-r, y1, x2, y1, x2, y1+r, x2, y2-r, x2, y2,
               x2-r, y2, x1+r, y2, x1, y2, x1, y2-r, x1, y1+r, x1, y1]
        self.cv.create_polygon(pts, smooth=True, fill=fill, outline=outline, width=1.5)

    def _panel(self, x1, y1, x2, y2):
        r = 16
        pts = [x1+r, y1, x2-r, y1, x2, y1, x2, y1+r, x2, y2-r, x2, y2,
               x2-r, y2, x1+r, y2, x1, y2, x1, y2-r, x1, y1+r, x1, y1]
        self.cv.create_polygon(pts, smooth=True, fill=PANEL, outline=LINE, width=1)

    # =================================================================== #
    # ANÁLISIS (igual que antes)
    # =================================================================== #
    def start_analyze(self):
        self.cv.itemconfig(self.status_id, text="Analizando tu red…")
        x1, x2, y = 90, W-90, 560
        self.cv.create_rectangle(x1, y, x2, y+8, fill="#16202f", outline="")
        self.bar = self.cv.create_rectangle(x1, y, x1, y+8, fill=ACC, outline="")
        self._bx1, self._bx2, self._bt, self._bc = x1, x2, 0.0, 0.0
        self.data = None
        opts = na.Options(fast=self.fast_var.get(), output=self.report_path,
                          json=os.path.join(tempfile.gettempdir(), "netaudit_report.json"))
        threading.Thread(target=self._analyze_worker, args=(opts,), daemon=True).start()
        self._poll_analyze()
        self._animate_bar()

    PHASES = 13

    def _analyze_worker(self, opts):
        try:
            c = {"n": 0}
            def status(msg):
                c["n"] += 1
                self.q.put(("status", msg, c["n"]/self.PHASES))
            data = na.analyze(opts, status=status)
            self.q.put(("done", data, 1.0))
        except Exception as e:
            self.q.put(("error", str(e), 0))

    def _poll_analyze(self):
        try:
            while True:
                kind, payload, prog = self.q.get_nowait()
                if kind == "status":
                    self.cv.itemconfig(self.status_id, text=payload); self._bt = min(0.97, prog)
                elif kind == "done":
                    self.data = payload; self._bt = 1.0
                    self.root.after(300, self.show_results); return
                elif kind == "error":
                    self.cv.itemconfig(self.status_id, text="Error: "+payload, fill=BAD); return
        except queue.Empty:
            pass
        self.root.after(80, self._poll_analyze)

    def _animate_bar(self):
        if not self.bar:
            return
        self._bc += (self._bt - self._bc) * 0.18
        self.cv.coords(self.bar, self._bx1, 560, self._bx1+(self._bx2-self._bx1)*self._bc, 568)
        if self.data is None or self._bc < 0.999:
            self.root.after(30, self._animate_bar)

    def show_results(self):
        self._clear()
        cv = tk.Canvas(self.root, width=W, height=H, bg=BG, highlightthickness=0)
        cv.pack(fill="both", expand=True); self.cv = cv
        sec = self.data.get("security") or {}
        score, grade = sec.get("score", 0), sec.get("grade", "—")
        color = ACC if grade in ("A", "B") else WARN if grade == "C" else BAD
        cv.create_text(W/2, 54, text="Análisis completado", fill=TXT, font=self.f_title)
        cx, cy, r = W/2, 180, 74
        cv.create_oval(cx-r, cy-r, cx+r, cy+r, outline="#16202f", width=12)
        cv.create_arc(cx-r, cy-r, cx+r, cy+r, start=90, extent=-359.9*(score/100.0) if score else -0.1,
                      outline=color, width=12, style="arc")
        cv.create_text(cx, cy-6, text=str(score), fill=color, font=self.f_gauge)
        cv.create_text(cx, cy+32, text=f"Grado {grade} · seguridad", fill=MUTED, font=self.f_small)
        lan = self.data.get("lan") or []
        n_ports = sum(len(h.get("ports", [])) for h in lan)
        pub = self.data.get("public") or {}; spd = self.data.get("speedtest") or {}
        stats = [("Hosts", str(len(lan))), ("Puertos", str(n_ports)),
                 ("IP pública", pub.get("ip") or "—"),
                 ("Velocidad ↓", f"{spd.get('mbps')} Mbps" if spd.get("mbps") else "—")]
        for i, (k, v) in enumerate(stats):
            yy = 288 + (i//2)*60; xx = 70 if i % 2 == 0 else W/2+10
            self._panel(xx, yy, xx+(W/2-80), yy+48)
            cv.create_text(xx+16, yy+16, anchor="w", text=k, fill=MUTED, font=self.f_small)
            cv.create_text(xx+16, yy+34, anchor="w", text=v, fill=TXT, font=self.f_btn)
        findings = sec.get("findings", [])
        cv.create_text(W/2, 432, fill=ACC if not findings else WARN, font=self.f_small,
                       text="Sin riesgos detectados 🎉" if not findings else f"{len(findings)} hallazgo(s) — revisa el informe")
        RoundButton(cv, W/2-130, 458, 260, 48, "Ver informe completo", self.f_btn, ACC, "#06231a",
                    command=lambda: webbrowser.open("file://"+os.path.abspath(self.report_path)))
        RoundButton(cv, W/2-130, 514, 260, 42, "Exportar a PDF", self.f_small, PANEL, ACC,
                    command=self.export_audit_pdf, radius=12)
        RoundButton(cv, W/2-130, 564, 260, 40, "Volver al inicio", self.f_small, PANEL, ACC2,
                    command=self.show_home, radius=12)

    def export_audit_pdf(self):
        path = filedialog.asksaveasfilename(defaultextension=".pdf",
                                            filetypes=[("PDF", "*.pdf")],
                                            initialfile="netaudit_auditoria.pdf")
        if not path:
            return
        try:
            pdfx.pdf_audit_report(self.data, path)
            messagebox.showinfo("PDF", f"Informe guardado en:\n{path}")
        except Exception as e:
            messagebox.showerror("PDF", f"No se pudo crear el PDF:\n{e}")

    # =================================================================== #
    # ESCÁNER DE RED (Advanced IP Scanner)
    # =================================================================== #
    def show_scanner(self):
        self._clear()
        top = tk.Frame(self.root, bg=BG); top.pack(fill="x", padx=16, pady=(14, 6))
        tk.Label(top, text="Escáner de red", bg=BG, fg=TXT, font=self.f_h2).pack(side="left")
        tk.Button(top, text="← Inicio", command=self.show_home, bg=PANEL, fg=ACC2,
                  relief="flat", font=self.f_small, highlightthickness=0, bd=0).pack(side="right")
        bar = tk.Frame(self.root, bg=BG); bar.pack(fill="x", padx=16)
        self.scan_status = tk.Label(bar, text="Listo", bg=BG, fg=MUTED, font=self.f_mono)
        self.scan_status.pack(side="left")
        tk.Button(bar, text="Reescanear", command=self._start_scan, bg=ACC2, fg="#04203f",
                  relief="flat", font=self.f_small, bd=0, padx=12, pady=4).pack(side="right")
        tk.Button(bar, text="Wake-on-LAN", command=self._scan_wol, bg=PANEL, fg=WARN,
                  relief="flat", font=self.f_small, bd=0, padx=12, pady=4).pack(side="right", padx=6)
        tk.Button(bar, text="Abrir", command=self._scan_open, bg=PANEL, fg=ACC,
                  relief="flat", font=self.f_small, bd=0, padx=12, pady=4).pack(side="right")
        tk.Button(bar, text="PDF", command=self._scan_pdf, bg=PANEL, fg=ACC,
                  relief="flat", font=self.f_small, bd=0, padx=12, pady=4).pack(side="right", padx=6)

        cols = ("ip", "host", "mac", "vendor", "os", "ports")
        frame = tk.Frame(self.root, bg=BG); frame.pack(fill="both", expand=True, padx=16, pady=10)
        self.tree = ttk.Treeview(frame, columns=cols, show="headings", style="Dark.Treeview")
        for c, t, w in [("ip", "IP", 110), ("host", "Nombre", 130), ("mac", "MAC", 130),
                        ("vendor", "Fabricante", 110), ("os", "SO", 80), ("ports", "Puertos", 150)]:
            self.tree.heading(c, text=t); self.tree.column(c, width=w, anchor="w")
        sb = ttk.Scrollbar(frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(side="left", fill="both", expand=True); sb.pack(side="right", fill="y")
        self._scan_rows = {}
        self._start_scan()

    def _start_scan(self):
        for i in self.tree.get_children():
            self.tree.delete(i)
        self._scan_rows = {}
        self.scan_status.config(text="Descubriendo hosts…", fg=ACC)
        self.q = queue.Queue()
        self.stop_event = threading.Event()
        threading.Thread(target=self._scan_worker, args=(self.stop_event,), daemon=True).start()
        self._poll_scan()

    def _scan_worker(self, stop):
        try:
            arp = na.collect_arp()
            arp_map = {e["ip"]: e for e in arp}
            net = na.guess_subnet()
            if net is None:
                self.q.put(("scandone", None)); return
            hosts = [str(h) for h in net.hosts()]
            if self.fast_var.get():
                hosts = hosts[:64]
            alive = []
            with concurrent.futures.ThreadPoolExecutor(max_workers=128) as ex:
                futs = {ex.submit(na.ping_host, h): h for h in hosts}
                for f in concurrent.futures.as_completed(futs):
                    if stop.is_set():
                        break
                    r = f.result()
                    if not r:
                        continue
                    ip = r["ip"]
                    try:
                        hn = __import__("socket").gethostbyaddr(ip)[0]
                    except Exception:
                        hn = None
                    a = arp_map.get(ip, {})
                    host = {"ip": ip, "rtt_ms": r["rtt_ms"], "ttl": r["ttl"],
                            "os_guess": na.os_from_ttl(r["ttl"]), "hostname": hn,
                            "mac": a.get("mac"), "vendor": a.get("vendor"), "ports": []}
                    alive.append(host)
                    self.q.put(("host", host))
            self.q.put(("sweepdone", len(alive)))
            ports = na.parse_ports(None)
            for host in alive:
                if stop.is_set():
                    break
                host["ports"] = na.scan_host_ports(host["ip"], ports, 0.5, host.get("hostname"))
                self.q.put(("ports", host))
            self.q.put(("scandone", len(alive)))
        except Exception as e:
            self.q.put(("scanerror", str(e)))

    def _poll_scan(self):
        try:
            while True:
                kind, payload = self.q.get_nowait()
                if kind == "host":
                    h = payload
                    iid = self.tree.insert("", "end", values=(
                        h["ip"], h.get("hostname") or "", h.get("mac") or "",
                        h.get("vendor") or "", h.get("os_guess") or "", ""))
                    self._scan_rows[h["ip"]] = (iid, h)
                elif kind == "ports":
                    h = payload
                    if h["ip"] in self._scan_rows:
                        iid, _ = self._scan_rows[h["ip"]]
                        pr = " ".join(str(p["port"]) for p in h["ports"])
                        self._scan_rows[h["ip"]] = (iid, h)
                        self.tree.set(iid, "ports", pr)
                elif kind == "sweepdone":
                    self.scan_status.config(text=f"{payload} hosts · escaneando puertos…", fg=ACC2)
                elif kind == "scandone":
                    self.scan_status.config(text=f"Completado · {payload or 0} hosts", fg=ACC)
                    return
                elif kind == "scanerror":
                    self.scan_status.config(text="Error: "+payload, fg=BAD); return
        except queue.Empty:
            pass
        self.root.after(100, self._poll_scan)

    def _selected_host(self):
        sel = self.tree.selection()
        if not sel:
            return None
        ip = self.tree.item(sel[0])["values"][0]
        rec = self._scan_rows.get(str(ip))
        return rec[1] if rec else None

    def _scan_wol(self):
        h = self._selected_host()
        if not h or not h.get("mac"):
            messagebox.showinfo("Wake-on-LAN", "Selecciona un host con MAC conocida.")
            return
        ok = na.wake_on_lan(h["mac"])
        messagebox.showinfo("Wake-on-LAN",
                            f"Paquete mágico enviado a {h['mac']}" if ok else "No se pudo enviar.")

    def _scan_pdf(self):
        hosts = [rec[1] for rec in self._scan_rows.values()]
        if not hosts:
            messagebox.showinfo("PDF", "No hay dispositivos que exportar.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".pdf",
                                            filetypes=[("PDF", "*.pdf")],
                                            initialfile="netaudit_escaner.pdf")
        if not path:
            return
        try:
            pdfx.pdf_scan_report(hosts, path)
            messagebox.showinfo("PDF", f"Guardado en:\n{path}")
        except Exception as e:
            messagebox.showerror("PDF", f"No se pudo crear el PDF:\n{e}")

    def _scan_open(self):
        h = self._selected_host()
        if not h:
            return
        acts = na.host_actions(h)
        url = next((u for name, u in acts if u.startswith("http")), None)
        if url:
            webbrowser.open(url)
        else:
            messagebox.showinfo("Abrir", f"Sin servicio web. Acciones: " +
                                ", ".join(a[0] for a in acts))

    # =================================================================== #
    # CAPTURA DE PAQUETES (Wireshark)
    # =================================================================== #
    def show_sniffer(self):
        self._clear()
        top = tk.Frame(self.root, bg=BG); top.pack(fill="x", padx=16, pady=(14, 6))
        tk.Label(top, text="Captura de paquetes", bg=BG, fg=TXT, font=self.f_h2).pack(side="left")
        tk.Button(top, text="← Inicio", command=self.show_home, bg=PANEL, fg=ACC2,
                  relief="flat", font=self.f_small, bd=0).pack(side="right")
        bar = tk.Frame(self.root, bg=BG); bar.pack(fill="x", padx=16)
        self.priv = sniff.privileged_backend()
        if self.priv == "root":
            txt, ok = "Listo · captura directa", True
        elif self.priv in ("macos", "linux-pkexec"):
            txt, ok = "Pulsa ▶ Iniciar (pedirá tu contraseña una vez)", True
        else:
            txt, ok = "Sin backend de captura (usa: sudo netaudit --capture)", False
        self.snf_status = tk.Label(bar, text=txt, bg=BG,
                                   fg=ACC if ok else WARN, font=self.f_mono)
        self.snf_status.pack(side="left")
        self.btn_start = tk.Button(bar, text="▶ Iniciar", command=self._snf_start, bg=ACC,
                                   fg="#06231a", relief="flat", font=self.f_small, bd=0, padx=12, pady=4)
        self.btn_start.pack(side="right")
        self.btn_stop = tk.Button(bar, text="■ Parar", command=self._snf_stop, bg=PANEL,
                                  fg=BAD, relief="flat", font=self.f_small, bd=0, padx=12, pady=4)
        self.btn_stop.pack(side="right", padx=6)
        tk.Button(bar, text="Guardar .pcap", command=self._snf_save, bg=PANEL, fg=ACC2,
                  relief="flat", font=self.f_small, bd=0, padx=12, pady=4).pack(side="right")
        tk.Button(bar, text="PDF", command=self._snf_pdf, bg=PANEL, fg=ACC,
                  relief="flat", font=self.f_small, bd=0, padx=12, pady=4).pack(side="right", padx=6)

        cols = ("no", "time", "src", "dst", "proto", "len", "info")
        frame = tk.Frame(self.root, bg=BG); frame.pack(fill="both", expand=True, padx=16, pady=(10, 4))
        self.ptree = ttk.Treeview(frame, columns=cols, show="headings", style="Dark.Treeview", height=14)
        for c, t, w in [("no", "No.", 46), ("time", "Tiempo", 92), ("src", "Origen", 130),
                        ("dst", "Destino", 130), ("proto", "Proto", 56), ("len", "Long", 50),
                        ("info", "Info", 200)]:
            self.ptree.heading(c, text=t); self.ptree.column(c, width=w, anchor="w")
        sb = ttk.Scrollbar(frame, orient="vertical", command=self.ptree.yview)
        self.ptree.configure(yscrollcommand=sb.set)
        self.ptree.pack(side="left", fill="both", expand=True); sb.pack(side="right", fill="y")
        self.ptree.bind("<<TreeviewSelect>>", self._snf_detail)

        self.detail = tk.Text(self.root, height=8, bg="#070b12", fg="#9fd6c0",
                              insertbackground=TXT, relief="flat", font=self.f_mono, bd=0)
        self.detail.pack(fill="x", padx=16, pady=(0, 12))
        self.detail.insert("1.0", "Selecciona un paquete para ver su detalle y hex…")
        self.capture_pkts = []
        if not ok:
            self.btn_start.config(state="disabled")

    def _snf_start(self):
        self.capture_pkts = []
        for i in self.ptree.get_children():
            self.ptree.delete(i)
        self.q = queue.Queue()
        self.stop_event = threading.Event()
        if self.priv == "root":
            self.snf_status.config(text="Capturando…", fg=ACC)
            threading.Thread(target=self._snf_worker_direct, args=(self.stop_event,), daemon=True).start()
        else:
            self.snf_status.config(text="Solicitando permiso…", fg=WARN)
            self._sentinel = sniff.stop_sentinel_path()
            self._pcap_path = sniff.live_pcap_path()
            threading.Thread(target=self._snf_worker_privileged, args=(self.stop_event,), daemon=True).start()
        self._poll_snf()

    def _snf_worker_direct(self, stop):
        try:
            sniff.capture(count=0, on_packet=lambda p: self.q.put(("pkt", p)), stop_event=stop)
            self.q.put(("capdone", None))
        except Exception as e:
            self.q.put(("caperror", str(e)))

    def _snf_worker_privileged(self, stop):
        try:
            ok, err = sniff.start_privileged_capture(
                sniff.default_iface(), self._pcap_path, self._sentinel)
            if not ok:
                self.q.put(("caperror", "Permiso cancelado" + (f": {err}" if err else "")))
                return
            self.q.put(("status", "Capturando…"))
            sniff.read_pcap_stream(self._pcap_path, lambda p: self.q.put(("pkt", p)), stop)
            self.q.put(("capdone", None))
        except Exception as e:
            self.q.put(("caperror", str(e)))

    def _poll_snf(self):
        try:
            while True:
                kind, payload = self.q.get_nowait()
                if kind == "status":
                    self.snf_status.config(text=payload, fg=ACC)
                    continue
                if kind == "pkt":
                    p = payload
                    self.capture_pkts.append(p)
                    import datetime as _dt
                    t = _dt.datetime.fromtimestamp(p["time"]).strftime("%H:%M:%S.%f")[:-3]
                    self.ptree.insert("", "end", iid=str(p["no"]), values=(
                        p["no"], t, p["src"], p["dst"], p["proto"], p["length"], p["info"][:80]))
                    if len(self.capture_pkts) % 8 == 0:
                        self.ptree.yview_moveto(1.0)
                    if len(self.capture_pkts) > 2000:
                        self.stop_event and self.stop_event.set()
                elif kind == "capdone":
                    self._snf_finish(); return
                elif kind == "caperror":
                    self.snf_status.config(text="Error: " + payload, fg=BAD); return
        except queue.Empty:
            pass
        if self.stop_event and not self.stop_event.is_set():
            self.root.after(120, self._poll_snf)
        else:
            self._snf_finish()

    def _snf_finish(self):
        n = len(self.capture_pkts)
        if n == 0:
            err = ""
            try:
                err = sniff.get_capture_error()
            except Exception:
                pass
            last = err.strip().splitlines()[-1] if err.strip() else ""
            self.snf_status.config(
                text="Sin paquetes. " + (last or "Prueba otra interfaz o revisa el permiso."),
                fg=WARN)
            if last:
                messagebox.showwarning("Captura", "No se capturaron paquetes.\n\n"
                                       f"tcpdump dijo:\n{err.strip()[-400:]}")
        else:
            self.snf_status.config(text=f"Detenido · {n} paquetes", fg=ACC2)

    def _snf_stop(self):
        if self.stop_event:
            self.stop_event.set()
        # detener también la captura privilegiada (sin volver a pedir contraseña)
        sentinel = getattr(self, "_sentinel", None)
        if sentinel:
            sniff.stop_privileged_capture(sentinel)

    def _snf_detail(self, _):
        sel = self.ptree.selection()
        if not sel:
            return
        try:
            p = self.capture_pkts[int(sel[0]) - 1]
        except Exception:
            return
        self.detail.delete("1.0", "end")
        d = p.get("detail") or {}
        lines = [f"Paquete #{p['no']}  ·  {p['proto']}  ·  {p['length']} bytes",
                 f"Origen: {p['src']}   Destino: {p['dst']}",
                 f"Ethernet: {p.get('eth_src')} → {p.get('eth_dst')}", ""]
        if d.get("transport"):
            lines.append("Info: " + d["transport"].get("info", ""))
        lines.append("")
        lines.append(p.get("hex", ""))
        self.detail.insert("1.0", "\n".join(lines))

    def _snf_save(self):
        if not self.capture_pkts:
            messagebox.showinfo("Guardar", "No hay paquetes capturados.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".pcap",
                                            filetypes=[("Captura pcap", "*.pcap")],
                                            initialfile="netaudit_capture.pcap")
        if path:
            sniff.write_pcap(path, self.capture_pkts)
            messagebox.showinfo("Guardado", f"Guardado en:\n{path}\n\nÁbrelo en Wireshark.")

    def _snf_pdf(self):
        if not self.capture_pkts:
            messagebox.showinfo("PDF", "No hay paquetes capturados.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".pdf",
                                            filetypes=[("PDF", "*.pdf")],
                                            initialfile="netaudit_captura.pdf")
        if path:
            try:
                pdfx.pdf_capture_report(self.capture_pkts, path)
                messagebox.showinfo("PDF", f"Guardado en:\n{path}")
            except Exception as e:
                messagebox.showerror("PDF", f"No se pudo crear el PDF:\n{e}")


def main():
    root = tk.Tk()
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
