#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
netaudit · interfaz gráfica (estilo Apple, oscura y cuidada).

Pensada para empaquetarse como app de macOS (.app dentro de un .dmg), pero
también funciona en Windows/Linux. Ejecuta el análisis de red en segundo plano
y abre el dashboard HTML al terminar.

    python3 netaudit_gui.py
"""

import os
import queue
import sys
import tempfile
import threading
import webbrowser

import tkinter as tk
import tkinter.font as tkfont

import network_analyzer as na

# ---- Paleta (coherente con el dashboard HTML) ----------------------------- #
BG       = "#0b0f17"
PANEL    = "#121826"
LINE     = "#1f2a3d"
TXT      = "#e7edf5"
MUTED    = "#6b7a93"
ACC      = "#37d39a"
ACC2     = "#4aa3ff"
BAD      = "#ff5d6c"
WARN     = "#ffb454"

W, H = 540, 640


def pick_font(root, candidates, size, weight="normal"):
    fams = set(tkfont.families(root))
    for c in candidates:
        if c in fams:
            return tkfont.Font(root=root, family=c, size=size, weight=weight)
    return tkfont.Font(root=root, size=size, weight=weight)


class RoundButton:
    """Botón redondeado dibujado en el canvas (look Apple, multiplataforma)."""
    def __init__(self, cv, x, y, w, h, text, font, fill, fg, command, radius=14):
        self.cv, self.command, self.enabled = cv, command, True
        self.fill, self.fg = fill, fg
        self.items = []
        self._round_rect(x, y, x + w, y + h, radius, fill)
        self.txt = cv.create_text(x + w / 2, y + h / 2, text=text, fill=fg,
                                  font=font, tags=("btn",))
        self.bbox = (x, y, x + w, y + h)
        for it in self.items + [self.txt]:
            cv.tag_bind(it, "<Button-1>", self._click)
            cv.tag_bind(it, "<Enter>", lambda e: cv.config(cursor="hand2"))
            cv.tag_bind(it, "<Leave>", lambda e: cv.config(cursor=""))

    def _round_rect(self, x1, y1, x2, y2, r, fill):
        cv = self.cv
        pts = [x1+r, y1, x2-r, y1, x2, y1, x2, y1+r, x2, y2-r, x2, y2,
               x2-r, y2, x1+r, y2, x1, y2, x1, y2-r, x1, y1+r, x1, y1]
        self.items.append(cv.create_polygon(pts, smooth=True, fill=fill, outline=fill))

    def _click(self, _):
        if self.enabled and self.command:
            self.command()

    def set_enabled(self, on):
        self.enabled = on
        color = self.fill if on else "#243047"
        for it in self.items:
            self.cv.itemconfig(it, fill=color, outline=color)
        self.cv.itemconfig(self.txt, fill=self.fg if on else MUTED)

    def set_text(self, t):
        self.cv.itemconfig(self.txt, text=t)


class App:
    def __init__(self, root):
        self.root = root
        root.title("netaudit")
        root.geometry(f"{W}x{H}")
        root.resizable(False, False)
        root.configure(bg=BG)
        try:
            root.tk.call("tk", "scaling", 2.0)
        except Exception:
            pass

        self.q = queue.Queue()
        self.report_path = os.path.join(tempfile.gettempdir(), "netaudit_report.html")
        self.data = None

        self.f_title = pick_font(root, ["SF Pro Display", "Helvetica Neue", "Helvetica", "Arial"], 30, "bold")
        self.f_sub   = pick_font(root, ["SF Pro Text", "Helvetica Neue", "Helvetica", "Arial"], 13)
        self.f_btn   = pick_font(root, ["SF Pro Text", "Helvetica Neue", "Helvetica", "Arial"], 15, "bold")
        self.f_small = pick_font(root, ["SF Pro Text", "Helvetica Neue", "Helvetica", "Arial"], 11)
        self.f_gauge = pick_font(root, ["SF Pro Display", "Helvetica Neue", "Helvetica"], 52, "bold")
        self.f_status= pick_font(root, ["SF Mono", "Menlo", "Consolas", "Courier"], 11)

        self.cv = tk.Canvas(root, width=W, height=H, bg=BG, highlightthickness=0)
        self.cv.pack(fill="both", expand=True)
        self.build_home()

    # ---- pantalla de inicio ---- #
    def build_home(self):
        cv = self.cv
        cv.delete("all")
        self.draw_logo(W / 2, 96, 34)
        cv.create_text(W / 2, 168, text="netaudit", fill=TXT, font=self.f_title)
        cv.create_text(W / 2, 198, text="Auditoría de red · análisis profesional",
                       fill=MUTED, font=self.f_sub)

        # tarjeta central
        self._panel(60, 240, W - 60, 470)
        cv.create_text(W / 2, 280, text="Analiza tu red en un clic",
                       fill=TXT, font=self.f_btn)
        cv.create_text(W / 2, 312, width=W - 160, justify="center", fill=MUTED, font=self.f_small,
                       text="Inventario local, IP pública, escaneo de la LAN, "
                            "puertos, Wi-Fi, DNS, velocidad y un score de seguridad.")

        # opción rápida
        self.fast_var = tk.BooleanVar(value=False)
        self.chk = cv.create_text(W / 2, 352, fill=MUTED, font=self.f_small,
                                  text="☐  Análisis rápido (menos pruebas)", tags=("chk",))
        cv.tag_bind("chk", "<Button-1>", self._toggle_fast)
        cv.tag_bind("chk", "<Enter>", lambda e: cv.config(cursor="hand2"))
        cv.tag_bind("chk", "<Leave>", lambda e: cv.config(cursor=""))

        self.btn = RoundButton(cv, W / 2 - 130, 388, 260, 52,
                               "Analizar mi red", self.f_btn, ACC, "#06231a",
                               command=self.start)

        # progreso (oculto al inicio)
        self.status_id = cv.create_text(W / 2, 510, text="", fill=MUTED, font=self.f_status)
        self.track = None
        self.bar = None

        cv.create_text(W / 2, H - 30, fill=MUTED, font=self.f_small,
                       text=f"netaudit v{na.__version__} · úsalo solo en redes propias o con permiso")

    def _toggle_fast(self, _):
        self.fast_var.set(not self.fast_var.get())
        mark = "☑" if self.fast_var.get() else "☐"
        self.cv.itemconfig(self.chk, text=f"{mark}  Análisis rápido (menos pruebas)",
                           fill=ACC if self.fast_var.get() else MUTED)

    def draw_logo(self, cx, cy, r):
        cv = self.cv
        # squircle de fondo
        self._round_squircle(cx - r - 14, cy - r - 14, cx + r + 14, cy + r + 14, 22,
                             fill=PANEL, outline=LINE)
        # radar: arcos concéntricos
        for i, rr in enumerate((r, r * 0.66, r * 0.33)):
            col = ACC if i == 0 else ACC2 if i == 1 else "#2b6f5a"
            cv.create_oval(cx - rr, cy - rr, cx + rr, cy + rr, outline=col, width=2)
        # barrido + nodos
        cv.create_line(cx, cy, cx + r * 0.92, cy - r * 0.55, fill=ACC, width=2)
        cv.create_oval(cx - 3, cy - 3, cx + 3, cy + 3, fill=ACC, outline=ACC)
        cv.create_oval(cx + r * 0.55 - 4, cy - r * 0.30 - 4,
                       cx + r * 0.55 + 4, cy - r * 0.30 + 4, fill=ACC2, outline=ACC2)
        cv.create_oval(cx - r * 0.5 - 3, cy + r * 0.45 - 3,
                       cx - r * 0.5 + 3, cy + r * 0.45 + 3, fill=WARN, outline=WARN)

    def _round_squircle(self, x1, y1, x2, y2, r, fill, outline):
        pts = [x1+r, y1, x2-r, y1, x2, y1, x2, y1+r, x2, y2-r, x2, y2,
               x2-r, y2, x1+r, y2, x1, y2, x1, y2-r, x1, y1+r, x1, y1]
        self.cv.create_polygon(pts, smooth=True, fill=fill, outline=outline, width=1.5)

    def _panel(self, x1, y1, x2, y2):
        r = 18
        pts = [x1+r, y1, x2-r, y1, x2, y1, x2, y1+r, x2, y2-r, x2, y2,
               x2-r, y2, x1+r, y2, x1, y2, x1, y2-r, x1, y1+r, x1, y1]
        self.cv.create_polygon(pts, smooth=True, fill=PANEL, outline=LINE, width=1)

    # ---- ejecución ---- #
    def start(self):
        self.btn.set_enabled(False)
        self.btn.set_text("Analizando…")
        self.cv.itemconfig(self.chk, state="hidden")
        # barra de progreso
        x1, x2, y = 90, W - 90, 540
        self.track = self.cv.create_rectangle(x1, y, x2, y + 8, fill="#16202f", outline="")
        self.bar = self.cv.create_rectangle(x1, y, x1, y + 8, fill=ACC, outline="")
        self._bar_x1, self._bar_x2, self._bar_target = x1, x2, 0.0
        self._bar_cur = 0.0
        self.cv.itemconfig(self.status_id, text="Iniciando…", fill=ACC)

        opts = na.Options(fast=self.fast_var.get(), output=self.report_path,
                          json=os.path.join(tempfile.gettempdir(), "netaudit_report.json"))
        threading.Thread(target=self._worker, args=(opts,), daemon=True).start()
        self._poll()
        self._animate_bar()

    PHASES = 13

    def _worker(self, opts):
        try:
            counter = {"n": 0}
            def status(msg):
                counter["n"] += 1
                self.q.put(("status", msg, counter["n"] / self.PHASES))
            data = na.analyze(opts, status=status)
            self.q.put(("done", data, 1.0))
        except Exception as e:
            self.q.put(("error", str(e), 0))

    def _poll(self):
        try:
            while True:
                kind, payload, prog = self.q.get_nowait()
                if kind == "status":
                    self.cv.itemconfig(self.status_id, text=payload, fill=ACC)
                    self._bar_target = min(0.97, prog)
                elif kind == "done":
                    self.data = payload
                    self._bar_target = 1.0
                    self.root.after(350, self.build_results)
                    return
                elif kind == "error":
                    self.cv.itemconfig(self.status_id, text="Error: " + payload, fill=BAD)
                    self.btn.set_enabled(True)
                    self.btn.set_text("Reintentar")
                    return
        except queue.Empty:
            pass
        self.root.after(80, self._poll)

    def _animate_bar(self):
        if self.bar is None:
            return
        self._bar_cur += (self._bar_target - self._bar_cur) * 0.18
        width = self._bar_x1 + (self._bar_x2 - self._bar_x1) * self._bar_cur
        self.cv.coords(self.bar, self._bar_x1, 540, width, 548)
        if self.data is None or self._bar_cur < 0.999:
            self.root.after(30, self._animate_bar)

    # ---- pantalla de resultados ---- #
    def build_results(self):
        cv = self.cv
        cv.delete("all")
        sec = self.data.get("security") or {}
        score = sec.get("score", 0)
        grade = sec.get("grade", "—")
        color = ACC if grade in ("A", "B") else WARN if grade == "C" else BAD

        cv.create_text(W / 2, 60, text="Análisis completado", fill=TXT, font=self.f_title)
        cv.create_text(W / 2, 92, text="Tu red, auditada", fill=MUTED, font=self.f_sub)

        # gauge circular
        cx, cy, r = W / 2, 200, 78
        cv.create_oval(cx - r, cy - r, cx + r, cy + r, outline="#16202f", width=12)
        extent = -359.9 * (score / 100.0) if score else -0.1
        cv.create_arc(cx - r, cy - r, cx + r, cy + r, start=90, extent=extent,
                      outline=color, width=12, style="arc")
        cv.create_text(cx, cy - 6, text=str(score), fill=color, font=self.f_gauge)
        cv.create_text(cx, cy + 34, text=f"Grado {grade} · seguridad", fill=MUTED, font=self.f_small)

        # métricas
        lan = self.data.get("lan") or []
        n_ports = sum(len(h.get("ports", [])) for h in lan)
        pub = (self.data.get("public") or {})
        spd = (self.data.get("speedtest") or {})
        stats = [
            ("Hosts en la red", str(len(lan))),
            ("Puertos abiertos", str(n_ports)),
            ("IP pública", pub.get("ip") or "—"),
            ("Velocidad ↓", (f"{spd.get('mbps')} Mbps" if spd.get("mbps") else "—")),
        ]
        y = 312
        for i, (k, v) in enumerate(stats):
            yy = y + (i // 2) * 60
            xx = 70 if i % 2 == 0 else W / 2 + 10
            self._panel(xx, yy, xx + (W / 2 - 80), yy + 48)
            cv.create_text(xx + 16, yy + 16, anchor="w", text=k, fill=MUTED, font=self.f_small)
            cv.create_text(xx + 16, yy + 34, anchor="w", text=v, fill=TXT, font=self.f_btn)

        # hallazgos resumen
        findings = sec.get("findings", [])
        msg = ("Sin riesgos detectados 🎉" if not findings
               else f"{len(findings)} hallazgo(s) de seguridad — revisa el informe")
        cv.create_text(W / 2, 452, text=msg,
                       fill=ACC if not findings else WARN, font=self.f_small)

        RoundButton(cv, W / 2 - 130, 482, 260, 52, "Ver informe completo",
                    self.f_btn, ACC, "#06231a", command=self.open_report)
        RoundButton(cv, W / 2 - 130, 546, 260, 44, "Analizar de nuevo",
                    self.f_small, PANEL, ACC2, command=self.build_home, radius=12)

        cv.create_text(W / 2, H - 22, fill=MUTED, font=self.f_small,
                       text=f"netaudit v{na.__version__}")

    def open_report(self):
        try:
            webbrowser.open("file://" + os.path.abspath(self.report_path))
        except Exception:
            pass


def main():
    root = tk.Tk()
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
