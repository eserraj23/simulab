#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NetCat GUI - Envoltorio gráfico multiplataforma para la utilidad Netcat (nc).

* Sin dependencias externas: solo biblioteca estándar (tkinter/ttk).
* Compatible con Python 3.5+ en Linux y macOS.
* Detecta la variante de nc instalada (OpenBSD/macOS, Traditional, GNU, Ncat,
  BusyBox) y adapta la sintaxis de la línea de comandos automáticamente.
* Recepción y envío en hilos secundarios: la interfaz nunca se congela.

Ejecutar:  python3 netcat_gui.py
"""

import codecs
import datetime
import ipaddress
import os
import queue
import re
import shutil
import subprocess
import sys
import threading
import time

try:
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox
    from tkinter import font as tkfont
except ImportError:  # pragma: no cover
    sys.stderr.write(
        "No se encontró tkinter. Instálalo con:\n"
        "  Debian/Ubuntu: sudo apt install python3-tk\n"
        "  Fedora:        sudo dnf install python3-tkinter\n"
        "  Arch:          sudo pacman -S tk\n"
        "  macOS (brew):  brew install python-tk\n")
    sys.exit(1)

APP_NAME = "NetCat GUI"

# ----------------------------------------------------------------- paleta ---
BG = "#1b1d27"
PANEL = "#262938"
PANEL_HI = "#313549"
CONSOLE_BG = "#12131a"
FG = "#e6e8f2"
MUTED = "#8a90aa"
ACCENT = "#6c8cff"
ACCENT_HI = "#869fff"
GREEN = "#3ddc84"
RED = "#ff5c6c"
AMBER = "#ffb454"
CYAN = "#7fdbff"

EOLS = {
    "LF  (\\n)": "\n",
    "CRLF (\\r\\n)": "\r\n",
    "CR  (\\r)": "\r",
    "Ninguno": "",
}

# ------------------------------------------------------------- utilidades ---
HOST_RE = re.compile(
    r"^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")

SYNTAX_RE = re.compile(
    r"usage|invalid option|unknown option|illegal option|unrecognized option|"
    r"mutually exclusive|cannot use|incompatible", re.I)

PEER_RE = re.compile(
    r"succeeded|\bopen\b|connected to|connection (from|received)|"
    r"connect to .* from|accepted", re.I)

ERROR_MAP = [
    (r"address already in use|already in use|bind.*failed",
     "El puerto ya está en uso por otro proceso. Elige otro puerto o cierra "
     "la aplicación que lo ocupa."),
    (r"connection refused",
     "Conexión rechazada: no hay ningún servicio escuchando en esa IP/puerto "
     "(o un cortafuegos lo bloquea)."),
    (r"permission denied|operation not permitted",
     "Permiso denegado. Los puertos inferiores a 1024 requieren privilegios "
     "de administrador (sudo)."),
    (r"name or service not known|nodename nor servname|unknown host|"
     r"getaddrinfo|forward host lookup|could not resolve|resolve",
     "No se pudo resolver el host o la dirección IP no es válida."),
    (r"cannot assign requested address|can't assign requested address",
     "La IP local indicada no pertenece a ningún interfaz de este equipo."),
    (r"no route to host", "No hay ruta hacia el host indicado."),
    (r"network is unreachable", "La red de destino es inalcanzable."),
    (r"timed out|timeout", "Se agotó el tiempo de espera de la conexión."),
]


def friendly_error(text):
    for pattern, message in ERROR_MAP:
        if re.search(pattern, text or "", re.I):
            return message
    return None


def valid_host(host):
    """Valida una IPv4/IPv6 o un nombre de host."""
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    if re.match(r"^[\d.]+$", host):  # parece IPv4 pero no lo es (p. ej. 999.1.1.1)
        return False
    return bool(HOST_RE.match(host))


def find_nc():
    for name in ("nc", "ncat", "netcat", "nc.openbsd", "nc.traditional"):
        path = shutil.which(name)
        if path:
            return path
    return None


def detect_style(path):
    """Devuelve (estilo, nombre_variante). estilo: 'bsd' o 'trad'."""
    try:
        proc = subprocess.Popen([path, "-h"], stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT)
        try:
            out, _ = proc.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
            out, _ = proc.communicate()
        text = out.decode("utf-8", "replace").lower()
    except Exception:
        return "trad", "desconocida"
    if "busybox" in text:
        return "trad", "BusyBox"
    if "ncat" in text:
        return "trad", "Ncat"
    if "gnu netcat" in text:
        return "trad", "GNU netcat"
    if "usage: nc" in text or "openbsd" in text:
        return "bsd", "OpenBSD/macOS"
    if "[v1.10" in text or "connect to somewhere" in text:
        return "trad", "Traditional"
    return "trad", "desconocida"


def build_argv(path, style, mode, proto, host, port):
    argv = [path]
    if mode == "server":
        argv.append("-l")
        if proto == "UDP":
            argv.append("-u")
        argv += ["-v", "-n"]
        if style == "bsd":          # OpenBSD / macOS: -l no admite -p
            if host:
                argv.append(host)
            argv.append(str(port))
        else:                       # Traditional / GNU / Ncat / BusyBox
            if host:
                argv += ["-s", host]
            argv += ["-p", str(port)]
    else:
        argv.append("-v")
        if proto == "UDP":
            argv.append("-u")
        argv += [host, str(port)]
    return argv


# ------------------------------------------------------------ back-end nc ---
class Backend(object):
    """Gestiona el proceso nc y sus hilos de E/S. Se comunica con la GUI
    exclusivamente mediante una cola de eventos (thread-safe)."""

    def __init__(self, events):
        self.events = events
        self.proc = None
        self.send_q = queue.Queue()
        self.user_stopped = False
        self.running = False

    def emit(self, kind, *payload):
        self.events.put((kind,) + payload)

    # -- API pública -------------------------------------------------------
    def start(self, path, style, mode, proto, host, port):
        self.user_stopped = False
        self.running = True
        self.send_q = queue.Queue()
        t = threading.Thread(target=self._run,
                             args=(path, style, mode, proto, host, port))
        t.daemon = True
        t.start()

    def send(self, data):
        if self.running:
            self.send_q.put(data)

    def stop(self):
        if not self.running:
            return
        self.user_stopped = True
        proc = self.proc
        self.send_q.put(None)

        def killer():
            if proc is None:
                return
            for action in (proc.stdin.close, proc.terminate):
                try:
                    action()
                except Exception:
                    pass
            try:
                proc.wait(timeout=2)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass

        th = threading.Thread(target=killer)
        th.daemon = True
        th.start()

    # -- internos ----------------------------------------------------------
    def _stderr_line(self, line):
        self.emit("nc", line)
        if PEER_RE.search(line):
            self.emit("peer", line)

    def _run(self, path, style, mode, proto, host, port):
        other = "trad" if style == "bsd" else "bsd"
        rc, errtext = None, ""
        for attempt, st in enumerate((style, other)):
            if self.user_stopped:
                break
            argv = build_argv(path, st, mode, proto, host, port)
            self.emit("sys", "$ " + " ".join(argv))
            try:
                proc = subprocess.Popen(argv, stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, bufsize=0)
            except OSError as exc:
                self.running = False
                self.emit("fatal", "No se pudo ejecutar netcat: %s" % exc)
                return
            self.proc = proc
            started = time.time()
            lock = threading.Lock()
            state = {"held": True, "pending": [], "lines": []}

            def release(proc=proc, lock=lock, state=state):
                with lock:
                    if not state["held"]:
                        return
                    state["held"] = False
                    pending, state["pending"] = state["pending"], []
                for ln in pending:
                    self._stderr_line(ln)
                if proc.poll() is None:
                    self.emit("alive")

            def err_reader(proc=proc, lock=lock, state=state):
                try:
                    for raw in iter(proc.stderr.readline, b""):
                        ln = raw.decode("utf-8", "replace").rstrip("\r\n")
                        if not ln:
                            continue
                        state["lines"].append(ln)
                        with lock:
                            if state["held"]:
                                state["pending"].append(ln)
                                continue
                        self._stderr_line(ln)
                except (OSError, ValueError):
                    pass

            def out_reader(proc=proc):
                decoder = codecs.getincrementaldecoder("utf-8")("replace")
                fd = proc.stdout.fileno()
                while True:
                    try:
                        data = os.read(fd, 4096)
                    except OSError:
                        break
                    if not data:
                        break
                    text = decoder.decode(data)
                    if text:
                        self.emit("rx", text)

            def writer(proc=proc, q=self.send_q):
                while True:
                    try:
                        data = q.get(timeout=0.2)
                    except queue.Empty:
                        if proc.poll() is not None:
                            break
                        continue
                    if data is None:
                        break
                    try:
                        view = memoryview(data)
                        while len(view):
                            n = proc.stdin.write(view)
                            view = view[n:]
                    except (OSError, ValueError):
                        self.emit("sys_err",
                                  "No se pudo enviar: la conexión está cerrada.")
                        break

            timer = threading.Timer(1.2, release)
            timer.daemon = True
            timer.start()
            threads = []
            for fn in (err_reader, out_reader, writer):
                th = threading.Thread(target=fn)
                th.daemon = True
                th.start()
                threads.append(th)

            rc = proc.wait()
            timer.cancel()
            self.send_q.put(None)
            for th in threads:
                th.join(1.0)
            errtext = "\n".join(state["lines"])
            elapsed = time.time() - started

            retry = (attempt == 0 and not self.user_stopped and rc != 0
                     and elapsed < 1.2 and SYNTAX_RE.search(errtext))
            if retry:
                with lock:
                    state["held"] = False
                    state["pending"] = []
                self.emit("sys", "Sintaxis de nc distinta a la esperada; "
                                 "reintentando con la alternativa…")
                self.send_q = queue.Queue()
                continue
            release()
            break

        self.running = False
        self.proc = None
        self.emit("exit", rc, self.user_stopped, errtext)


# ------------------------------------------------------------------- GUI ----
class App(object):
    def __init__(self, root):
        self.root = root
        root.title(APP_NAME)
        root.geometry("900x660")
        root.minsize(740, 540)
        root.configure(bg=BG)

        self.events = queue.Queue()
        self.backend = Backend(self.events)
        self.nc_path = find_nc()
        self.nc_style = "trad"
        self.nc_variant = "detectando…"
        self._at_line_start = True
        self._history = []
        self._hist_idx = 0
        self._cfg_widgets = []

        self._setup_fonts()
        self._setup_style()
        self._build_ui()
        self.set_status("off", "Desconectado")
        self._on_mode_change()

        root.protocol("WM_DELETE_WINDOW", self._on_close)
        root.after(40, self._poll)

        if self.nc_path:
            threading.Thread(target=self._detect_thread, daemon=True).start()
        else:
            self.nc_variant = "no encontrado"
            self._update_nc_info()
            self.log_line("No se encontró netcat (nc) en el PATH.", "err")
            self.log_line("Instálalo: Debian/Ubuntu 'sudo apt install "
                          "netcat-openbsd' · Fedora 'sudo dnf install "
                          "nmap-ncat' · macOS: viene incluido.", "sys")

    # -- estilo ------------------------------------------------------------
    def _setup_fonts(self):
        families = set(tkfont.families())

        def pick(options, fallback):
            for name in options:
                if name in families:
                    return name
            return fallback

        ui = pick(["Inter", "Segoe UI", "SF Pro Text", "Helvetica Neue",
                   "Ubuntu", "Cantarell", "DejaVu Sans"], "TkDefaultFont")
        mono = pick(["JetBrains Mono", "Fira Code", "Menlo", "SF Mono",
                     "DejaVu Sans Mono", "Liberation Mono", "Consolas",
                     "Monaco"], "Courier")
        self.f_ui = (ui, 10)
        self.f_ui_b = (ui, 10, "bold")
        self.f_small = (ui, 9)
        self.f_mono = (mono, 11)

    def _setup_style(self):
        s = ttk.Style(self.root)
        try:
            s.theme_use("clam")
        except tk.TclError:
            pass
        s.configure(".", background=BG, foreground=FG, font=self.f_ui,
                    fieldbackground=PANEL, bordercolor=PANEL_HI,
                    lightcolor=PANEL, darkcolor=PANEL, troughcolor=BG)
        s.configure("TFrame", background=BG)
        s.configure("Card.TFrame", background=PANEL)
        s.configure("TLabel", background=BG, foreground=FG)
        s.configure("Card.TLabel", background=PANEL, foreground=FG)
        s.configure("Muted.TLabel", background=BG, foreground=MUTED,
                    font=self.f_small)
        s.configure("Status.TLabel", background=PANEL, foreground=FG,
                    font=self.f_ui_b)
        s.configure("TEntry", fieldbackground=CONSOLE_BG, foreground=FG,
                    insertcolor=FG, padding=6, bordercolor=PANEL_HI)
        s.map("TEntry", bordercolor=[("focus", ACCENT)],
              fieldbackground=[("disabled", PANEL)],
              foreground=[("disabled", MUTED)])
        s.configure("TCombobox", fieldbackground=CONSOLE_BG, foreground=FG,
                    background=PANEL_HI, arrowcolor=FG, padding=5,
                    selectbackground=CONSOLE_BG, selectforeground=FG)
        s.map("TCombobox",
              fieldbackground=[("readonly", CONSOLE_BG),
                               ("disabled", PANEL)],
              foreground=[("disabled", MUTED)],
              selectbackground=[("readonly", CONSOLE_BG)],
              selectforeground=[("readonly", FG)])
        self.root.option_add("*TCombobox*Listbox.background", CONSOLE_BG)
        self.root.option_add("*TCombobox*Listbox.foreground", FG)
        self.root.option_add("*TCombobox*Listbox.selectBackground", ACCENT)
        self.root.option_add("*TCombobox*Listbox.selectForeground", "#ffffff")
        s.configure("TButton", background=PANEL_HI, foreground=FG,
                    padding=(14, 7), borderwidth=0, focusthickness=0,
                    focuscolor=PANEL_HI)
        s.map("TButton",
              background=[("disabled", PANEL), ("pressed", ACCENT),
                          ("active", "#3d4260")],
              foreground=[("disabled", MUTED)])
        s.configure("Accent.TButton", background=ACCENT, foreground="#ffffff",
                    font=self.f_ui_b)
        s.map("Accent.TButton",
              background=[("disabled", PANEL), ("pressed", "#5273e6"),
                          ("active", ACCENT_HI)],
              foreground=[("disabled", MUTED)])
        s.configure("Danger.TButton", background="#c2415a",
                    foreground="#ffffff", font=self.f_ui_b)
        s.map("Danger.TButton",
              background=[("disabled", PANEL), ("pressed", "#9c3248"),
                          ("active", RED)],
              foreground=[("disabled", MUTED)])
        s.configure("TRadiobutton", background=PANEL, foreground=FG,
                    focuscolor=PANEL, indicatorcolor=CONSOLE_BG)
        s.map("TRadiobutton", background=[("active", PANEL)],
              indicatorcolor=[("selected", ACCENT)],
              foreground=[("disabled", MUTED)])
        s.configure("TCheckbutton", background=BG, foreground=FG,
                    focuscolor=BG, indicatorcolor=CONSOLE_BG)
        s.map("TCheckbutton", background=[("active", BG)],
              indicatorcolor=[("selected", ACCENT)])
        s.configure("Vertical.TScrollbar", background=PANEL_HI,
                    troughcolor=CONSOLE_BG, arrowcolor=MUTED, borderwidth=0)
        s.map("Vertical.TScrollbar", background=[("active", "#444a6b")])

    # -- construcción de la interfaz --------------------------------------
    def _build_ui(self):
        outer = ttk.Frame(self.root, padding=14)
        outer.pack(fill="both", expand=True)

        # Tarjeta de configuración
        card = ttk.Frame(outer, style="Card.TFrame", padding=14)
        card.pack(fill="x")
        card.columnconfigure(1, weight=1)

        self.mode_var = tk.StringVar(value="server")
        ttk.Label(card, text="Modo", style="Card.TLabel",
                  font=self.f_ui_b).grid(row=0, column=0, sticky="w")
        modes = ttk.Frame(card, style="Card.TFrame")
        modes.grid(row=0, column=1, columnspan=3, sticky="w", padx=(10, 0))
        for text, val in (("Servidor (Listener)", "server"),
                          ("Cliente (Conexión)", "client")):
            rb = ttk.Radiobutton(modes, text=text, value=val,
                                 variable=self.mode_var,
                                 command=self._on_mode_change)
            rb.pack(side="left", padx=(0, 18))
            self._cfg_widgets.append(rb)

        self.host_label = ttk.Label(card, text="IP", style="Card.TLabel")
        self.host_label.grid(row=1, column=0, sticky="w", pady=(12, 0))
        self.host_var = tk.StringVar()
        host_entry = ttk.Entry(card, textvariable=self.host_var, width=26)
        host_entry.grid(row=1, column=1, sticky="ew", padx=(10, 12),
                        pady=(12, 0))
        self._cfg_widgets.append(host_entry)

        port_box = ttk.Frame(card, style="Card.TFrame")
        port_box.grid(row=1, column=2, pady=(12, 0))
        ttk.Label(port_box, text="Puerto", style="Card.TLabel").pack(
            side="left", padx=(0, 8))
        self.port_var = tk.StringVar(value="4444")
        port_entry = ttk.Entry(port_box, textvariable=self.port_var, width=8)
        port_entry.pack(side="left")
        self._cfg_widgets.append(port_entry)

        proto_box = ttk.Frame(card, style="Card.TFrame")
        proto_box.grid(row=1, column=3, padx=(12, 0), pady=(12, 0))
        ttk.Label(proto_box, text="Protocolo", style="Card.TLabel").pack(
            side="left", padx=(0, 8))
        self.proto_var = tk.StringVar(value="TCP")
        proto = ttk.Combobox(proto_box, textvariable=self.proto_var,
                             values=("TCP", "UDP"), state="readonly",
                             width=6)
        proto.pack(side="left")
        self._cfg_widgets.append(proto)

        # Fila de controles + estado
        ctrl = ttk.Frame(card, style="Card.TFrame")
        ctrl.grid(row=2, column=0, columnspan=4, sticky="ew", pady=(14, 0))
        self.start_btn = ttk.Button(ctrl, text="Iniciar servidor",
                                    style="Accent.TButton",
                                    command=self.on_start)
        self.start_btn.pack(side="left")
        self.stop_btn = ttk.Button(ctrl, text="Detener",
                                   style="Danger.TButton",
                                   command=self.on_stop, state="disabled")
        self.stop_btn.pack(side="left", padx=(10, 0))

        status = ttk.Frame(ctrl, style="Card.TFrame")
        status.pack(side="right")
        self.canvas = tk.Canvas(status, width=18, height=18, bg=PANEL,
                                highlightthickness=0, bd=0)
        self.canvas.pack(side="left", padx=(0, 8))
        self.dot = self.canvas.create_oval(2, 2, 16, 16, fill=RED,
                                           outline=RED)
        self.status_var = tk.StringVar()
        ttk.Label(status, textvariable=self.status_var,
                  style="Status.TLabel").pack(side="left")

        # Barra de herramientas de la consola
        bar = ttk.Frame(outer)
        bar.pack(fill="x", pady=(12, 6))
        self.autoscroll_var = tk.BooleanVar(value=True)
        self.timestamp_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(bar, text="Autoscroll",
                        variable=self.autoscroll_var).pack(side="left")
        ttk.Checkbutton(bar, text="Marca de tiempo",
                        variable=self.timestamp_var).pack(side="left",
                                                          padx=(12, 0))
        ttk.Button(bar, text="Guardar log",
                   command=self.on_save).pack(side="right")
        ttk.Button(bar, text="Limpiar",
                   command=self.on_clear).pack(side="right", padx=(0, 8))

        # Consola
        console = ttk.Frame(outer)
        console.pack(fill="both", expand=True)
        self.text = tk.Text(console, bg=CONSOLE_BG, fg=FG, font=self.f_mono,
                            insertbackground=FG, relief="flat", bd=0,
                            padx=12, pady=10, wrap="word", state="disabled",
                            selectbackground=ACCENT, highlightthickness=1,
                            highlightbackground=PANEL_HI,
                            highlightcolor=PANEL_HI, cursor="arrow")
        scroll = ttk.Scrollbar(console, orient="vertical",
                               command=self.text.yview)
        self.text.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y")
        self.text.pack(side="left", fill="both", expand=True)
        self.text.tag_configure("rx", foreground=GREEN)
        self.text.tag_configure("tx", foreground=CYAN)
        self.text.tag_configure("sys", foreground=MUTED)
        self.text.tag_configure("nc", foreground=AMBER)
        self.text.tag_configure("err", foreground=RED)

        # Entrada de envío
        send = ttk.Frame(outer)
        send.pack(fill="x", pady=(10, 0))
        self.eol_var = tk.StringVar(value="LF  (\\n)")
        eol = ttk.Combobox(send, textvariable=self.eol_var,
                           values=list(EOLS.keys()), state="readonly",
                           width=12)
        eol.pack(side="right", padx=(8, 0))
        self.send_btn = ttk.Button(send, text="Enviar", style="Accent.TButton",
                                   command=self.on_send, state="disabled")
        self.send_btn.pack(side="right", padx=(8, 0))
        self.msg_var = tk.StringVar()
        self.msg_entry = ttk.Entry(send, textvariable=self.msg_var,
                                   font=self.f_mono, state="disabled")
        self.msg_entry.pack(side="left", fill="x", expand=True)
        self.msg_entry.bind("<Return>", lambda e: self.on_send())
        self.msg_entry.bind("<KP_Enter>", lambda e: self.on_send())
        self.msg_entry.bind("<Up>", self._hist_prev)
        self.msg_entry.bind("<Down>", self._hist_next)

        self.info_var = tk.StringVar()
        ttk.Label(outer, textvariable=self.info_var,
                  style="Muted.TLabel").pack(anchor="w", pady=(8, 0))
        self._update_nc_info()

    # -- helpers de UI -----------------------------------------------------
    def _update_nc_info(self):
        self.info_var.set("netcat: %s · variante: %s" %
                          (self.nc_path or "no encontrado", self.nc_variant))

    def _detect_thread(self):
        style, name = detect_style(self.nc_path)
        self.events.put(("variant", style, name))

    def set_status(self, state, text):
        color = {"off": RED, "wait": AMBER, "on": GREEN}[state]
        self.status_state = state
        self.canvas.itemconfigure(self.dot, fill=color, outline=color)
        self.status_var.set(text)

    def _on_mode_change(self):
        server = self.mode_var.get() == "server"
        host = self.host_var.get().strip()
        if server:
            self.host_label.configure(text="IP local (opcional)")
            self.start_btn.configure(text="Iniciar servidor")
            if host == "127.0.0.1":
                self.host_var.set("")
        else:
            self.host_label.configure(text="IP / host remoto")
            self.start_btn.configure(text="Conectar")
            if not host:
                self.host_var.set("127.0.0.1")

    def _set_running_ui(self, running):
        for w in self._cfg_widgets:
            if isinstance(w, ttk.Combobox):
                w.configure(state="disabled" if running else "readonly")
            else:
                w.configure(state="disabled" if running else "normal")
        self.start_btn.configure(state="disabled" if running else "normal")
        self.stop_btn.configure(state="normal" if running else "disabled")
        self.send_btn.configure(state="normal" if running else "disabled")
        self.msg_entry.configure(state="normal" if running else "disabled")
        if running:
            self.msg_entry.focus_set()

    # -- consola -----------------------------------------------------------
    def _append(self, text, tag=None):
        t = self.text
        t.configure(state="normal")
        t.insert("end", text, (tag,) if tag else ())
        t.configure(state="disabled")
        if self.autoscroll_var.get():
            t.see("end")

    def _stamp(self):
        if self.timestamp_var.get():
            return "[%s] " % datetime.datetime.now().strftime("%H:%M:%S")
        return ""

    def log_line(self, text, tag="sys"):
        if not self._at_line_start:
            self._append("\n")
        self._append(self._stamp() + text + "\n", tag)
        self._at_line_start = True

    def log_rx(self, text):
        text = text.replace("\r\n", "\n").replace("\r", "\n").replace("\x00", "")
        if not text:
            return
        if self._at_line_start:
            text = self._stamp() + text
        self._append(text, "rx")
        self._at_line_start = text.endswith("\n")

    # -- acciones ----------------------------------------------------------
    def _error(self, message):
        self.log_line(message, "err")
        messagebox.showerror(APP_NAME, message, parent=self.root)

    def on_start(self):
        if self.backend.running:
            return
        mode = self.mode_var.get()
        host = self.host_var.get().strip()
        port_s = self.port_var.get().strip()

        if not self.nc_path:
            self._error("No se encontró netcat (nc) en el sistema.")
            return
        if mode == "client" and not host:
            self._error("Introduce la IP o el host remoto.")
            return
        if host and not valid_host(host):
            self._error("La dirección IP / host «%s» no es válida." % host)
            return
        if not port_s.isdigit() or not (1 <= int(port_s) <= 65535):
            self._error("El puerto debe ser un número entre 1 y 65535.")
            return

        proto = self.proto_var.get()
        port = int(port_s)
        self._set_running_ui(True)
        if mode == "server":
            self.set_status("wait", "Iniciando servidor…")
            self.log_line("Iniciando servidor %s en el puerto %d…" %
                          (proto, port), "sys")
        else:
            self.set_status("wait", "Conectando…")
            self.log_line("Conectando a %s:%d (%s)…" % (host, port, proto),
                          "sys")
        self.backend.start(self.nc_path, self.nc_style, mode, proto, host,
                           port)

    def on_stop(self):
        if self.backend.running:
            self.stop_btn.configure(state="disabled")
            self.set_status("wait", "Deteniendo…")
            self.backend.stop()

    def on_send(self):
        if not self.backend.running:
            return
        msg = self.msg_var.get()
        eol = EOLS.get(self.eol_var.get(), "\n")
        if msg == "" and eol == "":
            return
        self.backend.send((msg + eol).encode("utf-8"))
        self.log_line("> " + msg, "tx")
        if msg:
            self._history.append(msg)
        self._hist_idx = len(self._history)
        self.msg_var.set("")

    def _hist_prev(self, _event):
        if self._history and self._hist_idx > 0:
            self._hist_idx -= 1
            self.msg_var.set(self._history[self._hist_idx])
            self.msg_entry.icursor("end")
        return "break"

    def _hist_next(self, _event):
        if self._hist_idx < len(self._history) - 1:
            self._hist_idx += 1
            self.msg_var.set(self._history[self._hist_idx])
        else:
            self._hist_idx = len(self._history)
            self.msg_var.set("")
        self.msg_entry.icursor("end")
        return "break"

    def on_clear(self):
        self.text.configure(state="normal")
        self.text.delete("1.0", "end")
        self.text.configure(state="disabled")
        self._at_line_start = True

    def on_save(self):
        default = "netcat_log_%s.txt" % datetime.datetime.now().strftime(
            "%Y%m%d_%H%M%S")
        path = filedialog.asksaveasfilename(
            parent=self.root, title="Guardar log", initialfile=default,
            defaultextension=".txt",
            filetypes=[("Texto", "*.txt"), ("Todos los archivos", "*.*")])
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(self.text.get("1.0", "end-1c") + "\n")
            self.log_line("Log guardado en %s" % path, "sys")
        except OSError as exc:
            self._error("No se pudo guardar el log: %s" % exc)

    # -- eventos del back-end ---------------------------------------------
    def _poll(self):
        try:
            while True:
                self._handle(self.events.get_nowait())
        except queue.Empty:
            pass
        self.root.after(40, self._poll)

    def _handle(self, ev):
        kind = ev[0]
        server = self.mode_var.get() == "server"
        if kind == "rx":
            self.log_rx(ev[1])
        elif kind == "nc":
            self.log_line("[nc] " + ev[1], "nc")
        elif kind == "sys":
            self.log_line(ev[1], "sys")
        elif kind == "sys_err":
            self.log_line(ev[1], "err")
        elif kind == "peer":
            self.set_status("on", "Cliente conectado" if server
                            else "Conectado")
        elif kind == "alive":
            if self.status_state == "wait":
                self.set_status("on", "Escuchando…" if server
                                else "Conectado")
        elif kind == "variant":
            self.nc_style, self.nc_variant = ev[1], ev[2]
            self._update_nc_info()
        elif kind == "fatal":
            self._set_running_ui(False)
            self.set_status("off", "Desconectado")
            self._error(ev[1])
        elif kind == "exit":
            rc, user_stopped, errtext = ev[1], ev[2], ev[3]
            self._set_running_ui(False)
            self.set_status("off", "Desconectado")
            if user_stopped:
                self.log_line("Desconectado.", "sys")
            elif rc == 0:
                self.log_line("El otro extremo cerró la conexión (nc "
                              "terminó). Pulsa de nuevo para reiniciar.",
                              "sys")
            else:
                msg = friendly_error(errtext) or \
                    "netcat terminó con código %s." % rc
                self._error(msg)

    def _on_close(self):
        if self.backend.running:
            self.backend.stop()
            time.sleep(0.15)
        self.root.destroy()


def main():
    try:
        root = tk.Tk()
    except tk.TclError as exc:
        sys.stderr.write("No se pudo abrir la interfaz gráfica: %s\n" % exc)
        sys.exit(1)
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
