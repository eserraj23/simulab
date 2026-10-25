from datetime import datetime
import socket
import threading
import tkinter as tk
from tkinter import filedialog, messagebox
import customtkinter as ctk

# Configuración inicial de apariencia de CustomTkinter
ctk.set_appearance_mode("System")  # Opciones: "System", "Dark", "Light"
ctk.set_default_color_theme("blue")


class NetcatGUI(ctk.CTk):

  def __init__(self):
    super().__init__()

    self.title("Netcat GUI Wrapper - Python Edition")
    self.geometry("950x700")
    self.minsize(800, 600)

    # Variables de Control de Red
    self.running = False
    self.socket_obj = None
    self.conn_obj = None  # Conexión activa TCP (servidor)
    self.target_addr = None  # Dirección destino UDP
    self.network_thread = None

    self.create_widgets()

  def create_widgets(self):
    # --- CONTENEDOR PRINCIPAL ---
    self.grid_columnconfigure(0, weight=1)
    self.grid_rowconfigure(2, weight=1)

    # ==================== 1. PANEL DE CONFIGURACIÓN ====================
    config_frame = ctk.CTkFrame(self, corner_radius=10)
    config_frame.grid(row=0, column=0, padx=15, pady=15, sticky="ew")
    config_frame.grid_columnconfigure(5, weight=1)

    # Modo (Servidor / Cliente)
    lbl_mode = ctk.CTkLabel(
        config_frame, text="Modo:", font=ctk.CTkFont(weight="bold")
    )
    lbl_mode.grid(row=0, column=0, padx=10, pady=10, sticky="w")
    self.mode_menu = ctk.CTkComboBox(
        config_frame, values=["Servidor (Listener)", "Cliente (Conexión)"]
    )
    self.mode_menu.grid(row=0, column=1, padx=5, pady=10, sticky="ew")

    # Protocolo (TCP / UDP)
    lbl_proto = ctk.CTkLabel(
        config_frame, text="Protocolo:", font=ctk.CTkFont(weight="bold")
    )
    lbl_proto.grid(row=0, column=2, padx=10, pady=10, sticky="w")
    self.proto_menu = ctk.CTkComboBox(config_frame, values=["TCP", "UDP"])
    self.proto_menu.grid(row=0, column=3, padx=5, pady=10, sticky="ew")

    # Dirección IP
    lbl_ip = ctk.CTkLabel(
        config_frame, text="IP / Host:", font=ctk.CTkFont(weight="bold")
    )
    lbl_ip.grid(row=1, column=0, padx=10, pady=10, sticky="w")
    self.entry_ip = ctk.CTkEntry(
        config_frame, placeholder_text="ej. 127.0.0.1 o 0.0.0.0"
    )
    self.entry_ip.insert(0, "127.0.0.1")
    self.entry_ip.grid(
        row=1, column=1, columnspan=2, padx=5, pady=10, sticky="ew"
    )

    # Puerto
    lbl_port = ctk.CTkLabel(
        config_frame, text="Puerto:", font=ctk.CTkFont(weight="bold")
    )
    lbl_port.grid(row=1, column=3, padx=10, pady=10, sticky="e")
    self.entry_port = ctk.CTkEntry(
        config_frame, placeholder_text="ej. 4444", width=100
    )
    self.entry_port.grid(row=1, column=4, padx=5, pady=10, sticky="w")

    # ==================== 2. PANEL DE ESTADO Y CONTROLES ====================
    control_frame = ctk.CTkFrame(self, fg_color="transparent")
    control_frame.grid(row=1, column=0, padx=15, pady=(0, 10), sticky="ew")
    control_frame.grid_columnconfigure(3, weight=1)

    # Botones de Acción principal
    self.btn_start = ctk.CTkButton(
        control_frame,
        text="Iniciar / Conectar",
        fg_color="#28a745",
        hover_color="#218838",
        command=self.start_network,
    )
    self.btn_start.grid(row=0, column=0, padx=5, pady=5)

    self.btn_stop = ctk.CTkButton(
        control_frame,
        text="Desconectar / Detener",
        fg_color="#dc3545",
        hover_color="#c82333",
        state="disabled",
        command=self.stop_network,
    )
    self.btn_stop.grid(row=0, column=1, padx=5, pady=5)

    # Indicador Visual de Estado (Canvas para círculo de color)
    self.status_canvas = ctk.CTkCanvas(
        control_frame, width=20, height=20, bg="#242424", highlightthickness=0
    )
    self.status_canvas.grid(row=0, column=2, padx=(15, 5), pady=5)
    self.status_circle = self.status_canvas.create_oval(
        2, 2, 18, 18, fill="red", outline=""
    )

    self.lbl_status_text = ctk.CTkLabel(
        control_frame,
        text="Desconectado",
        font=ctk.CTkFont(weight="bold"),
        text_color="gray",
    )
    self.lbl_status_text.grid(row=0, column=3, padx=5, pady=5, sticky="w")

    # Botones auxiliares
    btn_clear = ctk.CTkButton(
        control_frame, text="Limpiar Pantalla", width=120, command=self.clear_log
    )
    btn_clear.grid(row=0, column=4, padx=5, pady=5)

    btn_save = ctk.CTkButton(
        control_frame, text="Guardar Log", width=110, command=self.save_log
    )
    btn_save.grid(row=0, column=5, padx=5, pady=5)

    # ==================== 3. ÁREA DE COMUNICACIÓN (TERMINAL) ====================
    terminal_frame = ctk.CTkFrame(self)
    terminal_frame.grid(
        row=2, column=0, padx=15, pady=(0, 15), sticky="nsew"
    )
    terminal_frame.grid_columnconfigure(0, weight=1)
    terminal_frame.grid_rowconfigure(0, weight=1)

    self.text_log = ctk.CTkTextbox(
        terminal_frame,
        font=ctk.CTkFont(family="Consolas", size=13),
        text_color="#00FF66",
        fg_color="#121212",
    )
    self.text_log.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
    self.text_log.configure(state="disabled")

    # ==================== 4. ENTRADA DE MENSAJES ====================
    input_frame = ctk.CTkFrame(self, fg_color="transparent")
    input_frame.grid(row=3, column=0, padx=15, pady=(0, 15), sticky="ew")
    input_frame.grid_columnconfigure(0, weight=1)

    self.entry_msg = ctk.CTkEntry(
        input_frame,
        placeholder_text="Escribe un comando o mensaje y presiona Enter...",
        height=40,
    )
    self.entry_msg.grid(row=0, column=0, padx=(0, 10), pady=0, sticky="ew")
    self.entry_msg.bind("<Return>", lambda event: self.send_data())

    self.btn_send = ctk.CTkButton(
        input_frame,
        text="Enviar",
        width=100,
        height=40,
        state="disabled",
        command=self.send_data,
    )
    self.btn_send.grid(row=0, column=1, padx=0, pady=0)

  # --- MÉTODOS DE RED Y HILOS (THREADING) ---

  def log_message(self, message):
    """Inserta texto en la consola de manera segura para hilos."""
    timestamp = datetime.now().strftime("[%H:%M:%S]")
    formatted_msg = f"{timestamp} {message}\n"

    def _update():
      self.text_log.configure(state="normal")
      self.text_log.insert("end", formatted_msg)
      self.text_log.see("end")
      self.text_log.configure(state="disabled")

    self.after(0, _update)

  def set_status(self, active, text):
    """Actualiza el indicador visual y texto de estado."""

    def _update():
      color = "#28a745" if active else "red"
      self.status_canvas.itemconfig(self.status_circle, fill=color)
      self.lbl_status_text.configure(
          text=text, text_color="#28a745" if active else "gray"
      )

    self.after(0, _update)

  def start_network(self):
    ip = self.entry_ip.get().strip()
    port_str = self.entry_port.get().strip()

    # Validación básica de puerto
    if not port_str.isdigit():
      messagebox.showerror(
          "Error de Validación",
          "El puerto debe ser un número entero válido (1-65535).",
      )
      return
    port = int(port_str)

    if not (1 <= port <= 65535):
      messagebox.showerror(
          "Error de Validación", "El puerto debe estar en el rango de 1 a 65535."
      )
      return

    mode = self.mode_menu.get()
    proto = self.proto_menu.get()

    self.running = True
    self.btn_start.configure(state="disabled")
    self.mode_menu.configure(state="disabled")
    self.proto_menu.configure(state="disabled")
    self.entry_ip.configure(state="disabled")
    self.entry_port.configure(state="disabled")

    self.btn_stop.configure(state="normal")
    self.btn_send.configure(state="normal")

    # Lanzar hilo secundario de red para evitar congelar la interfaz
    self.network_thread = threading.Thread(
        target=self.network_worker, args=(mode, proto, ip, port), daemon=True
    )
    self.network_thread.start()

  def network_worker(self, mode, proto, ip, port):
    try:
      if "Servidor" in mode:
        if proto == "TCP":
          self.run_tcp_server(ip, port)
        else:
          self.run_udp_server(ip, port)
      else:  # Cliente
        if proto == "TCP":
          self.run_tcp_client(ip, port)
        else:
          self.run_udp_client(ip, port)
    except Exception as e:
      self.log_message(f"[!] Excepción crítica: {e}")
      self.stop_network()

  def run_tcp_server(self, host, port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
      server.bind((host if host else "0.0.0.0", port))
      server.listen(1)
      self.socket_obj = server
      self.log_message(
          f"[*] Servidor TCP escuchando en {host or '0.0.0.0'}:{port}"
      )
      self.set_status(True, f"Escuchando en puerto {port}")

      self.conn_obj, addr = server.accept()
      self.log_message(f"[+] Conexión entrante aceptada desde {addr[0]}:{addr[1]}")
      self.set_status(True, f"Conectado con {addr[0]}")

      while self.running:
        data = self.conn_obj.recv(4096)
        if not data:
          break
        self.log_message(
            f"Recibido: {data.decode('utf-8', errors='ignore').strip()}"
        )
    except Exception as e:
      if self.running:
        self.log_message(f"[!] Error en Servidor TCP: {e}")
    finally:
      self.stop_network()

  def run_tcp_client(self, host, port):
    try:
      client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      self.socket_obj = client
      self.log_message(f"[*] Conectando a {host}:{port} (TCP)...")
      client.connect((host, port))
      self.log_message(f"[+] Conectado exitosamente a {host}:{port}")
      self.set_status(True, f"Conectado a {host}:{port}")

      while self.running:
        data = client.recv(4096)
        if not data:
          break
        self.log_message(
            f"Recibido: {data.decode('utf-8', errors='ignore').strip()}"
        )
    except Exception as e:
      if self.running:
        self.log_message(f"[!] Error de conexión TCP: {e}")
    finally:
      self.stop_network()

  def run_udp_server(self, host, port):
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
      server.bind((host if host else "0.0.0.0", port))
      self.socket_obj = server
      self.log_message(
          f"[*] Servidor UDP escuchando en {host or '0.0.0.0'}:{port}"
      )
      self.set_status(True, f"UDP Escuchando en {port}")

      while self.running:
        data, addr = server.recvfrom(4096)
        self.target_addr = addr  # Actualizar dirección para responderle
        self.log_message(
            f"Recibido de {addr[0]}:{addr[1]} ->"
            f" {data.decode('utf-8', errors='ignore').strip()}"
        )
    except Exception as e:
      if self.running:
        self.log_message(f"[!] Error en Servidor UDP: {e}")
    finally:
      self.stop_network()

  def run_udp_client(self, host, port):
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    self.socket_obj = client
    self.target_addr = (host, port)
    self.log_message(
        f"[*] Cliente UDP configurado hacia {host}:{port}. Listo para enviar."
    )
    self.set_status(True, f"UDP Activo hacia {host}:{port}")

    # En UDP cliente también podemos escuchar respuestas
    try:
      while self.running:
        client.settimeout(1.0)
        try:
          data, addr = client.recvfrom(4096)
          self.log_message(
              f"Recibido de {addr[0]}:{addr[1]} ->"
              f" {data.decode('utf-8', errors='ignore').strip()}"
          )
        except socket.timeout:
          continue
    except Exception as e:
      if self.running:
        self.log_message(f"[!] Error en Cliente UDP: {e}")
    finally:
      self.stop_network()

  def send_data(self):
    msg = self.entry_msg.get()
    if not msg or not self.running:
      return

    full_msg = msg + "\n"

    try:
      proto = self.proto_menu.get()
      if proto == "TCP":
        if self.conn_obj:
          self.conn_obj.sendall(full_msg.encode("utf-8"))
        elif self.socket_obj:
          self.socket_obj.sendall(full_msg.encode("utf-8"))
      else:  # UDP
        if self.target_addr and self.socket_obj:
          self.socket_obj.sendto(
              full_msg.encode("utf-8"), self.target_addr
          )
        else:
          host = self.entry_ip.get()
          port = int(self.entry_port.get())
          self.socket_obj.sendto(full_msg.encode("utf-8"), (host, port))

      self.log_message(f"Enviado: {msg}")
      self.entry_msg.delete(0, tk.END)
    except Exception as e:
      self.log_message(f"[!] Error al enviar datos: {e}")

  def stop_network(self):
    if not self.running and not self.socket_obj:
      return

    self.running = False

    # Cerrar sockets de forma segura
    try:
      if self.conn_obj:
        self.conn_obj.close()
    except Exception:
      pass

    try:
      if self.socket_obj:
        self.socket_obj.close()
    except Exception:
      pass

    self.conn_obj = None
    self.socket_obj = None
    self.target_addr = None

    # Restaurar estado de la interfaz
    def _reset_ui():
      self.btn_start.configure(state="normal")
      self.btn_stop.configure(state="disabled")
      self.btn_send.configure(state="disabled")
      self.mode_menu.configure(state="normal")
      self.proto_menu.configure(state="normal")
      self.entry_ip.configure(state="normal")
      self.entry_port.configure(state="normal")
      self.set_status(False, "Desconectado")
      self.log_message("[*] Conexión cerrada.")

    self.after(0, _reset_ui)

  def clear_log(self):
    self.text_log.configure(state="normal")
    self.text_log.delete("0.0", "end")
    self.text_log.configure(state="disabled")

  def save_log(self):
    file_path = filedialog.asksaveasfilename(
        defaultextension=".txt",
        filetypes=[("Archivos de texto", "*.txt"), ("Todos los archivos", "*.*")],
    )
    if file_path:
      try:
        content = self.text_log.get("0.0", "end")
        with open(file_path, "w", encoding="utf-8") as f:
          f.write(content)
        messagebox.showinfo(
            "Éxito", f"Log guardado correctamente en:\n{file_path}"
        )
      except Exception as e:
        messagebox.showerror("Error", f"No se pudo guardar el archivo:\n{e}")


if __name__ == "__main__":
  app = NetcatGUI()
  app.mainloop()