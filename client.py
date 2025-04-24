import socket
import tkinter as tk
from tkinter import messagebox, scrolledtext
import hashlib
from base64 import urlsafe_b64encode
from cryptography.fernet import Fernet
import threading
import secrets


class ClientGUI:
    def __init__(self, master):
        self.master = master
        master.title("Secure Chat Client")
        self.connected = False
        self.cipher = None
        self.client_socket = None

        master.protocol("WM_DELETE_WINDOW", self.on_closing)

        self.conn_frame = tk.Frame(master)
        self.conn_frame.pack(padx=10, pady=5, fill=tk.X)

        tk.Label(self.conn_frame, text="Server IP:").grid(row=0, column=0)
        self.ip_entry = tk.Entry(self.conn_frame)
        self.ip_entry.grid(row=0, column=1, padx=5)
        self.ip_entry.insert(0, "127.0.0.1")

        tk.Label(self.conn_frame, text="Port:").grid(row=0, column=2)
        self.port_entry = tk.Entry(self.conn_frame, width=5)
        self.port_entry.grid(row=0, column=3, padx=5)
        self.port_entry.insert(0, "5010")

        self.connect_btn = tk.Button(self.conn_frame, text="Connect", command=self.toggle_connection)
        self.connect_btn.grid(row=0, column=4, padx=5)

        self.chat_area = scrolledtext.ScrolledText(master, state='disabled')
        self.chat_area.pack(padx=10, pady=5, expand=True, fill=tk.BOTH)

        self.msg_frame = tk.Frame(master)
        self.msg_frame.pack(padx=10, pady=5, fill=tk.X)

        self.msg_entry = tk.Entry(self.msg_frame)
        self.msg_entry.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=5)
        self.msg_entry.bind("<Return>", lambda e: self.send_message())

        self.send_btn = tk.Button(self.msg_frame, text="Send", command=self.send_message)
        self.send_btn.pack(side=tk.RIGHT)

        self.status_label = tk.Label(master, text="Status: Disconnected", fg="red")
        self.status_label.pack(pady=5)

    def toggle_connection(self):
        if self.connected:
            self.disconnect()
        else:
            self.connect_server()

    def connect_server(self):
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((self.ip_entry.get(), int(self.port_entry.get())))

            data = self.client_socket.recv(4096).decode()
            if ',' not in data:
                raise ValueError("Invalid DH parameters received")
            p, g = map(int, data.split(','))

            private_key = secrets.randbelow(p - 1) + 1
            public_key = pow(g, private_key, p)
            self.client_socket.send(str(public_key).encode())

            server_public = int(self.client_socket.recv(4096).decode())

            if server_public <= 1 or server_public >= p - 1:
                raise ValueError("Invalid server public key")

            shared_secret = pow(server_public, private_key, p)
            key = hashlib.sha256(str(shared_secret).encode()).digest()
            fernet_key = urlsafe_b64encode(key)
            self.cipher = Fernet(fernet_key)

            self.connected = True
            self.connect_btn.config(text="Disconnect")
            self.status_label.config(text="Status: Connected", fg="green")
            self.append_message("System", "Securely connected to server!")

            threading.Thread(target=self.receive_messages, daemon=True).start()

        except Exception as e:
            messagebox.showerror("Error", f"Connection failed: {e}")
            if self.client_socket:
                self.client_socket.close()
            self.client_socket = None

    def disconnect(self):
        self.connected = False
        try:
            if self.client_socket:
                self.client_socket.close()
        except:
            pass
        finally:
            self.client_socket = None
            self.connect_btn.config(text="Connect")
            self.status_label.config(text="Status: Disconnected", fg="red")
            self.append_message("System", "Disconnected from server")

    def receive_messages(self):
        while self.connected:
            try:
                encrypted_msg = self.client_socket.recv(4096)
                if not encrypted_msg:
                    break

                decrypted_msg = self.cipher.decrypt(encrypted_msg).decode()
                self.append_message("Server", decrypted_msg)
            except Exception as e:
                if self.connected:  # Если мы не сами отключились
                    self.append_message("System", f"Connection error: {e}")
                    self.disconnect()
                break

    def send_message(self):
        if not self.connected or not self.cipher:
            messagebox.showerror("Error", "Not connected to server!")
            return

        msg = self.msg_entry.get()
        if msg:
            try:
                encrypted_msg = self.cipher.encrypt(msg.encode())
                self.client_socket.send(encrypted_msg)
                self.append_message("You", msg)
                self.msg_entry.delete(0, tk.END)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to send message: {e}")
                self.disconnect()

    def append_message(self, sender, message):
        self.chat_area.config(state='normal')
        self.chat_area.insert(tk.END, f"{sender}: {message}\n")
        self.chat_area.config(state='disabled')
        self.chat_area.see(tk.END)

    def on_closing(self):
        self.disconnect()
        self.master.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    app = ClientGUI(root)
    root.mainloop()