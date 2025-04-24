import socket
import threading
import sqlite3
import tkinter as tk
from tkinter import scrolledtext, messagebox
import hashlib
from base64 import urlsafe_b64encode
from cryptography.fernet import Fernet
import secrets

p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
g = 2


class ServerGUI:
    def __init__(self, master):
        self.master = master
        master.title("Secure Chat Server")
        self.running = False
        self.server_socket = None
        self.clients = []

        self.log_area = scrolledtext.ScrolledText(master, width=70, height=20)
        self.log_area.pack(padx=10, pady=10)

        self.btn_frame = tk.Frame(master)
        self.btn_frame.pack(pady=5)

        self.start_btn = tk.Button(self.btn_frame, text="Start Server", command=self.start_server)
        self.start_btn.pack(side=tk.LEFT, padx=5)

        self.stop_btn = tk.Button(self.btn_frame, text="Stop Server", command=self.stop_server, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)

        self.init_db()

    def init_db(self):
        conn = sqlite3.connect('clients.db', check_same_thread=False)
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS clients
                          (id INTEGER PRIMARY KEY AUTOINCREMENT,
                           ip TEXT,
                           port INTEGER,
                           public_key TEXT,
                           connected_at DATETIME DEFAULT CURRENT_TIMESTAMP)''')
        conn.commit()
        conn.close()

    def get_db_connection(self):
        conn = sqlite3.connect('clients.db', check_same_thread=False)
        return conn

    def log(self, message):
        self.log_area.insert(tk.END, message + "\n")
        self.log_area.see(tk.END)

    def start_server(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind(('0.0.0.0', 5010))
        self.server_socket.listen(5)
        self.running = True
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.log("[+] Server started on port 5010")

        accept_thread = threading.Thread(target=self.accept_clients)
        accept_thread.start()

    def stop_server(self):
        self.running = False
        if self.server_socket:
            self.server_socket.close()
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.log("[+] Server stopped")

    def accept_clients(self):
        while self.running:
            try:
                client_socket, addr = self.server_socket.accept()
                self.log(f"[+] New connection from {addr[0]}:{addr[1]}")
                client_handler = threading.Thread(target=self.handle_client, args=(client_socket, addr))
                client_handler.start()
            except Exception as e:
                if self.running:
                    self.log(f"[-] Error accepting connection: {e}")

    def handle_client(self, client_socket, addr):
        try:
            client_socket.send(f"{p},{g}".encode())

            client_public = int(client_socket.recv(4096).decode())

            if client_public <= 1 or client_public >= p - 1:
                raise ValueError("Invalid client public key")

            server_private = secrets.randbelow(p - 1) + 1
            server_public = pow(g, server_private, p)
            client_socket.send(str(server_public).encode())

            shared_secret = pow(client_public, server_private, p)
            key = hashlib.sha256(str(shared_secret).encode()).digest()
            fernet_key = urlsafe_b64encode(key)
            cipher = Fernet(fernet_key)

            conn = self.get_db_connection()
            cursor = conn.cursor()
            cursor.execute("INSERT INTO clients (ip, port, public_key) VALUES (?, ?, ?)",
                           (addr[0], addr[1], str(client_public)))
            conn.commit()
            conn.close()

            self.log(f"[+] Secure connection established with {addr[0]}:{addr[1]}")

            while self.running:
                encrypted_msg = client_socket.recv(4096)
                if not encrypted_msg:
                    break
                try:
                    decrypted_msg = cipher.decrypt(encrypted_msg)
                    self.log(f"[{addr[0]}:{addr[1]}] {decrypted_msg.decode()}")
                except Exception as e:
                    self.log(f"[-] Decryption error: {e}")
                    break

        except Exception as e:
            self.log(f"[-] Client error: {e}")
        finally:
            client_socket.close()
            self.log(f"[-] Connection with {addr[0]}:{addr[1]} closed")


if __name__ == "__main__":
    root = tk.Tk()
    app = ServerGUI(root)
    root.mainloop()