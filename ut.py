import unittest
import sqlite3
import tempfile
import os
import socket
import threading
import time
from unittest.mock import patch, Mock
import hashlib
from base64 import urlsafe_b64encode
from cryptography.fernet import Fernet

# Общие параметры
DH_P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
DH_G = 2


class TestDiffieHellman(unittest.TestCase):
    def test_key_exchange(self):
        private_a = 123456
        private_b = 654321

        public_a = pow(DH_G, private_a, DH_P)
        public_b = pow(DH_G, private_b, DH_P)

        shared_a = pow(public_b, private_a, DH_P)
        shared_b = pow(public_a, private_b, DH_P)

        self.assertEqual(shared_a, shared_b, "Общие секреты должны совпадать")

    def test_fernet_key_generation(self):
        shared_secret = 123456789
        key = hashlib.sha256(str(shared_secret).encode()).digest()
        fernet_key = urlsafe_b64encode(key)

        self.assertEqual(len(fernet_key), 44, "Ключ должен быть длиной 44 байта")
        self.assertTrue(isinstance(Fernet(fernet_key), Fernet), "Должен создаваться валидный объект Fernet")


class TestDatabase(unittest.TestCase):
    def setUp(self):
        self.db_fd, self.db_path = tempfile.mkstemp()
        self.conn = sqlite3.connect(self.db_path)
        self.conn.execute('''CREATE TABLE clients
                          (id INTEGER PRIMARY KEY,
                           ip TEXT, port INTEGER,
                           public_key TEXT)''')

    def test_client_insertion(self):
        test_data = ('127.0.0.1', 12345, 'test_public_key')
        self.conn.execute("INSERT INTO clients (ip, port, public_key) VALUES (?, ?, ?)", test_data)
        self.conn.commit()

        result = self.conn.execute("SELECT ip, port, public_key FROM clients").fetchone()
        self.assertEqual(result, test_data, "Данные должны совпадать")

    def tearDown(self):
        self.conn.close()
        os.close(self.db_fd)
        os.unlink(self.db_path)


class TestNetwork(unittest.TestCase):
    @patch('socket.socket')
    def test_server_socket_creation(self, mock_socket):
        mock_server = Mock()
        mock_socket.return_value = mock_server

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(('0.0.0.0', 12345))
        s.listen(5)

        mock_socket.assert_called_once_with(socket.AF_INET, socket.SOCK_STREAM)
        mock_server.bind.assert_called_once_with(('0.0.0.0', 12345))
        mock_server.listen.assert_called_once_with(5)

    def test_encryption(self):
        key = Fernet.generate_key()
        cipher = Fernet(key)
        test_msg = "Test message"

        encrypted = cipher.encrypt(test_msg.encode())
        decrypted = cipher.decrypt(encrypted).decode()

        self.assertEqual(test_msg, decrypted, "Сообщение должно корректно дешифроваться")


if __name__ == '__main__':
    unittest.main(verbosity=2)