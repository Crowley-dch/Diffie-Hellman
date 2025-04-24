# Diffie-Hellman
A secure client-server chat application featuring end-to-end encryption using Diffie-Hellman key exchange and Fernet symmetric encryption.

## Features

- **Secure Key Exchange**: 2048-bit Diffie-Hellman key negotiation
- **End-to-End Encryption**: Messages encrypted with AES-128 in Fernet tokens
- **Database Logging**: Server stores client connection records in SQLite
- **GUI Interface**: Both server and client have user-friendly Tkinter interfaces
- **Threaded Architecture**: Supports multiple concurrent client connections

## Security Implementation

1. **Key Exchange**:
   - Uses RFC 3526 2048-bit MODP group
   - Server validates client public keys (1 < key < p-1)
   - Cryptographically secure random numbers with `secrets` module

2. **Encryption**:
   - Shared secret converted to 256-bit key via SHA-256
   - Fernet provides authenticated encryption (AES-128-CBC + HMAC-SHA256)

3. **Network Security**:
   - All communication encrypted after initial handshake
   - Protection against basic MITM attacks through DH

## Running the Application
1. **Start the server:**
   ```bash
   python server.py
   ```

2. **Start the client (in another terminal):**
   ```bash
   python client.py
   ```

## Usage
1. Server Interface

  - Start/Stop server with buttons
  - View connection logs and chat messages
  - Client records stored in clients.db

2. Client Interface

  - Connect to server with IP/port
  - Send encrypted messages
  - View conversation history

## 🧪 Running Tests
Run unit tests using:
```bash
python ut.py
```

