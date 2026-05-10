# Secure Chat Application

A secure multi-client chat application written in C++ using TCP sockets, multithreading, JSON messaging, and RSA encryption with OpenSSL.

---

## Features

- Secure messaging using 2048-bit RSA encryption
- RSA-OAEP padding for improved security
- Real-time communication over TCP
- Multi-client support using multithreading
- End-to-end encrypted messaging model
- JSON-based communication protocol
- Public key exchange between clients
- Private and broadcast messaging
- Command-line chat interface

---

## Project Files

| File                 | Description                      |
| -------------------- | -------------------------------- |
| `server.cpp`         | Server implementation            |
| `client.cpp`         | Client implementation            |
| `securechat.hpp`     | Shared message/frame definitions |
| `rsa_encryption.hpp` | RSA encryption/decryption module |

---

## Prerequisites

### Linux (Ubuntu/Debian)

```bash
sudo apt-get update
sudo apt-get install -y \
    build-essential \
    cmake \
    libssl-dev \
    nlohmann-json3-dev
```

### macOS (with Homebrew)

```bash
brew install cmake openssl nlohmann-json
```

### Linux (Fedora/CentOS/RHEL)

```bash
sudo dnf install -y \
    gcc-c++ \
    cmake \
    openssl-devel \
    nlohmann_json-devel
```

---

# Compilation

```bash
mkdir build
cd build
cmake ..
make
```

This will create two executables:

- `server` - The chat server
- `client` - The CLI client

# Running the Application

## Step 1: Start the Server

Run:

```bash
./server
```

Example output:

```text
Server listening on 0.0.0.0:12345
Server initialized successfully
```

---

## Step 2: Start Clients

Open separate terminals for each client. Use localhost or the IP of the HOST if using on different devices in a LAN

### Terminal 1

```bash
./client Person1 localhost 12345
```

or

```bash
./client Person1
```

```bash
./client Person1 'server_IP' 12345
```

### Terminal 2

```bash
./client Dark localhost 12345
```

### Terminal 3

```bash
./client Rasgulla localhost 12345
```

Example client output:

```text
Generating RSA keys...
RSA keys generated (2048-bit)
Connecting to server...
Connected to chat server as alice
```

---

# Client Commands

| Command             | Description               |
| ------------------- | ------------------------- |
| `/users`            | Show connected users      |
| `/msg user message` | Send private message      |
| `/all message`      | Send message to all users |
| `/quit`             | Disconnect from chat      |

---

# How It Works

1. Client generates RSA public/private keys.
2. Public key is sent to the server.
3. Server distributes public keys to all clients.
4. Messages are encrypted using recipient public keys.
5. Server forwards encrypted messages.
6. Recipient decrypts using private key.

---

# Communication Protocol

Messages are sent with a 4-byte big-endian length prefix followed by JSON data:

```
[4 bytes: length] [JSON data]
```

### Message Types

**System Message:**

```json
{
  "type": "system",
  "message": "** alice has joined the chat **"
}
```

**Client List:**

```json
{
  "type": "client_list",
  "clients": {
    "alice": "-----BEGIN PUBLIC KEY-----\n...",
    "bob": "-----BEGIN PUBLIC KEY-----\n..."
  }
}
```

**Chat Message:**

```json
{
  "type": "chat",
  "sender": "alice",
  "message": ["a1b2c3d4...", "e5f6g7h8..."] // Hex-encoded encrypted chunks
}
```

---

# Security Features

- 2048-bit RSA encryption
- RSA-OAEP padding
- End-to-end encrypted messaging
- Encrypted message chunking
- Secure public key exchange

---

# Multithreading

## Server

- Each client handled in a separate thread.

## Client

- Background thread continuously receives messages.

This prevents blocking during send/receive operations.

---

# Advantages

- Secure communication using RSA encryption
- RSA-OAEP padding improves cryptographic security
- Supports end-to-end encrypted messaging
- Real-time communication using TCP sockets
- Multithreading enables concurrent client handling
- Mutex synchronization prevents race conditions
- JSON-based extensible communication protocol
- Length-prefixed framing ensures reliable parsing
- Modular and maintainable code structure
- Automatic public key exchange between clients

---

# Possible Improvements

- AES + RSA hybrid encryption
- GUI interface
- User authentication
- Secure file transfer
- Persistent message storage
- TLS transport encryption

---

## Troubleshooting

### "OpenSSL not found" error

```bash
# Ubuntu/Debian
sudo apt-get install libssl-dev

# macOS
brew install openssl

# CentOS/RHEL
sudo dnf install openssl-devel
```

### "nlohmann/json not found" error

```bash
# Ubuntu (newer versions)
sudo apt-get install nlohmann-json3-dev

# Or manually:
wget https://github.com/nlohmann/json/releases/download/v3.11.2/json.hpp
cp json.hpp /usr/local/include/nlohmann/
```

### Connection refused

- Ensure server is running: `./server`
- Check firewall: `sudo ufw allow 12345`
- Try localhost: `./client username localhost 12345`

---

# Notes

- The server forwards encrypted messages but does not decrypt them.
- Clients must remain connected to exchange messages.
- Default server port is `12345`.

---
