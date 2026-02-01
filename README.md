# Proxion FUSE: The Unified Mount 📂

Proxion FUSE is the high-performance bridging layer that makes decentralized storage (Solid Pods) accessible to legacy and modern containerized applications. It mounts remote directories as local drives, enabling a "local-first" experience for 90+ applications.

## 🏗️ Architecture: The Bridge Principle
Standard decentralized storage (Solid) operates over HTTP. This is incompatible with legacy software (Photoshop, Docker CLI, etc.) which expects a standard filesystem. Proxion FUSE bridges this gap:

1.  **Virtualization**: It creates a virtual disk (Drive P:) in the host OS.
2.  **Proxy Routing**: Instead of talking to the internet, it talks to the **Proxion Keyring Proxy** (localhost:8089).
3.  **Automatic Auth**: The Keyring automatically attaches the required **Capability Tokens** and DPoP signatures to every filesystem request.

## 🚀 Usage

### ⚙️ Prerequisites
- `pip install -r requirements.txt`
- `proxion-keyring` (Resource Server) must be active and authorized.

### 🔌 Basic Mount
To mount your entire Pod root to a local folder:
```bash
python mount.py <mount_point_path> /
```

### 🌉 The Unified P: Drive (Windows)
Proxion CLI uses this FUSE driver to orchestrate the **Unified Mount**:
```bash
python mount.py P: /stash/
```

## 🛠️ Internal Mechanics
- **RDF Parsing**: Translates Solid Turtle (`.ttl`) metadata into standard directory listings (readdir).
- **Range-Based Streaming**: Native support for large file streaming via HTTP Range headers (crucial for Media apps like Jellyfin).
- **Advisory Locking**: Transparently handles `.proxion.lock` files to prevent concurrent write collisions across the suite.
- **DPoP Integration**: Every I/O operation is cryptographically proven back to the Master Identity Key.

## 🛡️ Security
Proxion FUSE operates in a "Zero-Trust" mode. If the local **Resource Server** is not authorized or the session has expired, the filesystem will gracefully enter an I/O Error state, protecting your data from unauthorized local access.
