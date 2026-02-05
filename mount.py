import os
import sys
import errno
import logging
import time
import threading
import requests
import json
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from fuse import FUSE, Operations, LoggingMixIn
from datetime import datetime

# Optional: Using a simple LRU cache instead of external cachetools to minimize dependencies
class SimpleLRU:
    def __init__(self, capacity=1000, ttl=5):
        self.capacity = capacity
        self.ttl = ttl
        self.cache = {}
        self.order = []

    def get(self, key):
        if key in self.cache:
            val, expiry = self.cache[key]
            if time.time() < expiry:
                self.order.remove(key)
                self.order.append(key)
                return val
            else:
                del self.cache[key]
                self.order.remove(key)
        return None

    def set(self, key, value):
        if len(self.cache) >= self.capacity:
            oldest = self.order.pop(0)
            del self.cache[oldest]
        self.cache[key] = (value, time.time() + self.ttl)
        self.order.append(key)

class PodClient:
    """PROTOCOL CLIENT: Handles all communication with the Pod Proxy."""
    def __init__(self, proxy_url="http://localhost:8089"):
        self.proxy_url = proxy_url.rstrip('/')
        self.session_key = ed25519.Ed25519PrivateKey.generate()
        self.token = None
        self._login()

    def _get_pub_key_hex(self):
        return self.session_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        ).hex()

    def _login(self):
        """Exchange session public key for a capability token."""
        url = f"{self.proxy_url}/auth/stash_login"
        try:
            resp = requests.post(url, json={"pubkey": self._get_pub_key_hex()}, timeout=5)
            if resp.status_code == 200:
                self.token = resp.json()
                logging.info("PodClient: Successfully acquired session capability token.")
            else:
                logging.error(f"PodClient: Authentication failed ({resp.status_code}): {resp.text}")
        except Exception as e:
            logging.error(f"PodClient: Could not reach Proxy for login: {e}")

    def _sign_request(self, method, path):
        """Generate a simplified DPoP proof."""
        # In a full spec, this would be a JWT. Here we just sign the method+path.
        payload = f"{method}:{path}"
        signature = self.session_key.sign(payload.encode())
        return json.dumps({
            "method": method,
            "path": path,
            "signature": signature.hex(),
            "pubkey": self._get_pub_key_hex()
        })

    def request(self, method, path, **kwargs):
        if not self.token:
            self._login()
            if not self.token: return None

        url = f"{self.proxy_url}/pod{path}"
        headers = kwargs.pop("headers", {}).copy()
        headers["Authorization"] = f"Bearer {json.dumps(self.token)}"
        headers["DPoP"] = self._sign_request(method, path)
        
        try:
            resp = requests.request(method, url, headers=headers, timeout=10, **kwargs)
            if resp.status_code >= 400:
                logging.error(f"Proxy Error {resp.status_code} for {method} {path}: {resp.text}")
                return None
            return resp
        except Exception as e:
            logging.error(f"Network Error for {method} {path}: {e}")
            return None

    def get_attr(self, path):
        resp = self.request("GET", path, headers={"Accept": "application/json"})
        if resp: return resp.json()
        return None

    def list_dir(self, path):
        """List directory entries using Solid LDP (Turtle)."""
        resp = self.request("GET", path, headers={"Accept": "text/turtle, application/json"})
        if not resp: return []
        
        if 'text/turtle' in resp.headers.get('Content-Type', ''):
            return self._parse_turtle_contains(resp.text)
        
        # Fallback to JSON
        try:
            return resp.json().get("entries", [])
        except:
            return []

    def _parse_turtle_contains(self, turtle_text):
        """Robust parser for full ldp:contains triples."""
        import re
        # Match <> ldp:contains <URI> .  or just ldp:contains <URI>
        uris = re.findall(r'ldp:contains\s+<([^>]+)>', turtle_text)
        
        entries = []
        for uri in uris:
            clean = uri.strip().rstrip('/')
            if clean: # Ignore self <>
                entries.append(clean)
        return entries

    def read(self, path, size, offset):
        headers = {"Range": f"bytes={offset}-{offset+size-1}"}
        resp = self.request("GET", path, headers=headers)
        if resp: return resp.content
        return b''

    def write(self, path, data, offset):
        # Simplified PUT. Real implementation might need range support.
        files = {"content": data}
        params = {"offset": offset}
        resp = self.request("PUT", path, files=files, params=params)
        return len(data) if resp else 0

class ProxionUnifiedFS(LoggingMixIn, Operations):
    """
    Unified High-Performance FUSE implementation for the Proxion Suite.
    Integrates physical disks as virtual directories within the Solid Pod (Drive P:).
    """
    def __init__(self, proxy_url="http://localhost:8089"):
        self.client = PodClient(proxy_url)
        logging.info(f"FUSE Initialized with Pod Proxy at {proxy_url}")

    def getattr(self, path, fh=None):
        attr = self.client.get_attr(path)
        if not attr:
            raise OSError(errno.ENOENT, f"No such file: {path}")
        return attr

    def readdir(self, path, fh):
        entries = {'.', '..'}
        entries.update(self.client.list_dir(path))
        return list(entries)

    def read(self, path, size, offset, fh):
        return self.client.read(path, size, offset)

    def write(self, path, data, offset, fh):
        written = self.client.write(path, data, offset)
        if written == 0:
            raise OSError(errno.EACCES, "Write failed")
        return written

    def create(self, path, mode, fi=None):
        # Map to POST /pod/path
        resp = self.client.request("POST", path)
        if not resp:
            raise OSError(errno.EACCES, "Create failed")
        return 0

    def mkdir(self, path, mode):
        # Map to POST /pod/path with dir marker or separate endpoint
        resp = self.client.request("POST", path, params={"type": "container"})
        if not resp:
            raise OSError(errno.EACCES, "Mkdir failed")
        return 0

    def unlink(self, path):
        resp = self.client.request("DELETE", path)
        return 0 if resp else -1

    def rmdir(self, path):
        resp = self.client.request("DELETE", path)
        return 0 if resp else -1

def main(mountpoint, proxy_url="http://localhost:8089", verbose=False):
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format='%(asctime)s [%(levelname)s] %(message)s'
    )
    logging.info(f"Mounting Virtual Pod to {mountpoint} via {proxy_url}...")
    try:
        FUSE(ProxionUnifiedFS(proxy_url), mountpoint, nothreads=False, foreground=True)
    except Exception as e:
        logging.critical(f"FUSE Mount failed: {e}")

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description="Proxion Virtual Pod FUSE Driver")
    parser.add_argument("mountpoint", help="Mount point (e.g. P:)")
    parser.add_argument("--proxy", default="http://localhost:8089", help="Pod Proxy URL")
    parser.add_argument("--verbose", action="store_true", help="Enable debug logging")
    
    args = parser.parse_args()
    print(f"--- FUSE Starting: {args.mountpoint} ---")
    print(f"--- Proxy: {args.proxy} ---")
    main(args.mountpoint, args.proxy, args.verbose)
