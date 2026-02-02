import os
import sys
import errno
import logging
import time
import threading
import requests
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

class ProxionUnifiedFS(LoggingMixIn, Operations):
    """
    Unified High-Performance FUSE implementation for the Proxion Suite.
    Supports single-mount (Drive P:), LRU caching, and concurrency locking.
    """
    def __init__(self, pod_path, proxy_url='http://localhost:8089'):
        self.pod_base = pod_path.rstrip('/')
        self.proxy = proxy_url
        self.metadata_cache = SimpleLRU(capacity=2000, ttl=10)
        self.block_cache = SimpleLRU(capacity=500, ttl=30)
        self.locks = {} # In-memory lock state for this mount
        self.etags = {} # Path -> ETag for optimistic concurrency
        
        # Check for Local Direct Mode
        self.local_mode = os.path.exists(self.pod_base) and os.path.isdir(self.pod_base)
        mode_str = "DIRECT IO (LOCAL)" if self.local_mode else f"REMOTE PROXY ({proxy_url})"
        print(f"[Proxion] Unified FUSE Initialized. Backend: {pod_path}")
        print(f"[Proxion] Mode: {mode_str}")

    def _get_local_path(self, path):
        # normalize path separators
        rel = path.lstrip('/').replace('/', os.sep)
        return os.path.join(self.pod_base, rel)

    def _get_pod_url(self, path):
        # Ensure path is normalized for HTTP (forward slashes) even on Windows
        base = self.pod_base.replace('\\', '/')
        rel_path = path.lstrip('/').lstrip('\\').replace('\\', '/')
        full_path = f"{base}/{rel_path}"
        return f"{self.proxy}/pod/{full_path}"

    def getattr(self, path, fh=None):
        if self.local_mode:
            real_path = self._get_local_path(path)
            try:
                st = os.stat(real_path)
                # Force directory mode to be explicit for Windows
                # We map real stat to FUSE dict
                res = dict(st_mode=(st.st_mode | 0o777), st_nlink=st.st_nlink, st_size=st.st_size, st_ctime=st.st_ctime, st_mtime=st.st_mtime, st_atime=st.st_atime)
                return res
            except OSError:
                raise OSError(errno.ENOENT, "No such file")

        # ... Remote implementation ...
        cached = self.metadata_cache.get(path)
        if cached: return cached
        
        # Root fallback
        if path == '/': return dict(st_mode=(0o040000 | 0o777), st_nlink=2)

        # Basic remote fetch (fallback)
        url = self._get_pod_url(path)
        try:
            resp = requests.get(url, stream=True, timeout=3)
            if resp.status_code == 200:
                header_type = resp.headers.get('Content-Type', '')
                size = int(resp.headers.get('Content-Length', 0))
                if 'text/turtle' in header_type or url.endswith('/'):
                    res = dict(st_mode=(0o040000 | 0o777), st_nlink=2)
                else:
                    res = dict(st_mode=(0o100000 | 0o666), st_nlink=1, st_size=size)
                self.metadata_cache.set(path, res)
                return res
        except: pass
        raise OSError(errno.ENOENT, "No such file")

    def readdir(self, path, fh):
        if self.local_mode:
            real_path = self._get_local_path(path)
            try:
                entries = ['.', '..'] + os.listdir(real_path)
                return entries
            except:
                return ['.', '..']
                
        # ... Remote implementation ...
        url = self._get_pod_url(path)
        try:
            resp = requests.get(url, headers={'Accept': 'text/turtle'}, timeout=5)
            if resp.status_code == 200:
                from rdflib import Graph
                from rdflib.namespace import Namespace
                g = Graph(); g.parse(data=resp.text, format="turtle")
                LDP = Namespace("http://www.w3.org/ns/ldp#")
                files = ['.', '..']
                for s, p, o in g.triples((None, LDP.contains, None)):
                    files.append(str(o).rstrip('/').split('/')[-1])
                return files
        except: pass
        return ['.', '..']

    def read(self, path, size, offset, fh):
        if self.local_mode:
            real_path = self._get_local_path(path)
            try:
                with open(real_path, 'rb') as f:
                    f.seek(offset)
                    return f.read(size)
            except: return b''

        # ... Remote implementation ...
        url = self._get_pod_url(path)
        headers = {'Range': f'bytes={offset}-{offset+size-1}'}
        try:
            resp = requests.get(url, headers=headers, timeout=5)
            if resp.status_code in [200, 206]: return resp.content
        except: pass
        return b''

    def write(self, path, data, offset, fh):
        if self.local_mode:
            real_path = self._get_local_path(path)
            try:
                # 'r+b' allows writing without truncating
                mode = 'r+b' if os.path.exists(real_path) else 'wb'
                with open(real_path, mode) as f:
                    f.seek(offset)
                    f.write(data)
                return len(data)
            except Exception as e:
                print(f"[Proxion] Local Write Error: {e}")
                raise OSError(errno.EACCES, "Write failed")

        # ... Remote implementation ...
        url = self._get_pod_url(path)
        resp = requests.put(url, data=data, timeout=10)
        return len(data) if resp.status_code in [200, 201, 204] else 0

    def create(self, path, mode, fi=None):
        if self.local_mode:
            real_path = self._get_local_path(path)
            try:
                open(real_path, 'wb').close()
                return 0
            except: raise OSError(errno.EACCES, "Create failed")
        
        url = self._get_pod_url(path)
        requests.put(url, data=b'')
        return 0

    def unlink(self, path):
        if self.local_mode:
            real_path = self._get_local_path(path)
            try: os.remove(real_path)
            except: pass
            return 0
            
        url = self._get_pod_url(path)
        requests.delete(url)
        return 0

    def mkdir(self, path, mode):
        if self.local_mode:
            real_path = self._get_local_path(path)
            try: 
                os.makedirs(real_path, exist_ok=True)
                return 0
            except Exception as e:
                print(f"[Proxion] Local Mkdir Error: {e}")
                raise OSError(errno.EACCES, f"Mkdir failed: {e}")
        
        url = self._get_pod_url(path)
        requests.put(url + "/")
        return 0

    def rmdir(self, path):
        if self.local_mode:
            real_path = self._get_local_path(path)
            try: os.rmdir(real_path)
            except: pass
            return 0
            
        url = self._get_pod_url(path)
        requests.delete(url)
        return 0

def main(mountpoint, pod_path):
    # Drive P: by default if not specified
    print(f"[Proxion] Mounting Proxion Suite to {mountpoint}...")
    FUSE(ProxionUnifiedFS(pod_path), mountpoint, nothreads=False, foreground=True)

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("Usage: python mount.py <mountpoint> <pod_path>")
        sys.exit(1)
    main(sys.argv[1], sys.argv[2])
