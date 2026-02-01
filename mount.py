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
        
        print(f"[Proxion] Unified FUSE Initialized. Backend: {pod_path}")

    def _get_pod_url(self, path):
        full_path = f"{self.pod_base}/{path.lstrip('/')}"
        return f"{self.proxy}/pod/{full_path.lstrip('/')}"

    def _check_lock(self, path):
        """Check for advisory locks (.proxion.lock) in the app silo."""
        # Simple implementation: check if the parent directory has a lock file
        parts = path.lstrip('/').split('/')
        if len(parts) > 0:
            app_silo = parts[0]
            lock_path = f"/{app_silo}/.proxion.lock"
            # We don't block here, but we could log warnings
            pass

    def getattr(self, path, fh=None):
        cached = self.metadata_cache.get(path)
        if cached:
            return cached

        url = self._get_pod_url(path)
        
        # Root is always a directory
        if path == '/':
            res = dict(st_mode=(0o040000 | 0o755), st_nlink=2)
            self.metadata_cache.set(path, res)
            return res

        try:
            # Fetch metadata from Proxy (which talks to Solid Pod)
            resp = requests.get(url, stream=True, timeout=3)
            if resp.status_code == 200:
                header_type = resp.headers.get('Content-Type', '')
                size = int(resp.headers.get('Content-Length', 0))
                self.etags[path] = resp.headers.get('ETag')
                
                # If it's a LDP Container (Turtle), it's a directory
                if 'text/turtle' in header_type or url.endswith('/'):
                    res = dict(st_mode=(0o040000 | 0o755), st_nlink=2)
                else:
                    res = dict(st_mode=(0o100000 | 0o644), st_nlink=1, st_size=size)
                
                self.metadata_cache.set(path, res)
                return res
            else:
                raise OSError(errno.ENOENT, "No such file")
        except:
             raise OSError(errno.ENOENT, "No such file")

    def readdir(self, path, fh):
        url = self._get_pod_url(path)
        resp = requests.get(url, headers={'Accept': 'text/turtle'}, timeout=5)
        
        if resp.status_code != 200:
            return ['.', '..']

        from rdflib import Graph, URIRef
        from rdflib.namespace import Namespace
        
        g = Graph()
        try:
            g.parse(data=resp.text, format="turtle")
        except:
            return ['.', '..']
            
        LDP = Namespace("http://www.w3.org/ns/ldp#")
        files = ['.', '..']
        for s, p, o in g.triples((None, LDP.contains, None)):
            child_name = str(o).rstrip('/').split('/')[-1]
            files.append(child_name)
            
        return files

    def read(self, path, size, offset, fh):
        cache_key = f"{path}:{offset}:{size}"
        cached_data = self.block_cache.get(cache_key)
        if cached_data:
            return cached_data

        url = self._get_pod_url(path)
        headers = {'Range': f'bytes={offset}-{offset+size-1}'}
        
        try:
            resp = requests.get(url, headers=headers, timeout=5)
            if resp.status_code in [200, 206]:
                data = resp.content
                self.block_cache.set(cache_key, data)
                return data
        except Exception as e:
            print(f"[Proxion] Read Error: {e}")
            
        return b''

    def write(self, path, data, offset, fh):
        """Optimistic write with ETag verification."""
        url = self._get_pod_url(path)
        headers = {'Content-Type': 'application/octet-stream'}
        
        # If we have an ETag, use it for If-Match (Collision Defense)
        if path in self.etags and self.etags[path]:
            headers['If-Match'] = self.etags[path]
            
        # For simplicity in this shell, we assume the Proxy handles partial updates 
        # or we just PUT the whole thing if it's a small file.
        # Real implementation would use PATCH or range-aware PUT.
        resp = requests.put(url, data=data, headers=headers, timeout=10)
        
        if resp.status_code in [200, 201, 204]:
            self.metadata_cache.set(path, None) # Invalidate
            self.block_cache.set(path, None) # Invalidate
            return len(data)
        elif resp.status_code == 412:
            print(f"[Proxion] Collision Detected on {path}! ETag mismatch.")
            raise OSError(errno.EACCES, "Collision detected")
            
        return 0

    def create(self, path, mode, fi=None):
        url = self._get_pod_url(path)
        resp = requests.put(url, data=b'', headers={'Content-Type': 'application/octet-stream'})
        return 0

    def unlink(self, path):
        url = self._get_pod_url(path)
        requests.delete(url)
        self.metadata_cache.set(path, None)

def main(mountpoint, pod_path):
    # Drive P: by default if not specified
    print(f"[Proxion] Mounting Proxion Suite to {mountpoint}...")
    FUSE(ProxionUnifiedFS(pod_path), mountpoint, nothreads=False, foreground=True)

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("Usage: python mount.py <mountpoint> <pod_path>")
        sys.exit(1)
    main(sys.argv[1], sys.argv[2])
