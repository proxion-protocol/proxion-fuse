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
    Integrates physical disks as virtual directories within the Solid Pod (Drive P:).
    """
    def __init__(self, raw_sources):
        # raw_sources is a list of "Name|Path" strings
        self.mounts = {}
        self.primary_source = None
        
        for s in raw_sources:
            if '|' in s:
                name, path = s.split('|', 1)
                # Cleanup name for valid folder (no slashes, no spaces ideally)
                # Cleanup name for valid folder (No colons, no slashes, no spaces)
                safe_name = name.replace(' ', '_').replace('/', '').replace('\\', '').replace(':', '_')
                self.mounts[safe_name] = os.path.abspath(path.rstrip('/\\'))
                if not self.primary_source:
                    self.primary_source = self.mounts[safe_name]
        
        logging.info(f"FUSE Virtual Mounts: {self.mounts}")

    def _resolve(self, path):
        """Routes a pod path to the correct physical disk."""
        parts = path.lstrip('/\\').split('/')
        if not parts or parts[0] == '':
            return self.primary_source, True # It's the root
            
        virtual_dir = parts[0]
        if virtual_dir in self.mounts:
            # Route to the specific physical disk
            rel_path = os.sep.join(parts[1:])
            return os.path.join(self.mounts[virtual_dir], rel_path), False
            
        # Fallback to primary source (for legacy files in the pod root)
        return os.path.join(self.primary_source, path.lstrip('/\\')), False

    def getattr(self, path, fh=None):
        real_path, is_root = self._resolve(path)
        try:
            if is_root and not os.path.exists(real_path):
                # Return dummy dir stats for root so the mount doesn't fail
                return dict(st_mode=(0o40777), st_nlink=2, st_size=4096, 
                            st_ctime=time.time(), st_mtime=time.time(), st_atime=time.time())
            
            st = os.stat(real_path)
            return dict(st_mode=(st.st_mode | 0o777), st_nlink=st.st_nlink, st_size=st.st_size, 
                        st_ctime=st.st_ctime, st_mtime=st.st_mtime, st_atime=st.st_atime)
        except OSError:
            # Check if this is a virtual directory name
            parts = path.lstrip('/\\').split('/')
            if len(parts) == 1 and parts[0] in self.mounts:
                 return dict(st_mode=(0o40777), st_nlink=2, st_size=4096, 
                            st_ctime=time.time(), st_mtime=time.time(), st_atime=time.time())
            raise OSError(errno.ENOENT, f"No such file: {path}")

    def readdir(self, path, fh):
        real_path, is_root = self._resolve(path)
        entries = {'.', '..'}
        
        if is_root:
            # ONLY return virtual directories at the hub root for professional look
            entries.update(self.mounts.keys())
        else:
            try: entries.update(os.listdir(real_path))
            except: pass
            
        return list(entries)

    def read(self, path, size, offset, fh):
        real_path, _ = self._resolve(path)
        try:
            with open(real_path, 'rb') as f:
                f.seek(offset)
                return f.read(size)
        except: return b''

    def write(self, path, data, offset, fh):
        real_path, _ = self._resolve(path)
        try:
            os.makedirs(os.path.dirname(real_path), exist_ok=True)
            mode = 'r+b' if os.path.exists(real_path) else 'wb'
            with open(real_path, mode) as f:
                f.seek(offset)
                f.write(data)
            return len(data)
        except Exception as e:
            logging.error(f"Write Error at {path}: {e}")
            raise OSError(errno.EACCES, "Write failed")

    def create(self, path, mode, fi=None):
        real_path, _ = self._resolve(path)
        try:
            os.makedirs(os.path.dirname(real_path), exist_ok=True)
            open(real_path, 'wb').close()
            st = os.stat(real_path)
            # Necessary for some Windows apps to recognize the new file
            return 0
        except: raise OSError(errno.EACCES, "Create failed")

    def mkdir(self, path, mode):
        real_path, _ = self._resolve(path)
        try: 
            os.makedirs(real_path, exist_ok=True)
            return 0
        except Exception as e:
            raise OSError(errno.EACCES, f"Mkdir failed: {e}")

    def unlink(self, path):
        real_path, _ = self._resolve(path)
        try: os.remove(real_path)
        except: pass
        return 0

    def rmdir(self, path):
        real_path, _ = self._resolve(path)
        try: os.rmdir(real_path)
        except: pass
        return 0

def main(mountpoint, raw_sources, verbose=False):
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format='%(asctime)s [%(levelname)s] %(message)s'
    )
    logging.info(f"Mounting Virtual Pod to {mountpoint}...")
    try:
        FUSE(ProxionUnifiedFS(raw_sources), mountpoint, nothreads=False, foreground=True)
    except Exception as e:
        logging.critical(f"FUSE Mount failed: {e}")

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description="Proxion Virtual Pod FUSE Driver")
    parser.add_argument("mountpoint", help="Mount point (e.g. P:)")
    parser.add_argument("raw_sources", nargs='+', help="List of 'Name|Path' mappings")
    parser.add_argument("--verbose", action="store_true", help="Enable debug logging")
    
    args = parser.parse_args()
    print(f"--- FUSE Starting: {args.mountpoint} ---")
    print(f"--- Sources: {args.raw_sources} ---")
    main(args.mountpoint, args.raw_sources, args.verbose)
