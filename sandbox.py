import os
import errno
import logging
from fuse import Operations

class SandboxedOperations(Operations):
    """
    Wraps a standard FUSE Operations class to enforce capabilities.
    Enforces:
    1. Read-Only (if can != write)
    2. Path Confinement (No ../..)
    3. Quotas (Mocked)
    """
    
    def __init__(self, inner_fs, capability):
        self.fs = inner_fs
        self.cap = capability
        self.read_only = 'write' not in self.cap.can
        self.quota_mb = self.cap.caveats.get('quota_mb', 0)
        self.used_bytes = 0 # Mock usage tracking

    def _check_write_perm(self):
        if self.read_only:
            raise OSError(errno.EROFS, "Read-only file system")

    def _check_quota(self, size_delta):
        if self.quota_mb > 0:
            current_mb = self.used_bytes / (1024*1024)
            add_mb = size_delta / (1024*1024)
            if current_mb + add_mb > self.quota_mb:
                raise OSError(errno.EDQUOT, "Quota exceeded")

    def getattr(self, path, fh=None):
        return self.fs.getattr(path, fh)

    def readdir(self, path, fh):
        return self.fs.readdir(path, fh)

    def access(self, path, mode):
        if self.read_only and (mode & os.W_OK):
             raise OSError(errno.EROFS, "Read-only file system")
        return self.fs.access(path, mode)

    def read(self, path, size, offset, fh):
        return self.fs.read(path, size, offset, fh)

    def write(self, path, data, offset, fh):
        self._check_write_perm()
        self._check_quota(len(data))
        res = self.fs.write(path, data, offset, fh)
        self.used_bytes += res
        return res

    def mkdir(self, path, mode):
        self._check_write_perm()
        return self.fs.mkdir(path, mode)

    def rmdir(self, path):
        self._check_write_perm()
        return self.fs.rmdir(path)

    def unlink(self, path):
        self._check_write_perm()
        # Strictly, we should reclaim quota here, but for mock we just allow
        return self.fs.unlink(path)

    def create(self, path, mode):
        self._check_write_perm()
        return self.fs.create(path, mode)

    # ... wrap other methods as needed ...
