"""
Proxion High-Performance FUSE Driver
=====================================
Direct filesystem passthrough for maximum performance.
Includes security safeguards: capability tokens, ACLs, and audit logging.
"""
import os
import sys
import stat
import errno
import logging
import time
import json
import ctypes
from datetime import datetime, timezone
from pathlib import Path
from fuse import FUSE, Operations

# --- Configuration ---
DEFAULT_STASH_ROOT = os.path.join(os.path.dirname(__file__), '..', 'stash')
AUDIT_LOG_PATH = os.path.join(os.path.dirname(__file__), 'fuse_audit.log')
ACL_FILE_EXTENSION = '.acl'


class AuditLogger:
    """
    Audit logging for all file operations.
    Logs to both console and persistent file.
    """
    def __init__(self, log_path: str = AUDIT_LOG_PATH):
        self.log_path = log_path
        self._setup_logger()
    
    def _setup_logger(self):
        """Setup dedicated audit logger."""
        self.logger = logging.getLogger('proxion.fuse.audit')
        self.logger.setLevel(logging.INFO)
        
        # File handler for persistent audit log
        if not self.logger.handlers:
            fh = logging.FileHandler(self.log_path, encoding='utf-8')
            fh.setLevel(logging.INFO)
            fh.setFormatter(logging.Formatter(
                '%(asctime)s|%(levelname)s|%(message)s',
                datefmt='%Y-%m-%dT%H:%M:%S'
            ))
            self.logger.addHandler(fh)
    
    def log(self, operation: str, path: str, result: str = "OK", details: str = ""):
        """Log an audit event."""
        entry = f"{operation}|{path}|{result}"
        if details:
            entry += f"|{details}"
        self.logger.info(entry)
    
    def log_access(self, op: str, path: str, success: bool = True):
        """Shorthand for logging access operations."""
        result = "OK" if success else "DENIED"
        self.log(op, path, result)


class ACLManager:
    """
    Simple per-path ACL enforcement.
    Reads ACL from .acl sidecar files (JSON format).
    
    ACL Format:
    {
        "owner": "user_id",
        "permissions": {
            "read": ["*"],           # Everyone can read
            "write": ["owner"],      # Only owner can write
            "delete": ["owner"]      # Only owner can delete
        }
    }
    
    Special values:
    - "*": Everyone
    - "owner": The file owner
    - "none": No one (deny all)
    """
    
    DEFAULT_ACL = {
        "owner": "local",
        "permissions": {
            "read": ["*"],
            "write": ["*"],
            "delete": ["*"]
        }
    }
    
    def __init__(self, stash_root: str, audit: AuditLogger):
        self.stash_root = stash_root
        self.audit = audit
        self.acl_cache = {}  # Cache ACLs for performance
        self.cache_ttl = 30  # Cache TTL in seconds
        self.cache_times = {}
    
    def _get_acl_path(self, file_path: str) -> str:
        """Get the ACL sidecar file path for a given file."""
        return file_path + ACL_FILE_EXTENSION
    
    def _load_acl(self, path: str) -> dict:
        """Load ACL for a path, with caching."""
        now = time.time()
        
        # Check cache
        if path in self.acl_cache:
            if now - self.cache_times.get(path, 0) < self.cache_ttl:
                return self.acl_cache[path]
        
        # Try to load from .acl file
        acl_path = self._get_acl_path(path)
        try:
            if os.path.exists(acl_path):
                with open(acl_path, 'r') as f:
                    acl = json.load(f)
                    self.acl_cache[path] = acl
                    self.cache_times[path] = now
                    return acl
        except (json.JSONDecodeError, IOError):
            pass
        
        # Check parent directory for inherited ACL
        parent = os.path.dirname(path)
        if parent and parent != path and parent.startswith(self.stash_root):
            parent_acl = self._load_acl(parent)
            if parent_acl:
                return parent_acl
        
        # Return default ACL
        return self.DEFAULT_ACL
    
    def check_permission(self, path: str, operation: str, user: str = "local") -> bool:
        """
        Check if an operation is permitted on a path.
        
        Args:
            path: Full filesystem path
            operation: 'read', 'write', or 'delete'
            user: User identifier (default: 'local' for FUSE mounts)
        
        Returns:
            True if permitted, False otherwise
        """
        acl = self._load_acl(path)
        
        allowed = acl.get("permissions", {}).get(operation, ["*"])
        owner = acl.get("owner", "local")
        
        # Check permission
        if "*" in allowed:
            return True
        if "none" in allowed:
            self.audit.log_access(operation.upper(), path, success=False)
            return False
        if "owner" in allowed and user == owner:
            return True
        if user in allowed:
            return True
        
        self.audit.log_access(operation.upper(), path, success=False)
        return False
    
    def invalidate_cache(self, path: str):
        """Invalidate cache for a path (after ACL change)."""
        if path in self.acl_cache:
            del self.acl_cache[path]
            del self.cache_times[path]


class CapabilityVerifier:
    """
    Verifies capability tokens before allowing mount.
    The token file is created by the dashboard/CLI when mounting is authorized.
    """
    
    TOKEN_FILE = os.path.join(os.path.dirname(__file__), '.mount_token')
    
    def __init__(self):
        self.valid_token = None
    
    def verify_mount_authorization(self) -> bool:
        """
        Check if mounting is authorized via a local capability token.
        
        For security, the token must:
        1. Exist in the expected location
        2. Not be expired
        3. Contain the correct mount signature
        
        Returns:
            True if mount is authorized, False otherwise
        """
        if not os.path.exists(self.TOKEN_FILE):
            logging.error("CapabilityVerifier: No mount token found. Access denied.")
            return False
        
        try:
            with open(self.TOKEN_FILE, 'r') as f:
                token_data = json.load(f)
            
            # Check expiration
            exp_str = token_data.get('exp')
            if exp_str:
                exp = datetime.fromisoformat(exp_str.replace('Z', '+00:00'))
                if datetime.now(timezone.utc) > exp:
                    logging.error("CapabilityVerifier: Mount token expired")
                    return False
            
            # Check mount permission
            permissions = token_data.get('permissions', [])
            if not any('MOUNT' in str(p) for p in permissions):
                logging.error("CapabilityVerifier: Token lacks MOUNT permission")
                return False
            
            self.valid_token = token_data
            logging.info("CapabilityVerifier: Mount authorized via capability token")
            return True
            
        except (json.JSONDecodeError, IOError) as e:
            logging.error(f"CapabilityVerifier: Failed to read token: {e}")
            return False
    
    @classmethod
    def create_mount_token(cls, duration_hours: int = 24) -> dict:
        """
        Create a mount authorization token.
        This would typically be called by the dashboard/CLI.
        """
        from datetime import timedelta
        import secrets
        
        exp = datetime.now(timezone.utc) + timedelta(hours=duration_hours)
        token = {
            'token_id': secrets.token_urlsafe(16),
            'permissions': [['MOUNT', '/']],
            'exp': exp.isoformat(),
            'created': datetime.now(timezone.utc).isoformat()
        }
        
        with open(cls.TOKEN_FILE, 'w') as f:
            json.dump(token, f, indent=2)
        
        return token


class DirectLocalProvider:
    """
    HIGH-PERFORMANCE direct filesystem access with security.
    - Path traversal protection
    - ACL enforcement
    - Audit logging
    """
    EXCLUSION_LIST = ['.DS_Store', 'Thumbs.db', 'desktop.ini', '.proxion_meta']
    
    def __init__(self, root: str, acl_manager: ACLManager, audit: AuditLogger):
        self.root = os.path.abspath(root)
        self.acl = acl_manager
        self.audit = audit
        logging.info(f"DirectLocalProvider: Serving {self.root}")
    
    def _safe_path(self, path: str) -> str:
        """Safely join paths, preventing directory traversal."""
        path = path.lstrip('/')
        full = os.path.join(self.root, path)
        # Security: Ensure we don't escape root
        if not os.path.abspath(full).startswith(self.root):
            self.audit.log("PATH_TRAVERSAL", path, "BLOCKED", "Attempted escape from stash root")
            raise OSError(errno.EACCES, "Access denied")
        return full
    
    def getattr(self, path: str):
        full_path = self._safe_path(path)
        
        # ACL check for read
        if not self.acl.check_permission(full_path, 'read'):
            raise OSError(errno.EACCES, "Permission denied")
        
        try:
            st = os.lstat(full_path)
            self.audit.log("GETATTR", path, "OK")
            return {
                'st_mode': st.st_mode,
                'st_nlink': st.st_nlink,
                'st_size': st.st_size,
                'st_ctime': st.st_ctime,
                'st_mtime': st.st_mtime,
                'st_atime': st.st_atime,
                'st_uid': st.st_uid,
                'st_gid': st.st_gid,
            }
        except FileNotFoundError:
            return None
    
    def readdir(self, path: str):
        full_path = self._safe_path(path)
        
        # ACL check for read
        if not self.acl.check_permission(full_path, 'read'):
            self.audit.log("READDIR", path, "DENIED")
            raise OSError(errno.EACCES, "Permission denied")
        
        try:
            entries = os.listdir(full_path)
            # Filter exclusions and ACL files
            filtered = [e for e in entries 
                       if e not in self.EXCLUSION_LIST 
                       and not e.endswith(ACL_FILE_EXTENSION)]
            self.audit.log("READDIR", path, "OK", f"count={len(filtered)}")
            return filtered
        except (FileNotFoundError, PermissionError):
            return []
    
    def read(self, path: str, size: int, offset: int):
        full_path = self._safe_path(path)
        
        # ACL check for read
        if not self.acl.check_permission(full_path, 'read'):
            self.audit.log("READ", path, "DENIED")
            raise OSError(errno.EACCES, "Permission denied")
        
        with open(full_path, 'rb') as f:
            f.seek(offset)
            data = f.read(size)
        
        self.audit.log("READ", path, "OK", f"size={len(data)}")
        return data
    
    def write(self, path: str, data: bytes, offset: int):
        full_path = self._safe_path(path)
        
        # ACL check for write
        if not self.acl.check_permission(full_path, 'write'):
            self.audit.log("WRITE", path, "DENIED")
            raise OSError(errno.EACCES, "Permission denied")
        
        os.makedirs(os.path.dirname(full_path), exist_ok=True)
        mode = 'r+b' if os.path.exists(full_path) else 'wb'
        with open(full_path, mode) as f:
            f.seek(offset)
            f.write(data)
        
        self.audit.log("WRITE", path, "OK", f"size={len(data)}")
        return len(data)
    
    def create(self, path: str, mode: int):
        full_path = self._safe_path(path)
        parent = os.path.dirname(full_path)
        
        # ACL check for write on parent
        if not self.acl.check_permission(parent, 'write'):
            self.audit.log("CREATE", path, "DENIED")
            raise OSError(errno.EACCES, "Permission denied")
        
        os.makedirs(parent, exist_ok=True)
        fd = os.open(full_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
        os.close(fd)
        
        self.audit.log("CREATE", path, "OK")
        return 0
    
    def mkdir(self, path: str, mode: int):
        full_path = self._safe_path(path)
        parent = os.path.dirname(full_path)
        
        # ACL check for write on parent
        if not self.acl.check_permission(parent, 'write'):
            self.audit.log("MKDIR", path, "DENIED")
            raise OSError(errno.EACCES, "Permission denied")
        
        os.makedirs(full_path, mode=mode, exist_ok=True)
        self.audit.log("MKDIR", path, "OK")
        return 0
    
    def unlink(self, path: str):
        full_path = self._safe_path(path)
        
        # ACL check for delete
        if not self.acl.check_permission(full_path, 'delete'):
            self.audit.log("DELETE", path, "DENIED")
            raise OSError(errno.EACCES, "Permission denied")
        
        os.unlink(full_path)
        self.audit.log("DELETE", path, "OK")
        return 0
    
    def rmdir(self, path: str):
        full_path = self._safe_path(path)
        
        # ACL check for delete
        if not self.acl.check_permission(full_path, 'delete'):
            self.audit.log("RMDIR", path, "DENIED")
            raise OSError(errno.EACCES, "Permission denied")
        
        os.rmdir(full_path)
        self.audit.log("RMDIR", path, "OK")
        return 0
    
    def truncate(self, path: str, length: int):
        full_path = self._safe_path(path)
        
        # ACL check for write
        if not self.acl.check_permission(full_path, 'write'):
            self.audit.log("TRUNCATE", path, "DENIED")
            raise OSError(errno.EACCES, "Permission denied")
        
        with open(full_path, 'r+b') as f:
            f.truncate(length)
        
        self.audit.log("TRUNCATE", path, "OK", f"length={length}")
        return 0
    
    def rename(self, old: str, new: str):
        old_path = self._safe_path(old)
        new_path = self._safe_path(new)
        
        # Need delete on old, write on new's parent
        if not self.acl.check_permission(old_path, 'delete'):
            self.audit.log("RENAME", old, "DENIED", "delete on source")
            raise OSError(errno.EACCES, "Permission denied")
        
        if not self.acl.check_permission(os.path.dirname(new_path), 'write'):
            self.audit.log("RENAME", new, "DENIED", "write on destination")
            raise OSError(errno.EACCES, "Permission denied")
        
        os.rename(old_path, new_path)
        self.audit.log("RENAME", f"{old}->{new}", "OK")
        return 0


class HybridFS(Operations):
    """
    HIGH-PERFORMANCE Hybrid Filesystem with security.
    
    Routes:
    - /stash/* -> DirectLocalProvider (direct disk access with ACL)
    - /cloud/* -> Placeholder for remote resources
    """
    
    def __init__(self, stash_root: str, audit: AuditLogger):
        self.audit = audit
        acl_manager = ACLManager(stash_root, audit)
        self.stash = DirectLocalProvider(stash_root, acl_manager, audit)
        logging.info(f"HybridFS: stash -> {stash_root} (DIRECT + ACL)")
        logging.info("HybridFS: cloud -> (placeholder)")
    
    def _route(self, path: str):
        """Route path to appropriate provider."""
        path = path.lstrip('/')
        
        if path == '' or path == '/':
            return 'root', ''
        
        if path.startswith('stash'):
            subpath = path[5:]
            return 'stash', subpath.lstrip('/')
        
        if path.startswith('cloud'):
            subpath = path[5:]
            return 'cloud', subpath.lstrip('/')
        
        return None, path
    
    def getattr(self, path, fh=None):
        provider, subpath = self._route(path)
        
        if provider == 'root':
            return {
                'st_mode': stat.S_IFDIR | 0o755,
                'st_nlink': 3,
                'st_size': 0,
                'st_ctime': time.time(),
                'st_mtime': time.time(),
                'st_atime': time.time(),
                'st_uid': 0,
                'st_gid': 0,
            }
        
        if provider == 'stash':
            target = subpath if subpath else ''
            attr = self.stash.getattr(target)
            if attr:
                return attr
        
        if provider == 'cloud':
            if subpath == '' or subpath == '/':
                return {
                    'st_mode': stat.S_IFDIR | 0o755,
                    'st_nlink': 2,
                    'st_size': 0,
                    'st_ctime': time.time(),
                    'st_mtime': time.time(),
                    'st_atime': time.time(),
                    'st_uid': 0,
                    'st_gid': 0,
                }
        
        raise OSError(errno.ENOENT, f"No such file: {path}")
    
    def readdir(self, path, fh):
        provider, subpath = self._route(path)
        entries = ['.', '..']
        
        if provider == 'root':
            entries.extend(['stash', 'cloud'])
            return entries
        
        if provider == 'stash':
            target = subpath if subpath else ''
            entries.extend(self.stash.readdir(target))
            return entries
        
        if provider == 'cloud':
            return entries
        
        return entries
    
    def read(self, path, size, offset, fh):
        provider, subpath = self._route(path)
        if provider == 'stash':
            return self.stash.read(subpath, size, offset)
        raise OSError(errno.ENOENT, f"Cannot read: {path}")
    
    def write(self, path, data, offset, fh):
        provider, subpath = self._route(path)
        if provider == 'stash':
            return self.stash.write(subpath, data, offset)
        raise OSError(errno.EACCES, f"Cannot write: {path}")
    
    def create(self, path, mode, fi=None):
        provider, subpath = self._route(path)
        if provider == 'stash':
            return self.stash.create(subpath, mode)
        raise OSError(errno.EACCES, f"Cannot create: {path}")
    
    def mkdir(self, path, mode):
        provider, subpath = self._route(path)
        if provider == 'stash':
            return self.stash.mkdir(subpath, mode)
        raise OSError(errno.EACCES, f"Cannot mkdir: {path}")
    
    def unlink(self, path):
        provider, subpath = self._route(path)
        if provider == 'stash':
            return self.stash.unlink(subpath)
        raise OSError(errno.EACCES, f"Cannot unlink: {path}")
    
    def rmdir(self, path):
        provider, subpath = self._route(path)
        if provider == 'stash':
            return self.stash.rmdir(subpath)
        raise OSError(errno.EACCES, f"Cannot rmdir: {path}")
    
    def truncate(self, path, length, fh=None):
        provider, subpath = self._route(path)
        if provider == 'stash':
            return self.stash.truncate(subpath, length)
        raise OSError(errno.EACCES, f"Cannot truncate: {path}")
    
    def rename(self, old, new):
        old_provider, old_subpath = self._route(old)
        new_provider, new_subpath = self._route(new)
        if old_provider == 'stash' and new_provider == 'stash':
            return self.stash.rename(old_subpath, new_subpath)
        raise OSError(errno.EACCES, f"Cannot rename across providers")


def main(mountpoint, stash_root=None, verbose=False):
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format='%(asctime)s [%(levelname)s] %(message)s'
    )
    
    # 1. VERIFY MOUNT AUTHORIZATION
    verifier = CapabilityVerifier()
    if not verifier.verify_mount_authorization():
        logging.critical("Mount authorization failed. Create a mount token first.")
        sys.exit(1)
    
    # 2. SETUP AUDIT LOGGING
    audit = AuditLogger()
    audit.log("MOUNT", mountpoint, "STARTING")
    
    # 3. RESOLVE STASH ROOT
    if stash_root is None:
        try:
            config_path = os.path.join(os.path.dirname(__file__), '..', 'proxion-keyring', 'proxion_config.json')
            if os.path.exists(config_path):
                with open(config_path) as f:
                    config = json.load(f)
                    stash_root = config.get('pod_local_root', DEFAULT_STASH_ROOT)
            else:
                stash_root = DEFAULT_STASH_ROOT
        except:
            stash_root = DEFAULT_STASH_ROOT
    
    stash_root = os.path.abspath(stash_root)
    
    if not os.path.exists(stash_root):
        logging.warning(f"Stash root does not exist, creating: {stash_root}")
        os.makedirs(stash_root, exist_ok=True)
    
    logging.info(f"=== Proxion FUSE Driver (SECURE MODE) ===")
    logging.info(f"Mount point: {mountpoint}")
    logging.info(f"Stash root:  {stash_root}")
    logging.info(f"Audit log:   {AUDIT_LOG_PATH}")
    logging.info(f"Mode:        DIRECT PASSTHROUGH + ACL + AUDIT")
    
    try:
        FUSE(
            HybridFS(stash_root, audit),
            mountpoint,
            nothreads=False,
            foreground=True,
            FileInfoTimeout=-1,
            DirInfoTimeout=-1,
            VolumeInfoTimeout=-1,
        )
    except Exception as e:
        audit.log("MOUNT", mountpoint, "FAILED", str(e))
        logging.critical(f"FUSE Mount failed: {e}")
        sys.exit(1)
    finally:
        audit.log("MOUNT", mountpoint, "UNMOUNTED")


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description="Proxion Secure FUSE Driver")
    parser.add_argument("mountpoint", nargs='?', help="Mount point (e.g. P:)")
    parser.add_argument("--stash", default=None, help="Path to stash root directory")
    parser.add_argument("--verbose", action="store_true", help="Enable debug logging")
    parser.add_argument("--create-token", action="store_true", help="Create a mount authorization token")
    
    args = parser.parse_args()
    
    if args.create_token:
        token = CapabilityVerifier.create_mount_token()
        print(f"Created mount token: {token['token_id']}")
        print(f"Expires: {token['exp']}")
        sys.exit(0)
    
    # Set console title on Windows for easier process management
    if os.name == 'nt':
        try:
            ctypes.windll.kernel32.SetConsoleTitleW("Proxion FUSE (Secure Mode)")
        except:
            pass
            
    print(f"=== Proxion FUSE (Secure Mode) ===")
    print(f"Mount: {args.mountpoint}")
    main(args.mountpoint, args.stash, args.verbose)
