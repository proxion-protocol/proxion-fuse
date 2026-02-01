
import unittest
import errno
from unittest.mock import MagicMock
from sandbox import SandboxedOperations

# Mock Capability Class (since we don't want to depend on proxion_core here for simple test)
class MockCapability:
    def __init__(self, can, quota_mb=0):
        self.can = can
        self.caveats = {"quota_mb": quota_mb}

class TestSandbox(unittest.TestCase):
    def setUp(self):
        self.mock_fs = MagicMock()
        self.mock_fs.write.return_value = 10 # Mock write 10 bytes success

    def test_read_only_blocks_write(self):
        # Create Read-Only Cap
        cap = MockCapability(can="read")
        sandbox = SandboxedOperations(self.mock_fs, cap)
        
        # Try Write
        with self.assertRaises(OSError) as cm:
            sandbox.write("/foo", b"data", 0, None)
        self.assertEqual(cm.exception.errno, errno.EROFS)
        
    def test_quota_exceeded(self):
        # Create Write Cap with 1MB Quota
        cap = MockCapability(can="write", quota_mb=1)
        sandbox = SandboxedOperations(self.mock_fs, cap)
        
        # Write small chunk - OK
        sandbox.write("/foo", b"x" * 1024, 0, None)
        
        # Write massive chunk > 1MB
        large_data = b"x" * (1024 * 1024 * 2)
        with self.assertRaises(OSError) as cm:
            sandbox.write("/foo", large_data, 0, None)
        self.assertEqual(cm.exception.errno, errno.EDQUOT)

if __name__ == '__main__':
    unittest.main()
