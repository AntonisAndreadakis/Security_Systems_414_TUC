import os
import tempfile
import unittest
from datetime import datetime, timedelta
from typing import List

import ac_system

class TestACSystemComprehensive(unittest.TestCase):
    def setUp(self):
        fd, self.logpath = tempfile.mkstemp(prefix="test_log_", suffix=".log")
        os.close(fd)
        # Sample fingerprints for testing
        self.fp1 = "d41d8cd98f00b204e9800998ecf8427e"
        self.fp2 = "e48bd9e9b9b027d21055007ac56d7816"
        self.fp3 = "f5eb612ae3992c3b96e732318d860cb4"

    def tearDown(self):
        try:
            os.remove(self.logpath)
        except OSError:
            pass

    def write_log(self, lines: List[str]):
        with open(self.logpath, "w", encoding="utf-8") as f:
            for line in lines:
                f.write(line + "\n")

    def test_read_log_malformed_lines(self):
        """Test parsing of malformed/incomplete log lines"""
        lines = [
            # Missing fields
            "100",
            "100\t0 0 1",
            # Extra tabs
            "100\t0 0 1\tfile\t2025-1-1\t12:0:0\tfp\t\t\t",
            # Missing action fields
            "100\t0\tfile\t2025-1-1\t12:0:0\tfp",
            # Garbage in fields
            "abc\txyz 0 1\tfile\t2025-1-1\t12:0:0\tfp",
            # Valid line for comparison
            "100\t0 0 1\tfile\t2025-1-1\t12:0:0\tfp"
        ]
        self.write_log(lines)
        entries = ac_system.read_log_file(self.logpath)
        # Should get 6 entries with default/fallback values for bad ones
        self.assertEqual(len(entries), 6)
        # Check the valid line parsed correctly
        self.assertEqual(entries[-1].uid, 100)
        self.assertEqual(entries[-1].action_type, 0)

    def test_list_malicious_users(self):
        """Test detection of malicious users with denied actions"""
        lines = [
            # User 100: 2 denied actions
            f"100\t0 1 1\tfile1\t2025-1-1\t12:0:0\t{self.fp1}",
            f"100\t1 1 1\tfile2\t2025-1-1\t12:0:0\t{self.fp1}",
            # User 101: 1 denied action
            f"101\t0 1 1\tfile1\t2025-1-1\t12:0:0\t{self.fp1}",
            # User 102: no denied actions
            f"102\t0 0 1\tfile1\t2025-1-1\t12:0:0\t{self.fp1}"
        ]
        self.write_log(lines)
        entries = ac_system.read_log_file(self.logpath)
        malicious = ac_system.list_malicious(entries, threshold=2)
        self.assertEqual(len(malicious), 1)
        self.assertEqual(malicious[0], 100)

    def test_list_modifications_complex(self):
        """Test modification detection with multiple users and fingerprints"""
        lines = [
            # Initial state
            f"100\t0 0 1\tfile1\t2025-1-1\t12:0:0\t{self.fp1}",
            # User 100 modifies (fp changes)
            f"100\t2 0 1\tfile1\t2025-1-1\t12:1:0\t{self.fp2}",
            # User 101 writes but same fingerprint
            f"101\t2 0 1\tfile1\t2025-1-1\t12:2:0\t{self.fp2}",
            # User 100 modifies again
            f"100\t2 0 1\tfile1\t2025-1-1\t12:3:0\t{self.fp3}",
            # Different file (should be ignored)
            f"100\t2 0 1\tfile2\t2025-1-1\t12:4:0\t{self.fp1}"
        ]
        self.write_log(lines)
        entries = ac_system.read_log_file(self.logpath)
        mods = ac_system.list_modifications(entries, "file1")
        # User 100 should have 2 modifications (2 fingerprint changes)
        self.assertEqual(mods.get(100), 2)
        # User 101 should not be counted (no fingerprint change)
        self.assertNotIn(101, mods)

    def test_files_created_edge_cases(self):
        """Test file creation counting with edge cases in dates"""
        now = datetime.now()
        t1 = now - timedelta(minutes=5)
        t2 = now - timedelta(minutes=15)
        t3 = now - timedelta(minutes=25)
        lines = [
            # Recent creation
            f"0\t0 0 1\tfile1\t{t1.year}-{t1.month}-{t1.day}\t{t1.hour}:{t1.minute}:{t1.second}\t{self.fp1}",
            # Mid-range creation
            f"0\t0 0 1\tfile2\t{t2.year}-{t2.month}-{t2.day}\t{t2.hour}:{t2.minute}:{t2.second}\t{self.fp1}",
            # Outside range
            f"0\t0 0 1\tfile3\t{t3.year}-{t3.month}-{t3.day}\t{t3.hour}:{t3.minute}:{t3.second}\t{self.fp1}",
            # Non-creation events (should be ignored)
            f"0\t1 0 1\tfile4\t{t1.year}-{t1.month}-{t1.day}\t{t1.hour}:{t1.minute}:{t1.second}\t{self.fp1}",
            f"0\t2 0 1\tfile5\t{t1.year}-{t1.month}-{t1.day}\t{t1.hour}:{t1.minute}:{t1.second}\t{self.fp1}",
            # Malformed date (should be skipped)
            "0\t0 0 1\tfile6\tbad-date\t12:00:00\tfp",
            # Single-digit month/day/hour (should work)
            "0\t0 0 1\tfile7\t2025-1-6\t9:5:0\tfp"
        ]
        self.write_log(lines)
        entries = ac_system.read_log_file(self.logpath)
        # Count files created in last 20 minutes
        count = ac_system.files_created_in_range(entries, 20)
        # Should find 2 files (file1 and file2) within range
        self.assertEqual(count, 2)

    def test_print_encrypted_files(self):
        """Test encrypted file detection"""
        lines = [
            # Regular encrypted files
            f"0\t0 0 1\tfile1.encrypt\t2025-1-1\t12:0:0\t{self.fp1}",
            f"0\t0 0 1\tfile2.encrypt\t2025-1-1\t12:0:0\t{self.fp1}",
            # Non-encrypted files
            f"0\t0 0 1\tfile3\t2025-1-1\t12:0:0\t{self.fp1}",
            # File with .encrypt in middle (should not count)
            f"0\t0 0 1\tmy.encrypt.backup\t2025-1-1\t12:0:0\t{self.fp1}",
            # Multiple operations on same encrypted file
            f"0\t2 0 1\tfile1.encrypt\t2025-1-1\t12:1:0\t{self.fp2}"
        ]
        self.write_log(lines)
        entries = ac_system.read_log_file(self.logpath)
        encrypted = ac_system.print_encrypted(entries)
        # Should find 2 unique encrypted files
        self.assertEqual(len(encrypted), 2)
        self.assertIn("file1", encrypted)
        self.assertIn("file2", encrypted)

if __name__ == '__main__':
    unittest.main()
