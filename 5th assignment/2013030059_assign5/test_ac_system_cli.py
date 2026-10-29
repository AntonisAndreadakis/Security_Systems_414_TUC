import io
import sys
import unittest
from unittest.mock import patch
import tempfile
import os
from datetime import datetime

import ac_system

class TestACSystemCLI(unittest.TestCase):
    def setUp(self):
        # Capture stdout
        self.old_stdout = sys.stdout
        self.stdout = io.StringIO()
        sys.stdout = self.stdout

        # Create test files with content
        test_files = {
            'file1.txt': 'Test content 1',
            'file2.txt': 'Test content 2',
            'file3.encrypt': 'Encrypted content',
            'original.txt.encrypt': 'Another encrypted file'
        }

        for fname, content in test_files.items():
            with open(fname, 'w') as f:
                f.write(content)

        # Create a temporary log file
        fd, self.logpath = tempfile.mkstemp(prefix="test_log_", suffix=".log")
        os.close(fd)

        # Save original LOGFILE path and point to our test log
        self.original_logfile = ac_system.LOGFILE
        ac_system.LOGFILE = self.logpath

        # Sample log entries with proper format matching behavior
        now = datetime.now()
        # Format: uid action denied fileStat path date time hexfp
        date_str = f"{now.year}-{now.month}-{now.day}"
        time_str = f"{now.hour}:{now.minute}:{now.second}"

        self.sample_lines = [
            # User 100 has multiple denied actions (malicious behavior)
            *[f"100\t1 1 0\tfile1.txt\t{date_str}\t{time_str}\td41d8cd98f00b204e9800998ecf8427e" for _ in range(10)],

            # File modifications by multiple users on file2.txt
            f"200\t2 0 1\tfile2.txt\t{date_str}\t{time_str}\taaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            f"201\t2 0 1\tfile2.txt\t{date_str}\t{time_str}\tbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",

            # Encrypted files access log
            f"300\t2 0 1\tfile3.encrypt\t{date_str}\t{time_str}\tcccccccccccccccccccccccccccccccc",
            f"301\t2 0 1\toriginal.txt.encrypt\t{date_str}\t{time_str}\tdddddddddddddddddddddddddddddddd"
        ]
        with open(self.logpath, "w") as f:
            for line in self.sample_lines:
                f.write(line + "\n")
        # Temporarily replace the default log path
        self.original_logfile = ac_system.LOGFILE
        ac_system.LOGFILE = self.logpath

    def tearDown(self):
        # Restore stdout
        sys.stdout = self.old_stdout

        # Clean up test log file
        try:
            os.remove(self.logpath)
        except OSError:
            pass

        # Restore original log path
        ac_system.LOGFILE = self.original_logfile

        # Clear any test files that might have been created
        test_files = ['file1.txt', 'file2.txt', 'file3.encrypt', 'original.txt.encrypt']
        for f in test_files:
            try:
                os.remove(f)
            except OSError:
                pass

    @patch('sys.argv', ['ac_system.py', 'monitor', '-m'])
    def test_cli_malicious_users(self):
        """Test -m flag to list malicious users"""
        ac_system.main()
        output = self.stdout.getvalue()
        self.assertIn("Malicious users:", output)
        # User 100 has multiple denied actions
        self.assertIn("uid:", output)  # Check for the label
        self.assertIn("100", output)  # Check for the user ID

    @patch('sys.argv', ['ac_system.py', 'monitor', '-i', 'file2.txt'])
    def test_cli_file_modifications(self):
        """Test -i flag to list file modifications"""
        ac_system.main()
        output = self.stdout.getvalue()
        # File has modifications by users 200 and 201
        self.assertIn("file2.txt", output)  # Check for the filename
        # Only the second entry changes the fingerprint and is reported
        self.assertIn("201", output)  # Modifier UID

    @patch('sys.argv', ['ac_system.py', 'monitor', '-v', '20'])
    def test_cli_files_created(self):
        """Test -v flag to show files created"""
        ac_system.main()
        output = self.stdout.getvalue()
        self.assertIn("Info:", output)
        self.assertIn("files were created", output)

    @patch('sys.argv', ['ac_system.py', 'monitor', '-e'])
    def test_cli_encrypted_files(self):
        """Test -e flag to list encrypted files"""
        ac_system.main()
        output = self.stdout.getvalue()
        self.assertIn("Encrypted:", output)
        # Should find both encrypted files (print_encrypted returns base names
        # without the .encrypt suffix)
        self.assertIn("file3", output)
        self.assertIn("original.txt", output)

    @patch('sys.argv', ['ac_system.py', 'run_test'])
    def test_cli_run_test(self):
        """Test run_test command"""
        ac_system.main()
        output = self.stdout.getvalue()
        self.assertIn("Test sequence completed", output)

    @patch('sys.argv', ['ac_system.py'])
    def test_cli_no_args(self):
        """Test running without arguments shows help"""
        ac_system.main()
        output = self.stdout.getvalue()
        self.assertIn("usage:", output.lower())

    def test_read_complex_log(self):
        """Test reading a complex log with various entry types"""
        # Add some complex entries
        additional_lines = [
            # Malformed lines
            "bad line",
            "100\tbad action\tfile\tdate\ttime\thash",
            # Valid but complex
            f"102\t0 0 1\tfile with spaces.txt\t{datetime.now().year}-{datetime.now().month}-{datetime.now().day}\t12:00:00\td41d8cd98f00b204e9800998ecf8427e",
            f"103\t2 0 1\t../path/traversal.txt\t{datetime.now().year}-{datetime.now().month}-{datetime.now().day}\t12:00:00\td41d8cd98f00b204e9800998ecf8427e"
        ]
        with open(self.logpath, "a") as f:
            for line in additional_lines:
                f.write(line + "\n")

        entries = ac_system.read_log_file(self.logpath)
        self.assertTrue(any(e.uid == 102 for e in entries))
        self.assertTrue(any(e.uid == 103 for e in entries))
        # Bad lines should be handled gracefully
        self.assertTrue(all(isinstance(e.uid, int) for e in entries))

if __name__ == '__main__':
    unittest.main()
