import os
import tempfile
import unittest
from datetime import datetime, timedelta

import ac_system

class TestACSystem(unittest.TestCase):
    def setUp(self):
        # create a temporary logfile
        fd, self.logpath = tempfile.mkstemp(prefix="test_log_", suffix=".log")
        os.close(fd)

    def tearDown(self):
        try:
            os.remove(self.logpath)
        except OSError:
            pass

    def write_lines(self, lines):
        with open(self.logpath, "w", encoding="utf-8") as f:
            for l in lines:
                f.write(l + "\n")

    def test_read_log_and_parse(self):
        lines = [
            "100\t0 0 1\tfile_a\t2025-11-06\t12:00:00\td41d8cd98f00b204e9800998ecf8427e",
            "101\t2 0 1\tfile_a\t2025-11-06\t12:05:00\taaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ]
        self.write_lines(lines)
        entries = ac_system.read_log_file(self.logpath)
        self.assertEqual(len(entries), 2)
        self.assertEqual(entries[0].uid, 100)
        self.assertEqual(entries[1].action_type, 2)

    def test_list_modifications(self):
        lines = [
            "0\t0 0 1\tfoo\t2025-11-06\t10:00:00\t11111111111111111111111111111111",
            "0\t2 0 1\tfoo\t2025-11-06\t10:05:00\t22222222222222222222222222222222",
            "1\t2 0 1\tfoo\t2025-11-06\t10:10:00\t22222222222222222222222222222222",
        ]
        self.write_lines(lines)
        entries = ac_system.read_log_file(self.logpath)
        mods = ac_system.list_modifications(entries, "foo")
        # user 0 modified first, user 1 did not change fingerprint relative to new one
        self.assertIn(0, mods)
        self.assertEqual(mods[0], 1)

    def test_files_created_in_range(self):
        now = datetime.now()
        t1 = now - timedelta(minutes=5)
        t2 = now - timedelta(minutes=30)
        line1 = f"0\t0 0 1\tnewfile\t{t1.year}-{t1.month}-{t1.day}\t{t1.hour}:{t1.minute}:{t1.second}\td41d8cd98f00b204e9800998ecf8427e"
        line2 = f"0\t0 0 1\toldfile\t{t2.year}-{t2.month}-{t2.day}\t{t2.hour}:{t2.minute}:{t2.second}\td41d8cd98f00b204e9800998ecf8427e"
        self.write_lines([line1, line2])
        entries = ac_system.read_log_file(self.logpath)
        count = ac_system.files_created_in_range(entries, 20)
        self.assertEqual(count, 1)

if __name__ == '__main__':
    unittest.main()
