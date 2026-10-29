import os
import tempfile
import ac_system


def test_read_log_uses_global_logfile():
    # create a temporary logfile and write a simple entry
    fd, path = tempfile.mkstemp(prefix="test_readlog_", suffix=".log")
    os.close(fd)
    try:
        # write one line matching expected format
        with open(path, "w", encoding="utf-8") as f:
            f.write("42\t1 0 1\tmyfile.txt\t2025-11-06\t12:00:00\t" + "a"*32 + "\n")

        # point ac_system.LOGFILE to the temp file and call with no args
        old = ac_system.LOGFILE
        ac_system.LOGFILE = path
        entries = ac_system.read_log_file()
        assert any(e.uid == 42 and e.path == "myfile.txt" for e in entries)
    finally:
        # cleanup and restore
        ac_system.LOGFILE = old
        try:
            os.remove(path)
        except OSError:
            pass
