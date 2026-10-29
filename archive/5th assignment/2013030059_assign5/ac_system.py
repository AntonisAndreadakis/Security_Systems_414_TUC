#!/usr/bin/env python3
"""
ac_system.py

A single-file, easy-to-debug Python reimplementation of the access-control
logging system from the C project. It provides three main roles in one script:

- logger: functions that wrap file operations and append structured entries to
  `file_logging.log` (MD5 fingerprint included).
- monitor: functions to parse `file_logging.log` and implement commands similar
  to `acmonitor` (-m, -i, -v, -e).
- test: a test runner that exercises the logger behaviour similar to
  `test_aclog.c`.

Run with `-h` to see commands.

This is intentionally straightforward and written to make stepping through the
logic in a debugger easy.

"""

import argparse
import hashlib
import os
from datetime import datetime, timedelta
from typing import Optional, List, Tuple

LOGFILE = "file_logging.log"

# Action types same as the original project
CREATE = 0
OPEN = 1
WRITE = 2


class LogEntry:
    def __init__(self, uid: int, action_type: int, action_flag: int, file_stat: int,
                 path: str, date: str, tm: str, fingerprint: str):
        self.uid = uid
        self.action_type = action_type
        self.action_flag = action_flag
        self.file_stat = file_stat
        self.path = path
        self.date = date
        self.time = tm
        self.fingerprint = fingerprint

    def __repr__(self):
        return (f"LogEntry(uid={self.uid}, action_type={self.action_type}, "
                f"action_flag={self.action_flag}, file_stat={self.file_stat}, "
                f"path={self.path}, date={self.date}, time={self.time}, "
                f"fingerprint={self.fingerprint})")


def now_tuple() -> Tuple[str, str]:
    """Return date and time strings in the same format used by the C logger.

    date: YYYY-M-D
    time: H:M:S
    """
    t = datetime.now()
    return f"{t.year}-{t.month}-{t.day}", f"{t.hour}:{t.minute}:{t.second}"


def compute_md5(path: Optional[str], additional_data: Optional[bytes] = None) -> Optional[bytes]:
    """Compute MD5 of the file contents and optional additional_data appended.
    Returns None if the file can't be opened.
    """
    md5 = hashlib.md5()
    if path and os.path.exists(path):
        try:
            with open(path, "rb") as f:
                while True:
                    chunk = f.read(4096)
                    if not chunk:
                        break
                    md5.update(chunk)
        except Exception:
            return None
    if additional_data:
        md5.update(additional_data)
    return md5.digest()


def print_hex(b: bytes) -> str:
    return b.hex()


def log_print(uid: int, action_type: int, action_flag: int, file_stat: int,
              path: str, date: str, tm: str, fingerprint: bytes):
    """Append a line to the logfile in the project's format.

    Format similar to logger.c: uid\t<action> <flag> <fileStat>\tpath\tDATE\tTIME\tHEXFINGERPRINT\n
    """
    hexfp = print_hex(fingerprint) if fingerprint else "".ljust(32, "0")
    line = f"{uid}\t{action_type} {action_flag} {file_stat}\t{path}\t{date}\t{tm}\t{hexfp}\n"
    with open(LOGFILE, "a", encoding="utf-8") as lf:
        lf.write(line)


# ------------------ Logger style helper functions ------------------


def logger_open(path: str, mode: str, uid: Optional[int] = None):
    """Open a file and log the access. Returns a file object.
    This is not a global LD_PRELOAD interception; it's a Python wrapper you can
    step through in a debugger.
    """
    uid = uid if uid is not None else (os.getuid() if hasattr(os, "getuid") else 0)
    existed = os.path.exists(path)
    action_type = determine_action_from_mode(mode, existed)
    denied = 0
    try:
        f = open(path, mode)
    except Exception:
        f = None
        denied = 1
    # fingerprint current file (before any write)
    fp = compute_md5(path)
    date, tm = now_tuple()
    file_stat = 1 if existed else 0
    log_print(uid, action_type, denied, file_stat, path, date, tm, fp or b"\x00" * 16)
    return f


def determine_action_from_mode(mode: str, existed: bool) -> int:
    if mode in ("a", "a+"):
        return CREATE if not existed else OPEN
    if mode in ("r", "r+"):
        return OPEN
    if mode in ("w", "w+"):
        return CREATE
    # fallback
    return OPEN


def logger_write(f, data: bytes, uid: Optional[int] = None):
    """Write bytes to the file object and log the write. Returns number of bytes written.
    The function computes the fingerprint after including the new data.
    """
    uid = uid if uid is not None else (os.getuid() if hasattr(os, "getuid") else 0)
    if f is None:
        raise ValueError("file object is None")
    # get path via file object
    path = None
    try:
        path = f.name
    except Exception:
        path = "unknown"
    # do the write
    written = f.write(data.decode() if isinstance(data, bytes) else data)
    f.flush()
    # compute fingerprint with new data appended
    new_fp = compute_md5(path, additional_data=(data if isinstance(data, bytes) else data.encode()))
    date, tm = now_tuple()
    file_stat = 1 if os.path.exists(path) else 0
    denied = 0
    log_print(uid, WRITE, denied, file_stat, path, date, tm, new_fp or b"\x00" * 16)
    return written


# ------------------ Monitor (acmonitor) functionality ------------------


def read_log_file(logpath: Optional[str] = None) -> List[LogEntry]:
    # Use the current global LOGFILE if no explicit path is provided. The
    # default must not be bound at function-definition time because tests
    # mutate `ac_system.LOGFILE` at runtime.
    if logpath is None:
        logpath = LOGFILE
    entries: List[LogEntry] = []
    if not os.path.exists(logpath):
        return entries
    with open(logpath, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            # Expect: uid\t<action> <flag> <fileStat>\tpath\tDATE\tTIME\tHEXFP
            parts = line.split("\t")
            # flexible parsing: map expected positions but tolerate missing parts
            uid_s = parts[0] if len(parts) > 0 else "0"
            action_group = parts[1].strip() if len(parts) > 1 else "0 0 0"
            path = parts[2] if len(parts) > 2 else ""
            date = parts[3] if len(parts) > 3 else ""
            tm = parts[4] if len(parts) > 4 else ""
            # fingerprint may be the remainder joined
            hexfp = ""
            if len(parts) > 5:
                hexfp = "".join(p.strip() for p in parts[5:])
            # parse uid defensively
            try:
                uid = int(uid_s)
            except (ValueError, TypeError):
                uid = 0
            # parse action_group into three ints defensively
            try:
                a_tokens = action_group.split()
                action_type = int(a_tokens[0]) if len(a_tokens) > 0 else 0
                action_flag = int(a_tokens[1]) if len(a_tokens) > 1 else 0
                file_stat = int(a_tokens[2]) if len(a_tokens) > 2 else 0
            except Exception:
                action_type = 0
                action_flag = 0
                file_stat = 0
            fingerprint = hexfp
            entries.append(LogEntry(uid, action_type, action_flag, file_stat, path, date, tm, fingerprint))
    return entries


def list_malicious(entries: List[LogEntry], threshold: int = 1):
    counts = {}
    for e in entries:
        if e.action_flag == 1:
            counts[e.uid] = counts.get(e.uid, 0) + 1
    malicious = [uid for uid, c in counts.items() if c >= threshold]
    return malicious


def list_modifications(entries: List[LogEntry], target_file: str):
    # track last known fingerprint
    last_fp = None
    modificants = {}
    for e in entries:
        if e.path == target_file:
            if last_fp is None:
                # first appearance of file
                last_fp = e.fingerprint
            elif e.fingerprint != last_fp:
                # fingerprint changed from last seen
                modificants[e.uid] = modificants.get(e.uid, 0) + 1
                last_fp = e.fingerprint
    return modificants


def files_created_in_range(entries: List[LogEntry], minutes: int) -> int:
    now = datetime.now()
    start = now - timedelta(minutes=minutes)
    count = 0
    for e in entries:
        # Robust parsing: the log may have non-zero-padded month/day/hours
        try:
            # try integer parsing first (fast and flexible)
            ymd = e.date.strip().split("-")
            hms = e.time.strip().split(":")
            if len(ymd) >= 3 and len(hms) >= 3:
                y, m, d = int(ymd[0]), int(ymd[1]), int(ymd[2])
                hh, mm, ss = int(hms[0]), int(hms[1]), int(hms[2])
                dt = datetime(y, m, d, hh, mm, ss)
            else:
                # fallback to strptime with a forgiving format
                dt = datetime.strptime(e.date + " " + e.time, "%Y-%m-%d %H:%M:%S")
        except Exception:
            # give up on this entry
            continue
        if start <= dt <= now and e.action_type == CREATE:
            count += 1
    return count


def print_encrypted(entries: List[LogEntry]):
    found = set()
    for e in entries:
        if e.path.endswith(".encrypt"):
            # Strip .encrypt from the end to get original name
            base = e.path[:-len(".encrypt")]
            found.add(base)
    return found


# ------------------ Test runner (mimics test_aclog.c) ------------------


def run_test_sequence():
    # Create 10 files file_0..file_9 and write their names into them
    filenames = [f"file_{i}" for i in range(10)]
    for name in filenames:
        f = logger_open(name, "w+")
        if f:
            try:
                data = (name + "\n").encode()
                logger_write(f, data)
            finally:
                f.close()

    # attempt to open some non-existing tests to get denied or creates
    for t in ("test1.txt", "test2.txt", "test3.txt"):
        f = logger_open(t, "r")
        if f:
            f.close()

    # test writes and opens
    f = logger_open("test1.txt", "w")
    if f:
        logger_write(f, b"something to write\n")
        f.close()

    f = logger_open("test1.txt", "w+")
    if f:
        logger_write(f, b"something else\n")
        f.close()

    # open readonly
    try:
        fd = os.open("test1.txt", os.O_RDONLY)
        os.close(fd)
        # Log the open via our logger_open wrapper for consistency. Close
        # the returned file object to avoid ResourceWarning about unclosed
        # files when running under tests.
        f = logger_open("test1.txt", "r")
        if f:
            f.close()
    except Exception:
        pass

    # append mode
    f = logger_open("test.txt", "a")
    if f:
        f.close()

    # create some files, write into them
    small_names = [f"file{i}" for i in range(10)]
    for name in small_names:
        f = logger_open(name, "w")
        if f:
            logger_write(f, b"small content\n")
            f.close()

    # final checks opening
    for t in ("test.txt", "test1.txt", "test2.txt"):
        f = logger_open(t, "r")
        if f:
            f.close()

    print("Test sequence completed. Check file_logging.log for entries.")


# ------------------ CLI ------------------


def main():
    parser = argparse.ArgumentParser(description="Access-control logger+monitor in Python")
    sub = parser.add_subparsers(dest="cmd")

    sub.add_parser("run_test", help="Run the test sequence to generate log entries")

    mon_parser = sub.add_parser("monitor", help="Run monitor actions on file_logging.log")
    mon_parser.add_argument("-m", action="store_true", help="List malicious users (action_flag==1)")
    mon_parser.add_argument("-i", metavar="FILENAME", help="Show users who modified given file")
    mon_parser.add_argument("-v", metavar="MINUTES", type=int, help="Files created in last MINUTES")
    mon_parser.add_argument("-e", action="store_true", help="Print encrypted files (.encrypt)")

    args = parser.parse_args()

    if args.cmd == "run_test":
        run_test_sequence()
        return

    if args.cmd == "monitor":
        entries = read_log_file()
        if args.m:
            mal = list_malicious(entries)
            if not mal:
                print("No malicious users.")
            else:
                print("Malicious users:")
                for u in mal:
                    print(f"uid:\t{u}")
        if args.i:
            mods = list_modifications(entries, args.i)
            if not mods:
                print("No modifications found.")
            else:
                print(f"Users who modified \"{args.i}\":")
                for uid, count in mods.items():
                    print(f"{uid}\t{count}")
        if args.v is not None:
            c = files_created_in_range(entries, args.v)
            print(f"Info: {c} files were created in the last {args.v} minutes.")
        if args.e:
            enc = print_encrypted(entries)
            if not enc:
                print("Encrypted: 0")
            else:
                print(f"Encrypted: {len(enc)}")
                for fn in enc:
                    print(f"File:\t{fn}")
        return

    parser.print_help()


if __name__ == "__main__":
    main()
