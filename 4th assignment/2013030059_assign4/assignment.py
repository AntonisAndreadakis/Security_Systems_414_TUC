#!/usr/bin/env python3
"""Assignment 4: Python file-operation logging and TSV log monitoring.

Use Logger.open() for operations to audit. This does not interpose C functions
or monitor unrelated processes. No administrator privileges are required.
"""
import argparse
from dataclasses import dataclass
from datetime import datetime, timedelta
import hashlib
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
import unittest

@dataclass(frozen=True)
class Event:
    uid: int
    path: str
    timestamp: datetime
    action: int
    denied: int
    digest: str

    def line(self):
        if any(c in self.path for c in '\t\r\n'):
            raise ValueError('Log paths cannot contain tabs or newlines')
        return f'{self.uid}\t{self.path}\t{self.timestamp:%Y-%m-%d}\t{self.timestamp:%H:%M:%S}\t{self.action}\t{self.denied}\t{self.digest}\n'

def parse_event(line):
    fields = line.rstrip('\r\n').split('\t')
    if len(fields) != 7: raise ValueError('Expected seven tab-separated fields')
    uid, path, date, clock, action, denied, digest = fields
    if not uid.isdecimal() or not path or action not in ('0','1','2') or denied not in ('0','1'):
        raise ValueError('Invalid event fields')
    if digest != '-' and not re.fullmatch('[0-9a-fA-F]{32}', digest): raise ValueError('Invalid MD5')
    return Event(int(uid), path, datetime.strptime(date+' '+clock,'%Y-%m-%d %H:%M:%S'),
                 int(action),int(denied),digest.lower())

def read_events(path):
    events, rejected = [], 0
    with Path(path).open(encoding='utf-8') as stream:
        for line in stream:
            if not line.strip(): continue
            try: events.append(parse_event(line))
            except ValueError: rejected += 1
    return events, rejected

def fingerprint(path):
    digest = hashlib.md5()
    try:
        with Path(path).open('rb') as stream:
            for block in iter(lambda:stream.read(65536), b''): digest.update(block)
    except OSError: return '-'
    return digest.hexdigest()

class LoggedFile:
    def __init__(self, stream, path, logger):
        self.stream, self.path, self.logger = stream, path, logger
    def write(self, data):
        try:
            result = self.stream.write(data)
            self.stream.flush()
        except (OSError, ValueError, TypeError) as error:
            self.logger.record(self.path,2,int(isinstance(error,PermissionError)))
            raise
        self.logger.record(self.path,2,0)
        return result
    def writelines(self, lines):
        for line in lines: self.write(line)
    def __getattr__(self, name): return getattr(self.stream,name)
    def __iter__(self): return iter(self.stream)
    def __enter__(self): return self
    def __exit__(self,*args): self.stream.close()

class Logger:
    def __init__(self, log_path='file_logging.log', uid=None):
        self.log_path = Path(log_path).resolve()
        self.uid = uid if uid is not None else (os.getuid() if hasattr(os,'getuid') else 0)
        if not isinstance(self.uid,int) or self.uid < 0: raise ValueError('UID must be nonnegative')
    def record(self,path,action,denied):
        path = str(Path(path).resolve())
        event = Event(self.uid,path,datetime.now().replace(microsecond=0),action,denied,fingerprint(path))
        data = event.line().encode('utf-8')
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os,'O_NOFOLLOW',0)
        descriptor = os.open(self.log_path, flags, 0o600)
        try:
            if not stat.S_ISREG(os.fstat(descriptor).st_mode): raise ValueError('Log must be a regular file')
            if hasattr(os,'fchmod'): os.fchmod(descriptor,0o600)
            # flock is advisory: all cooperating Python loggers share this lock.
            if os.name == 'posix':
                import fcntl
                fcntl.flock(descriptor, fcntl.LOCK_EX)
            remaining = memoryview(data)
            while remaining:
                written = os.write(descriptor,remaining)
                if not written: raise OSError('Short log write')
                remaining = remaining[written:]
        finally: os.close(descriptor)
    def open(self,path,mode='r',**kwargs):
        path = Path(path).resolve()
        if path == self.log_path: raise ValueError('Cannot audit the log file itself')
        if any(c in str(path) for c in '\t\r\n'): raise ValueError('Unsupported log path')
        existed = path.exists()
        try: stream = path.open(mode,**kwargs)
        except OSError as error:
            self.record(path,1,int(isinstance(error,PermissionError)))
            raise
        try: self.record(path,1 if existed else 0,0)
        except Exception:
            stream.close(); raise
        return LoggedFile(stream,path,self)

def malicious_users(events, threshold=8):
    if threshold < 1: raise ValueError('Threshold must be positive')
    denied = {}
    for e in events:
        if e.denied: denied.setdefault(e.uid,set()).add(e.path)
    return {uid:len(paths) for uid,paths in denied.items() if len(paths) >= threshold}

def modifications(events,path):
    target = str(Path(path).resolve())
    last, users = None, {}
    for e in events:
        if str(Path(e.path).resolve()) != target: continue
        users.setdefault(e.uid,0)
        if e.denied or e.digest == '-': continue
        if e.action == 2 and last is not None and last != e.digest: users[e.uid] += 1
        last = e.digest
    return users

def demo(directory):
    directory = Path(directory)
    directory.mkdir()  # Refuse an existing directory; never reuse user fixtures.
    logger = Logger(directory/'file_logging.log')
    path = directory/'example.bin'
    with logger.open(path,'wb') as stream:
        stream.write(b'\0first\xff'); stream.write(b'\0second\xfe')
    with logger.open(path,'rb') as stream: print('Read',len(stream.read()),'bytes')
    print('Log:',logger.log_path)

class Tests(unittest.TestCase):
    def test_logger_binary_and_modifications(self):
        with tempfile.TemporaryDirectory() as tmp:
            path, log = Path(tmp)/'space file.bin', Path(tmp)/'log'
            logger = Logger(log,uid=42)
            with logger.open(path,'wb') as stream:
                stream.write(b'\0\xff'); stream.write(b'\x80')
            with logger.open(path,'rb') as stream: self.assertEqual(stream.read(),b'\0\xff\x80')
            events,rejected = read_events(log)
            self.assertEqual(rejected,0)
            self.assertEqual([e.action for e in events],[0,2,2,1])
            self.assertEqual(events[-1].digest,hashlib.md5(path.read_bytes()).hexdigest())
            self.assertEqual(modifications(events,path),{42:2})
            if os.name == 'posix': self.assertEqual(stat.S_IMODE(log.stat().st_mode),0o600)

    def test_permission_denial(self):
        if os.name != 'posix': self.skipTest('POSIX permission semantics')
        self.assertNotEqual(os.getuid(),0,'Run tests as an ordinary user')
        with tempfile.TemporaryDirectory() as tmp:
            path, log = Path(tmp)/'denied',Path(tmp)/'log'
            path.write_text('fixture'); path.chmod(0)
            try:
                with self.assertRaises(PermissionError): Logger(log).open(path)
            finally: path.chmod(0o600)
            events,_ = read_events(log)
            self.assertEqual(events[0].denied,1)

    def test_malformed_and_threshold(self):
        now = datetime.now().replace(microsecond=0)
        events = [Event(42,f'/tmp/{i}',now,1,1,'-') for i in range(8)]
        self.assertEqual(malicious_users(events*2),{42:8})
        self.assertEqual(malicious_users(events[:7]),{})
        self.assertEqual(parse_event(events[0].line()),events[0])
        for line in ('bad','-1\tx\t2026-01-01\t00:00:00\t1\t0\t-',
                     '0\tx\t2026-99-01\t00:00:00\t1\t0\t-'):
            with self.assertRaises(ValueError): parse_event(line)

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument('--self-test',action='store_true')
    action.add_argument('--demo',type=Path,metavar='NEW_DIRECTORY')
    action.add_argument('-m',action='store_true'); action.add_argument('-i',metavar='PATH')
    parser.add_argument('--log',type=Path,default=Path('file_logging.log'))
    args = parser.parse_args(argv)
    if args.self_test:
        return 0 if unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Tests)).wasSuccessful() else 1
    try:
        if args.demo: demo(args.demo); return 0
        events,rejected = read_events(args.log)
        if rejected: print(f'Ignored {rejected} malformed log records',file=sys.stderr)
        table = malicious_users(events) if args.m else modifications(events,args.i)
        print('UID\tCOUNT')
        for uid,count in sorted(table.items()): print(f'{uid}\t{count}')
    except (OSError,ValueError) as error: parser.exit(1,f'Error: {error}\n')
    return 0

if __name__ == '__main__': sys.exit(main())
