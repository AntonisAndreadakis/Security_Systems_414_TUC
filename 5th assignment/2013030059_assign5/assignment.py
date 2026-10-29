#!/usr/bin/env python3
"""Assignment 5: file-activity logger, time-window and encryption-event detector.

Use Logger.open() for operations to audit. This does not interpose C functions
or monitor unrelated processes. No administrator privileges are required.
"""
import argparse
from dataclasses import dataclass
from datetime import datetime, timedelta
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
import tempfile
import unittest

MAX_EVENT_BYTES = 64 * 1024
MAX_FIXTURE_BYTES = 1024 * 1024

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
    with Path(path).open('rb') as stream:
        while True:
            raw = stream.readline(MAX_EVENT_BYTES + 1)
            if not raw:
                break
            if len(raw) > MAX_EVENT_BYTES and not raw.endswith(b'\n'):
                while raw and not raw.endswith(b'\n'):
                    raw = stream.readline(MAX_EVENT_BYTES + 1)
                rejected += 1
                continue
            if not raw.strip():
                continue
            try:
                events.append(parse_event(raw.decode('utf-8')))
            except (UnicodeDecodeError, ValueError):
                rejected += 1
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
            self.logger.record(self.path,2,1)
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
        if action not in (0, 1, 2) or denied not in (0, 1):
            raise ValueError('Invalid event action or denied flag')
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
        create_attempt = 'x' in mode or (not existed and ('w' in mode or 'a' in mode))
        try: stream = path.open(mode,**kwargs)
        except OSError:
            self.record(path,0 if create_attempt else 1,1)
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
        if e.denied or e.digest == '-': continue
        if e.action == 2 and last is not None and last != e.digest:
            users[e.uid] = users.get(e.uid, 0) + 1
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

    def test_failed_access_and_record_validation(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory, log = Path(tmp), Path(tmp)/'log'
            logger = Logger(log,uid=7)
            with self.assertRaises(FileNotFoundError):
                logger.open(directory/'missing.txt','r')
            events,rejected = read_events(log)
            self.assertEqual(rejected,0)
            self.assertEqual((events[0].action,events[0].denied),(1,1))
            with self.assertRaises(ValueError): logger.record(directory/'x',9,0)

    def test_reader_rejects_invalid_utf8_and_oversized_records(self):
        with tempfile.TemporaryDirectory() as tmp:
            log=Path(tmp)/'log'
            valid=Event(4,'valid',datetime.now().replace(microsecond=0),1,0,'-')
            with log.open('wb') as stream:
                stream.write(b'x'*(MAX_EVENT_BYTES+1)+b'\n')
                stream.write(b'\xff\xfe\n')
                stream.write(valid.line().encode())
            events,rejected=read_events(log)
            self.assertEqual((events,rejected),([valid],2))

    def test_modifications_omits_zero_count_users(self):
        now=datetime.now().replace(microsecond=0)
        path=str(Path('target').resolve())
        events=[Event(1,path,now,1,0,'a'*32),
                Event(2,path,now,1,0,'a'*32),
                Event(1,path,now,2,0,'b'*32)]
        self.assertEqual(modifications(events,path),{1:1})


def recent_creations(events, now=None):
    """Distinct successfully created paths in the last twenty minutes."""
    now = now or datetime.now()
    return {e.path for e in events if e.action == 0 and not e.denied
            and now - timedelta(minutes=20) <= e.timestamp <= now}

def encrypted_events(events):
    """Ordered OPEN original -> CREATE original.encrypt, by the same UID."""
    opened, detected = set(), []
    for event in events:
        if event.denied: continue
        if event.action == 1:
            opened.add((event.uid, event.path))
        elif event.action == 0 and event.path.endswith('.encrypt'):
            original = event.path[:-len('.encrypt')]
            key = (event.uid, original)
            if key in opened:
                detected.append((event.uid, original, event.path))
                opened.remove(key)
    return detected

def simulate(directory, count):
    """Generate harmless fixture events and labelled marker files, never encrypt/delete."""
    if not 1 <= count <= 10000: raise ValueError('Count must be between 1 and 10000')
    directory = Path(directory)
    directory.mkdir()  # Refuses existing user directories.
    logger = Logger(directory/'file_logging.log')
    for i in range(count):
        original = directory/f'fixture_{i:05d}.txt'
        with logger.open(original,'x',encoding='utf-8') as out:
            out.write(f'Generated fixture {i}\n')
        with logger.open(original,'rb') as stream:
            content = stream.read()
        with logger.open(str(original)+'.encrypt','xb') as out:
            out.write(b'SIMULATION ONLY - not encrypted\n'+content)
    print('Simulation complete; originals retained:', directory)
    return logger.log_path

def lab(directory, count):
    """APPROVAL REQUIRED: encrypt/delete only newly generated fixtures.

    This is not called by self-tests. Existing directories are refused. The
    retained AES-GCM key and manifest permit recovery of the generated files.
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    if not 1 <= count <= 10000: raise ValueError('Count must be between 1 and 10000')
    directory = Path(directory)
    directory.mkdir(mode=0o700)
    key = AESGCM.generate_key(bit_length=256)
    key_path = directory/'lab.key'
    descriptor = os.open(key_path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(descriptor,'wb') as out: out.write(key)
    cipher = AESGCM(key)
    names = [f'fixture_{i:05d}.txt' for i in range(count)]
    with (directory/'lab.json').open('x',encoding='utf-8') as out:
        json.dump({'format':'assignment5-aesgcm-v1','files':names},out)
    logger = Logger(directory/'file_logging.log')
    for name in names:
        original = directory/name
        with logger.open(original,'xb') as out: out.write(f'Generated lab fixture {name}\n'.encode())
        with logger.open(original,'rb') as stream: data=stream.read()
        nonce=secrets.token_bytes(12)
        encoded=nonce+cipher.encrypt(nonce,data,name.encode())
        encrypted=Path(str(original)+'.encrypt')
        with logger.open(encrypted,'xb') as out: out.write(encoded)
        # Confirm the just-written file is recoverable before removing this fixture.
        saved=encrypted.read_bytes()
        if cipher.decrypt(saved[:12],saved[12:],name.encode())!=data:
            raise ValueError('Recovery validation failed; original retained')
        original.unlink()
    print('Generated-fixture lab complete. Keep lab.key; recover with --recover:',directory)

def recovery_plan(directory):
    """Read-only validation of every recovery input before any output is written.

    This checks structure and collisions, not ciphertext authentication. It can
    be tested without running the separately approved recovery workflow.
    """
    directory=Path(directory)
    if directory.is_symlink(): raise ValueError('Lab directory cannot be a symlink')
    manifest_path,key_path=directory/'lab.json',directory/'lab.key'
    if manifest_path.is_symlink() or key_path.is_symlink(): raise ValueError('Symlinked lab metadata refused')
    for path,limit in ((manifest_path,512*1024),(key_path,32)):
        metadata=path.stat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size>limit:
            raise ValueError('Invalid lab metadata file or size')
    manifest=json.loads(manifest_path.read_text(encoding='utf-8'))
    if not isinstance(manifest,dict) or manifest.get('format')!='assignment5-aesgcm-v1': raise ValueError('Unknown lab format')
    names=manifest.get('files')
    if not isinstance(names,list) or not 1 <= len(names) <= 10000:
        raise ValueError('Invalid manifest')
    if any(not isinstance(name,str) or not re.fullmatch(r'fixture_[0-9]{5}\.txt',name) for name in names):
        raise ValueError('Invalid fixture names')
    if len(set(names))!=len(names): raise ValueError('Duplicate fixture names')
    key=key_path.read_bytes()
    if len(key)!=32: raise ValueError('Lab key must be exactly 32 bytes')
    for name in names:
        original=directory/name; encrypted=Path(str(original)+'.encrypt')
        if original.exists() or original.is_symlink() or encrypted.is_symlink():
            raise ValueError('Existing output or symlink refused')
        metadata=encrypted.stat()
        if not stat.S_ISREG(metadata.st_mode) or not 28 <= metadata.st_size <= MAX_FIXTURE_BYTES:
            raise ValueError('Invalid encrypted fixture file or size')
    return directory,names,key

def _read_encrypted_fixture(path):
    """Read one bounded regular file without following symlinks where supported."""
    flags=os.O_RDONLY|getattr(os,'O_NOFOLLOW',0)
    descriptor=os.open(path,flags)
    try:
        metadata=os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or not 28 <= metadata.st_size <= MAX_FIXTURE_BYTES:
            raise ValueError('Invalid encrypted fixture file or size')
        chunks=[]; remaining=MAX_FIXTURE_BYTES+1
        while remaining:
            chunk=os.read(descriptor,min(65536,remaining))
            if not chunk: break
            chunks.append(chunk); remaining-=len(chunk)
        encoded=b''.join(chunks)
        if not 28 <= len(encoded) <= MAX_FIXTURE_BYTES:
            raise ValueError('Invalid fixture size')
        return encoded
    finally:
        os.close(descriptor)

def recover(directory):
    """APPROVAL REQUIRED: recover only manifest-listed generated fixtures."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.exceptions import InvalidTag
    directory,names,key=recovery_plan(directory)
    cipher=AESGCM(key)
    logger=Logger(directory/'file_logging.log')
    # Authenticate every input before creating any plaintext output. This avoids
    # a corrupt later fixture leaving a partially recovered directory.
    for name in names:
        encoded=_read_encrypted_fixture(directory/(name+'.encrypt'))
        try: cipher.decrypt(encoded[:12],encoded[12:],name.encode())
        except InvalidTag as error: raise ValueError('Fixture authentication failed; no plaintext written') from error
    created=[]
    try:
        for name in names:
            original=directory/name; encrypted=directory/(name+'.encrypt')
            if original.exists() or original.is_symlink() or encrypted.is_symlink():
                raise ValueError('Existing output or symlink refused')
            encoded=_read_encrypted_fixture(encrypted)
            try: data=cipher.decrypt(encoded[:12],encoded[12:],name.encode())
            except InvalidTag as error: raise ValueError('Fixture changed during recovery') from error
            out=logger.open(original,'xb')
            created.append(original)
            with out: out.write(data)
    except Exception:
        for path in created:
            try: path.unlink()
            except FileNotFoundError: pass
        raise
    print('Recovered generated fixtures; encrypted copies retained:',directory)

class DetectionTests(unittest.TestCase):
    def test_recovery_preflight_is_read_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory=Path(tmp)
            names=['fixture_00000.txt','fixture_00001.txt']
            (directory/'lab.json').write_text(json.dumps({'format':'assignment5-aesgcm-v1','files':names}))
            (directory/'lab.key').write_bytes(bytes(32))
            # Arbitrary structural markers: no encryption, decryption, or deletion.
            for name in names: (directory/(name+'.encrypt')).write_bytes(bytes(28))
            snapshot={p.name:p.read_bytes() for p in directory.iterdir()}
            self.assertEqual(recovery_plan(directory),(directory,names,bytes(32)))
            self.assertEqual(snapshot,{p.name:p.read_bytes() for p in directory.iterdir()})
            (directory/names[1]).write_text('existing user output')
            with self.assertRaises(ValueError): recovery_plan(directory)
            self.assertFalse((directory/names[0]).exists())
            self.assertEqual((directory/names[1]).read_text(),'existing user output')

    def test_recovery_preflight_rejects_bad_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory=Path(tmp)
            (directory/'lab.key').write_bytes(bytes(32))
            invalid=[[],['../outside'],['fixture_00000.txt']*2,[['nested']],['fixture_00000.txt']]
            for names in invalid:
                (directory/'lab.json').write_text(json.dumps({'format':'assignment5-aesgcm-v1','files':names}))
                with self.assertRaises((ValueError,FileNotFoundError)): recovery_plan(directory)

    def test_recovery_authenticates_all_inputs_before_writing(self):
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        except ImportError:
            self.skipTest('cryptography is not installed')
        with tempfile.TemporaryDirectory() as tmp:
            directory=Path(tmp); key=AESGCM.generate_key(bit_length=256); cipher=AESGCM(key)
            names=['fixture_00000.txt','fixture_00001.txt']
            (directory/'lab.json').write_text(json.dumps({'format':'assignment5-aesgcm-v1','files':names}))
            (directory/'lab.key').write_bytes(key)
            for name in names:
                nonce=secrets.token_bytes(12)
                (directory/(name+'.encrypt')).write_bytes(nonce+cipher.encrypt(nonce,name.encode(),name.encode()))
            damaged=directory/(names[1]+'.encrypt')
            data=bytearray(damaged.read_bytes()); data[-1]^=1; damaged.write_bytes(data)
            with self.assertRaisesRegex(ValueError,'authentication failed'):
                recover(directory)
            self.assertFalse(any((directory/name).exists() for name in names))

    def test_recovery_restores_authenticated_generated_fixtures(self):
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        except ImportError:
            self.skipTest('cryptography is not installed')
        with tempfile.TemporaryDirectory() as tmp:
            directory=Path(tmp); key=AESGCM.generate_key(bit_length=256); cipher=AESGCM(key)
            names=['fixture_00000.txt','fixture_00001.txt']
            expected={name:('generated '+name).encode() for name in names}
            (directory/'lab.json').write_text(json.dumps({'format':'assignment5-aesgcm-v1','files':names}))
            (directory/'lab.key').write_bytes(key)
            for name,data in expected.items():
                nonce=secrets.token_bytes(12)
                (directory/(name+'.encrypt')).write_bytes(nonce+cipher.encrypt(nonce,data,name.encode()))
            recover(directory)
            self.assertEqual({name:(directory/name).read_bytes() for name in names},expected)
            self.assertTrue(all((directory/(name+'.encrypt')).exists() for name in names))

    def test_lab_requires_approval_before_writing(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory=Path(tmp)/'must-not-exist'
            with self.assertRaises(SystemExit) as result:
                main(['--lab',str(directory)])
            self.assertEqual(result.exception.code,1)
            self.assertFalse(directory.exists())
    def test_time_window_threshold_and_distinct_paths(self):
        now = datetime(2026,1,2,0,10,0)
        def event(path, age, denied=0):
            return Event(10,path,now-timedelta(minutes=age),0,denied,'-')
        events = [event('new',1),event('new',2),event('boundary',20),
                  event('old',21),event('future',-1),event('denied',1,1)]
        self.assertEqual(recent_creations(events,now),{'new','boundary'})

    def test_order_uid_denial_and_suffix(self):
        now = datetime.now()
        def event(uid,path,action,denied=0): return Event(uid,path,now,action,denied,'-')
        events = [event(1,'orphan.encrypt',0), event(1,'a',1), event(2,'a.encrypt',0),
                  event(1,'a.encrypt',0), event(1,'b',1,1), event(1,'b.encrypt',0),
                  event(1,'c',1), event(1,'c.encrypt.bak',0), event(1,'a.encrypt',2)]
        self.assertEqual(encrypted_events(events),[(1,'a','a.encrypt')])

    def test_simulation_preserves_originals(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)/'simulation'
            path = simulate(directory,3)
            events,rejected = read_events(path)
            self.assertEqual(rejected,0)
            self.assertEqual(len(encrypted_events(events)),3)
            self.assertEqual(len(recent_creations(events)),6)
            for i in range(3):
                original = directory/f'fixture_{i:05d}.txt'
                self.assertEqual(original.read_text(),f'Generated fixture {i}\n')
                self.assertTrue(Path(str(original)+'.encrypt').read_bytes().startswith(b'SIMULATION ONLY'))
            with self.assertRaises(FileExistsError): simulate(directory,1)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument('--self-test',action='store_true')
    action.add_argument('--demo',type=Path,metavar='NEW_DIRECTORY')
    action.add_argument('-m',action='store_true'); action.add_argument('-i',metavar='PATH')
    action.add_argument('-v',type=int,metavar='MINIMUM_COUNT')
    action.add_argument('-e',action='store_true')
    action.add_argument('--simulate',type=Path,metavar='NEW_DIRECTORY')
    action.add_argument('--lab',type=Path,metavar='NEW_DIRECTORY')
    action.add_argument('--recover',type=Path,metavar='LAB_DIRECTORY')
    parser.add_argument('--approve-lab',action='store_true',help='use only after separate approval for the generated-fixture encryption/deletion lab')
    parser.add_argument('--count',type=int,default=10)
    parser.add_argument('--log',type=Path,default=Path('file_logging.log'))
    args = parser.parse_args(argv)
    if args.self_test:
        return 0 if unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite([unittest.defaultTestLoader.loadTestsFromTestCase(Tests), unittest.defaultTestLoader.loadTestsFromTestCase(DetectionTests)])).wasSuccessful() else 1
    try:
        if args.lab or args.recover:
            if not args.approve_lab: raise ValueError('Lab workflow needs separate approval and --approve-lab; nothing was changed')
            if args.lab: lab(args.lab,args.count)
            else: recover(args.recover)
            return 0
        if args.demo: demo(args.demo); return 0
        if args.simulate: simulate(args.simulate,args.count); return 0
        if args.v is not None and args.v < 1: raise ValueError('-v requires a positive minimum count')
        events,rejected = read_events(args.log)
        if rejected: print(f'Ignored {rejected} malformed log records',file=sys.stderr)
        if args.v is not None:
            count = len(recent_creations(events))
            print(f'Files created in last 20 minutes: {count}')
            print('Threshold reached: ' + ('yes' if count >= args.v else 'no'))
            return 0
        if args.e:
            print('UID\tORIGINAL\tENCRYPTED')
            for row in encrypted_events(events): print('\t'.join(map(str,row)))
            return 0
        table = malicious_users(events) if args.m else modifications(events,args.i)
        print('UID\tCOUNT')
        for uid,count in sorted(table.items()): print(f'{uid}\t{count}')
    except (OSError,ValueError,ImportError) as error: parser.exit(1,f'Error: {error}\n')
    return 0

if __name__ == '__main__': sys.exit(main())
