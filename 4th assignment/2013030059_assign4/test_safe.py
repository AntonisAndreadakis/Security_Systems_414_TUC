"""Exercise only temporary owned files; never preload a system program."""
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile

base = Path(__file__).resolve().parent
assert os.geteuid() != 0, 'Permission-denial tests require an unprivileged user'
with tempfile.TemporaryDirectory(prefix='aclog-') as directory:
    work = Path(directory)
    log = work / 'events.tsv'
    env = dict(os.environ, ACLOG_PATH=str(log))
    subprocess.run([str(base / 'test_aclog')], cwd=work,
                   env=dict(env, LD_PRELOAD=str(base / 'logger.so')), check=True, timeout=15)
    def report(*args):
        return subprocess.run([str(base / 'acmonitor'), *args], cwd=work,
                              env=env, capture_output=True, text=True, check=True, timeout=10).stdout
    assert f'{os.getuid()}\t8\n' in report('-m')
    modified = work / 'aclog-test/modified.txt'
    assert f'{os.getuid()}\t2\n' in report('-i', str(modified))
    rows = [line.split('\t') for line in log.read_text().splitlines()]
    assert rows and all(len(row) == 7 for row in rows)
    assert (log.stat().st_mode & 0o777) == 0o600
    digest = hashlib.md5(modified.read_bytes()).hexdigest()
    writes = [r for r in rows if r[1] == str(modified) and r[4] == '2']
    assert writes[-1][6] == digest
    with log.open('a') as out:
        out.write('malformed record\n')
    assert f'{os.getuid()}\t8\n' in report('-m')
    assert subprocess.run([str(base / 'acmonitor'), '-h'], capture_output=True).returncode == 0
    assert subprocess.run([str(base / 'acmonitor')], capture_output=True).returncode != 0
print('PASS: denied files, modifications, digest, log permissions, malformed row, CLI')
