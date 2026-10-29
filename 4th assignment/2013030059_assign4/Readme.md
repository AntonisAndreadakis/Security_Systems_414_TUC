# Assignment 4 - File access logging

Andreadakis Antonios - 2013030059

## Python version (current entry point)

`assignment.py` needs Python 3.11+ and the standard library. The public
`Logger.open()` wrapper audits creation, opening, binary/text writes, and
permission denials. It writes the same seven-field TSV schema as the C logger.
POSIX log appends use an advisory lock and mode 0600.

```sh
python assignment.py --self-test
python assignment.py --demo NEW_DIRECTORY
python assignment.py --log NEW_DIRECTORY/file_logging.log -i NEW_DIRECTORY/example.bin
python assignment.py --log NEW_DIRECTORY/file_logging.log -m
```

The demo refuses an existing directory. Three tests passed for binary hashes
and modification counts, permission denial, strict parsing, and the
eight-distinct-denied-files threshold.

This is an explicit Python API: it does not intercept unmodified external
programs, os.write, or C stdio. Callers must perform audited writes through the
wrapper. Linux permission/locking tests are authoritative; Windows ACL behavior
has not been verified.

```powershell
powershell -NoProfile -File sandbox/run.ps1 -Assignment 4 -Python
```

## Earlier C/shell validation status

The revised C implementation compiled and passed its assertions in the
unprivileged Docker sandbox.

## Updates and components

- `logger.c`: intercepts `fopen` and `fwrite`, distinguishes creation/open/write,
  records denied actions, resolves successful paths, and hashes file contents.
- `acmonitor.c`: parses the log, reports users denied access to more than seven
  distinct files, and counts per-user fingerprint changes on writes.
- `test_aclog.c` and `test_safe.py`: generate and check temporary fixtures.
- Makefile: corrected shared-library target and warning-clean build.

Original source is retained in disabled sections for comparison where present.

## Build and safe tests

Requires Linux, a C11 compiler, Make, OpenSSL development files, and Python 3.
Run as an ordinary user; permission-denial tests require a non-root UID.

```sh
make
make check
./acmonitor -h
```

Preferred test from the testing workspace:

```powershell
powershell -NoProfile -File sandbox/run.ps1 -Assignment 4
```

`make check` uses temporary fixtures. Legacy `make run`/`make clear` targets
write or truncate local files and should only be used in disposable copies.

## Log and monitor interface

The default log is `file_logging.log`; `ACLOG_PATH` overrides its location.
Seven tab-separated fields hold UID, path, date, time, access type
(0=create, 1=open, 2=write), denied flag, and MD5 fingerprint.

`acmonitor -m` lists suspicious users. `acmonitor -i PATH` reports modifications.
Each invocation selects one reporting mode. No elevated process is required.

## Verified results and limits

Tests assert eight distinct denied files, two modifications, the expected final
MD5 fingerprint, mode 0600 log permissions, malformed-line handling, and CLI
behavior. Host fixtures remain outside the test writes.

This is process-local LD_PRELOAD instrumentation, not complete system auditing.
It cannot capture programs that bypass these functions. Concurrency, unusual
stream/I/O failure cases, and adversarial log tampering need further testing.
MD5 here is a coursework change detector, not an integrity guarantee.
