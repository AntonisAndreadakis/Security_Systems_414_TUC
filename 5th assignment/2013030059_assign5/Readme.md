# Assignment 5 - File activity detection

Andreadakis Antonios - 2013030059

This assignment detects suspicious file activity from audit logs. The supported
entry point is **`assignment.py`** on Python 3.11+; the older C, Bash, and
`ac_system.py` implementations are retained only as historical work
(`ac_system.py` and its tests now live in `archive/5th assignment/`).

## Status

| Area | Status | Notes |
| --- | --- | --- |
| Log parsing and monitor modes | Supported | Malformed records are rejected instead of becoming fabricated user events. |
| Simulation and self-tests | Verified | Fourteen safe tests pass in Docker; simulation does not encrypt or delete data. |
| AES-256-GCM recovery | Verified on synthetic fixtures | Authentication failure is atomic with respect to plaintext outputs; encrypted inputs are retained. |
| AES-256-GCM lab generation | **Unverified, opt-in** | The original-removal path was not executed; use only on generated lab fixtures with explicit approval. |
| C/Bash implementation (logger.c, acmonitor.c, ransomware.sh) | Fixed and verified | `make check` builds all three and round-trips them on disposable fixtures in `tests/check_legacy.sh`; see "Legacy implementation" below. |

## Quick start

Run the safe self-test or generate harmless synthetic events:

```sh
python assignment.py --self-test
python assignment.py --simulate NEW_DIRECTORY --count 10
```

Run monitor modes against a log:

```sh
python assignment.py --log NEW_DIRECTORY/file_logging.log -v 10
python assignment.py --log NEW_DIRECTORY/file_logging.log -e
```

- `-v COUNT` compares distinct successful creations in the preceding **20
  minutes** with `COUNT`.
- `-e` requires an ordered successful `OPEN` of the original followed by
  `CREATE` of `original.encrypt` by the same UID.
- `-m` counts distinct denied paths.
- `-i PATH` reports changed write fingerprints.

Simulation writes plainly labelled markers to a new directory and retains every
original. Tests cover boundaries, denied/duplicate paths, UID and event
matching, binary hashes, malformed records, and approval refusal.

The Docker-backed Python check can be run from the repository root:

```powershell
powershell -NoProfile -File sandbox/run.ps1 -Assignment 5 -Python
```

## Opt-in AES-GCM lab

Lab mode creates only its own fixtures, uses AES-256-GCM, verifies recovery,
and removes the generated originals:

```sh
python assignment.py --lab NEW_DIRECTORY --count N --approve-lab
python assignment.py --recover LAB_DIRECTORY --approve-lab
```

Recovery uses the retained `lab.key` and manifest; encrypted copies remain.
Before writing, it checks manifest entries, input sizes, key length, output
conflicts, and authenticates every ciphertext. Tests confirm malformed or
tampered inputs create no plaintext outputs, and successful recovery restores
generated synthetic fixtures while retaining encrypted copies. The authenticated
format is not compatible with the historical ECB exercise or OpenSSL `enc`.
Install `requirements.txt` first.

> **Safety warning:** The lab generation path that removes its generated
> originals has not been executed. Recovery was tested only with synthetic
> fixtures in a disposable Docker container. Run either workflow only in a new
> disposable directory and only with explicit approval.

## C/Bash implementation (`logger.c`, `acmonitor.c`, `ransomware.sh`)

These are the files the assignment brief itself asks for: `logger.c`
(LD_PRELOAD `fopen`/`fwrite` hooks writing the 7-field tab-separated log),
`acmonitor.c` (enriches Assignment 4's `-m`/`-i` with `-v <count>` and `-e`),
and `ransomware.sh` (create/encrypt+delete/decrypt). Each `.c`/`.sh` file
keeps the original 2020 submission inside an `#if 0` block (or, for
`ransomware.sh`, in a leading comment) for reference; it is not compiled or
executed. `ac_system.py`, its four test files and the old `run_tests.sh` are
historical dead ends and were moved to
`archive/5th assignment/2013030059_assign5/`.

Fixed from the original submission:
- `logger.c`: dropped a bogus `open()` hook that truncated the very file it
  was about to open; fixed sign-extension in the hex fingerprint; the
  fingerprint of written data now covers `size*nmemb` bytes, not
  `strlen(ptr)`; the log is a single well-formed 7-field tab-separated
  record per event (previously a mix of space- and tab-delimited fields that
  `acmonitor`'s parser could not line up); the log file is created `0600`,
  not world-writable; `fopen()`'s own result is checked before writing
  through it.
- `acmonitor.c`: fixed the `getopt` string so `-m` no longer expects an
  argument; `-m` now reports users with **more than 7** distinct denied
  files (not 1); `-v <count>` reports successful creations in the last 20
  minutes and whether `count` was reached, using real timestamp parsing
  instead of a lexicographic string comparison; `-e` matches an `OPEN` of
  `name` to a later `CREATE` of `name.encrypt` by the same UID (per-pair,
  not a `strtok(".")` scan that corrupted multi-dot filenames and could
  overflow a fixed buffer); every mode re-opens the log instead of reusing
  one exhausted `FILE*`.
- `ransomware.sh`: `-n <count>` now actually reads the count it was given
  (previously stored in `$file_num` but read back as `$filenum`); directory
  arguments are used as given instead of being forced under `~/`; filenames
  and the password are quoted; `rm` only removes the original after
  `openssl` succeeds, and a failed run never leaves a partial output behind;
  `-d` means "directory" everywhere (as in both of the brief's own usage
  examples) and decryption is now a separate `-x` flag instead of
  overloading `-d`; `LD_PRELOAD` is resolved next to the script instead of a
  hardcoded path from the original machine.

`make check` builds `logger.so`, `acmonitor` and `test_aclog`, then runs
`tests/check_legacy.sh`, which exercises all three end to end inside a
disposable temporary directory next to the sources (not `/tmp`, which this
project's Docker sandbox mounts `noexec`): it generates denied/modified/
recent/encrypted events with `test_aclog`, checks `acmonitor -m/-i/-v/-e`
against them, then runs `ransomware.sh` through create → encrypt+delete →
decrypt on throwaway fixtures (including a wrong-password case that must not
produce plaintext). Nothing outside that temporary directory is touched.

Legacy tests previously overwrote `file0`-`file9`, `file_0`-`file_9`, and
`test1.txt` in this directory; their former contents were not recovered.
Those leftovers, the old `file_logging.log`, and the empty
`acmonitor.c.encrypt` are now in the archive folder. The current
`test_aclog`/`ransomware.sh` tests are confined to disposable directories and
cannot reproduce that problem.
