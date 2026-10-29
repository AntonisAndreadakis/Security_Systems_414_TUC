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
| Historical C/Bash implementation | Unfinished and unsafe | Known correctness and destructive-operation risks remain. |

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

## Legacy implementation

The legacy files are `logger.c`, `acmonitor.c`, `test_aclog.c`, and the
destructive exercise `ransomware.sh`; `ac_system.py`, its four test files and
`run_tests.sh` were moved to `archive/5th assignment/2013030059_assign5/`. The safe
`make check` target runs only the maintained Python regression suite; this
legacy path is neither working nor safe. Known issues include unsafe
shell quoting/deletion, file truncation, incompatible parsing, incorrect
fingerprints and thresholds, unsafe buffers and permissions, incorrect Python
monitor semantics, and Makefile targets that can modify fixtures.

Earlier syntax/CLI checks and 15 legacy unit tests passed, but they do not
establish specification compliance or validate the C deliverable. No C build
or destructive script execution has been validated.

Legacy tests previously overwrote `file0`-`file9`, `file_0`-`file_9`, and
`test1.txt`; their former contents were not recovered. Those leftovers, the
old `file_logging.log`, and the empty `acmonitor.c.encrypt` are now in the
archive folder.

> **Legacy safety warning:** Never run legacy tests in the submission directory;
> use disposable copies. Do not run `ransomware.sh`, cleanup targets, or
> encryption/deletion workflows against real data. Any destructive exercise
> requires separate approval.
