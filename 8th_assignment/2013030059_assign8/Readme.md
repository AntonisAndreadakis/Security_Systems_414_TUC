# Assignment 8 - Buffer-overflow lab and safe comparison

Andreadakis Antonios - 2013030059

## Python version (current entry point)

`assignment.py` needs only Python 3.11+. Its safe checks cover the greeter,
explicit memory model, and read-only inspection of the supplied files.

```sh
python assignment.py --self-test
python assignment.py --greet Alice
python assignment.py --inspect
python assignment.py --simulate-hex 41414141
```

The memory model uses a bytearray to demonstrate a 32-byte buffer and a
configurable return-address offset (default 48). It explicitly reports
overflow and simulated return changes, and always reports executed=false.
The layout is a teaching model, not a claim that Python has C stack corruption.
`--inspect` reports the original ELF architecture, hash, and stored payload
metadata without running it.

The actual native exploit and missing shellcode test remain separate
unapproved/incomplete deliverables. This Python model is not an equivalent
native exploit demonstration and does not close that original requirement.

```powershell
powershell -NoProfile -File sandbox/run.ps1 -Assignment 8 -Python
```

## Status: safe subset verified

The safe regression suite is designed to run in Docker. The original exploitation assignment is
**not fully completed or validated**: its shellcode test program is missing,
and shell spawning/exploit execution remains outside the approved scope.

## Files and updates

- `Greeter.c` and the supplied `Greeter` binary remain the intentionally
  vulnerable historical target.
- `myRes.txt` retains the historical 52-byte payload.
- `exploit.py` is now a metadata-only inspector for the stored payload. It has
  no payload-emission or process-execution mode.
- `greeter_safe.c` is a separate bounded-input comparison program.
- The Makefile defaults to the safe target and refuses the vulnerable build.
- `test_safe.py` tests only the safe target, simulation, and read-only metadata
  inspection.

## Approved build and test workflow

Requires a C11 compiler, Make, and Python 3.

```sh
make
make check
python3 exploit.py --describe
```

Preferred isolated test from the testing workspace:

```powershell
powershell -NoProfile -File sandbox/run.ps1 -Assignment 8
```

Tests check normal greetings, the 31-character boundary, overlong input,
embedded NULs, empty input, Python syntax, simulation boundaries, malformed ELF
metadata, and the existing payload. They do not execute the historical binary
or generate a replacement payload.

## Remaining work

The fixed-address payload depends on the supplied x86-32 binary and has not
been demonstrated against a rebuilt target. The missing shellcode test and
original exploit demonstration require separate approval and an appropriate
disposable environment. The safe comparison is useful regression coverage,
but does not satisfy those original exploitation deliverables.

Old claims that the exploit works are historical observations, not results of
this maintenance session. No root access, executable-memory changes, or shell
spawning were attempted in the current tests.
