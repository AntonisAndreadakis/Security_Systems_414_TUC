# Python assignment projects

Each assignment now has a standalone **assignment.py** entry point. The original
C/Bash files are retained for reference. Use Python 3.11 or newer.

| Assignment | Python entry point | Scope |
| --- | --- | --- |
| 1 | [Ciphers](<1st assignment/2013030059_assign1/assignment.py>) | OTP, Caesar, Vigenere, original demo |
| 2 | [AES/CMAC](<2nd assignment/2013030059_assign2/assignment.py>) | Binary/empty encryption, signing, verification, supplied fixtures |
| 3 | [RSA](<3d assignment/2013030059_assign3/assignment.py>) | Key generation and compatible 64-bit little-endian files |
| 4 | [Access logging](<4th assignment/2013030059_assign4/assignment.py>) | Explicit Python file wrapper, TSV logger and monitor |
| 5 | [Activity detection](<5th assignment/2013030059_assign5/assignment.py>) | Corrected logger, 20-minute count, event sequence detection, simulation |
| 6 | [Packet monitor](<6th assignment/2013030059_assign6/assignment.py>) | Standalone offline PCAP parser; gated Linux live mode |
| 7 | [Ad-block planner](<7th assignment/2013030059_assign7/assignment.py>) | Validated blocklist, JSON plans/state, gated application |
| 8 | [Buffer-layout lab](<8th_assignment/2013030059_assign8/assignment.py>) | Safe memory model, greeter, read-only ELF/payload inspection |

## Run the tests

From this workspace in PowerShell, with Docker Desktop running:

```powershell
docker build --tag student-assignments-sandbox:local --file sandbox/Dockerfile sandbox
powershell -NoProfile -File sandbox/run.ps1 -Assignment 0 -Python
```

Assignment 0 runs every Python self-test followed by eight CLI integration
checks. The verified combined run passed **46 self-tests and 8 CLI checks**.
Select 1 through 8 instead to test a single project. The container runs
as UID 10001 with no network or capabilities, a read-only source mount, and
temporary test copies. It disappears after the run. See [sandbox details](sandbox/README.md).

For local use, run `python assignment.py --help` or `--self-test` inside a
project directory. Assignment 2 needs its requirements.txt; assignment 5 needs
its requirements only for the separately approved real lab. All other Python
entry points use the standard library. Docker installs dependencies only into
the image as an ordinary user; no host installation or root attempt is made.

## Important differences from the original assignments

- Assignment 4 audits operations through Logger.open(), not arbitrary external
  C programs. Assignment 5's maintained entry point is assignment.py; old
  ac_system.py and its tests were moved to [archive](archive/README.md) and
  should not be used.
- Assignment 5's ordinary simulation retains originals and writes labelled
  markers. The real generated-fixture AES-GCM encryption/deletion/recovery
  implementation is gated and **not yet executed or verified**.
- Assignment 6's live mode and assignment 7's real DNS/firewall integration are
  implemented behind opt-ins but **not tested**. No privileges are acquired.
- Assignment 7 saves a project blocklist, not a complete host firewall snapshot.
- Assignment 8's bytearray model is **not** a native C exploit. The original
  exploit execution and missing shellcode test remain unapproved/incomplete.

These limits follow the user's earlier safety boundary. Passing safe tests is
not evidence that those remaining integration requirements are complete.
Each project's README describes its commands, behavior, and remaining work.
