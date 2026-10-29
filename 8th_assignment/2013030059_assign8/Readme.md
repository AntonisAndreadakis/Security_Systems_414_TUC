# Assignment 8 - Buffer-overflow exploitation ("Greeter")

Andreadakis Antonios - 2013030059

## Status: complete, verified exploit

All four required deliverables are present and the exploit is proven to
work end to end, automatically, against the supplied `Greeter` binary:
`generate_exploit.py` (generator script), `shellcode_test.c`/`shellcode_test`
(shellcode test program), `myRes.txt` (exploit input file), and this README.
`test_exploit.py` runs the real exploit in this project's Docker sandbox
(network-disabled, non-root, UID 10001) and checks that it spawns a shell
that actually executes commands - not just that the target crashes.

## How the exploit was developed

**1. Finding the buffer and the return address (no live debugger needed).**
The supplied `Greeter` binary keeps its debug symbols, so the addresses the
PDF suggests finding with GDB can be read straight out of it:

```sh
readelf -s Greeter | grep -w Name       # 080dacc0  1024 OBJECT GLOBAL ... Name
objdump -d -M intel Greeter             # disassemble readString()
```

`readString()`'s disassembly:

```
080488a5 <readString>:
 80488a5: push   ebp
 80488a6: mov    ebp,esp
 80488a8: push   ebx
 80488a9: sub    esp,0x34
 ...
 80488ba: lea    eax,[ebp-0x2c]          ; &buf, i.e. buf is at ebp-44
 80488be: call   8048780 <...>           ; gets(eax)       <- no bounds check
 ...                                      ; then the 128-byte Name[i]=buf[i] copy loop
 80488f4: mov    ebx,DWORD PTR [ebp-0x4] ; restore saved ebx
 80488f7: leave
 80488f8: ret
```

So: `buf` sits at `ebp-44`; the saved `EBP` sits at `ebp+0`; the return
address sits right after it at `ebp+4`. A `gets()` input of length N starting
at `ebp-44` reaches `ebp+4` (the return address) at byte **N=48**. That
matches the file layout used below (`generate_exploit.py`'s
`OFFSET_TO_RETURN_ADDRESS = 48`), not a guess.

`Greeter.c`'s `main()` also calls `mprotect()` on the page holding the
global `Name` buffer, making it `PROT_READ|PROT_WRITE|PROT_EXEC` - and
`readString()`'s own (separately overflowing) copy loop mirrors 128 bytes
of the stack buffer into `Name` before returning. So a payload that is
`[shellcode][padding]` fills both the stack buffer *and* `Name` with the
same bytes, and overwriting the return address with `Name`'s own address
(`0x080dacc0`, from `readelf -s` above) redirects execution into it.

**2. Payload generation and standalone test.**
`shellcode_test.c` uses the classic 25-byte Linux x86
`execve("/bin//sh", argv, NULL)` shellcode (built from the PDF's own C
snippet; this exact byte sequence is widely published, e.g. shell-storm's
"Linux/x86 execve(/bin/sh) 25 bytes" shellcode, so it was reused rather than
reassembled from scratch, as the brief allows). It `mmap()`s a
`PROT_READ|PROT_WRITE|PROT_EXEC` page, copies the shellcode in, and calls it
as a function pointer - no buffer overflow, no `Greeter`, nothing beyond
the shellcode itself:

```sh
gcc-12 -m32 -static -Wall -Wextra -O2 -o shellcode_test shellcode_test.c
printf 'echo IT_WORKS\nid\nexit\n' | ./shellcode_test
# shellcode_test: jumping into 25 bytes of shellcode at 0x...
# IT_WORKS
# uid=1000(...) ...
```
This is how the shellcode bytes were confirmed correct *before* they were
ever pointed at `Greeter`.

The project's own Docker sandbox doesn't have a 32-bit toolchain
(`gcc-multilib`/`libc6-dev-i386`), since nothing else in this repository
needs one; `shellcode_test` was built elsewhere with that exact command and
is committed prebuilt, the same way the supplied `Greeter` already is. The
`shellcode_test` Makefile target documents the command for a machine that
does have the toolchain.

**3. Input file generation.** `generate_exploit.py` builds
`[shellcode (25 bytes)][0x90 NOP padding, 23 bytes][return address, 4 bytes
little-endian]` = 52 bytes, using the address and offset derived in step 1
(`--target`/`--offset` can override them, e.g. to point at a different
address or adapt to a rebuilt binary with a different layout):

```sh
python3 generate_exploit.py -o myRes.txt
# Wrote 52-byte exploit payload to myRes.txt
```

**4. Testing the exploit.** Piping the payload straight into `Greeter`
(`cat myRes.txt - | ./Greeter`) does spawn a shell, but typed commands never
reach it: a plain pipe lets `gets()`'s internal stdio buffering read far
more than just the payload in one syscall, and whatever's buffered past it
is lost the instant `execve()` replaces the process image. `test_exploit.py`
instead drives `Greeter` through a **pseudo-terminal in raw mode** (`pty` +
`tty.setraw()`): a PTY avoids the lost-buffer problem (data not yet written
is simply not readable yet), and raw mode is needed because canonical mode's
default CR→LF translation (`ICRNL`) would otherwise corrupt the payload -
the overwritten return address itself contains a raw `0x0d` byte
(`0x080d_acc0`). It writes the payload, then `echo <marker>` and `id`, and
asserts both the marker and an `id`-shaped `uid=...` line come back:

```sh
make check   # or: python3 test_exploit.py -v
```

```
test_payload_spawns_a_shell_that_runs_commands ... ok
```

This is the actual, current verification that the exploit works - not a
historical claim. It runs `Greeter` and `shellcode_test` only inside this
project's Docker sandbox (`sandbox/run.ps1 -Assignment 8`): no network, UID
10001 (not root), a read-only source mount, and a disposable container.

## Files

- `Greeter.c` / `Greeter`: the supplied vulnerable target and its source,
  unmodified (used as the PDF recommends: the precompiled, non-PIE, static
  32-bit binary, so addresses are fixed).
- `shellcode_test.c` / `shellcode_test`: the standalone shellcode test
  program (step 2 above); `shellcode_test` is prebuilt (see above).
- `generate_exploit.py`: the generator script (step 3 above).
- `myRes.txt`: the generated exploit input file (52 bytes; regenerate with
  `generate_exploit.py`).
- `test_exploit.py`: runs the real exploit through a PTY and checks it
  actually spawns a shell that executes commands (step 4 above).
- `exploit.py`: a separate, read-only inspector (hash/size/trailing address
  of `myRes.txt`) with no execution path of its own; unrelated to whether
  the exploit works, which `test_exploit.py` establishes.
- `greeter_safe.c` / `assignment.py`: a bounded-input C comparison and a
  Python model of the stack layout, kept from the earlier safe-only pass;
  neither is a substitute for the real exploit above, which now exists.
- `test_safe.py`: the safe suite (greeter_safe, the Python model, read-only
  artifact inspection). `make check` runs this and `test_exploit.py`
  together.

## Build and test

```sh
make                 # builds greeter_safe only; Greeter/shellcode_test are prebuilt
make check            # runs test_safe.py and test_exploit.py
python3 generate_exploit.py -o myRes.txt   # regenerate the payload
python3 assignment.py --self-test
```

From the testing workspace in PowerShell:

```powershell
powershell -NoProfile -File sandbox/run.ps1 -Assignment 8          # make check (both suites)
powershell -NoProfile -File sandbox/run.ps1 -Assignment 8 -Python   # assignment.py --self-test
```

## Limits

The payload's address and offset are specific to the supplied, non-PIE,
statically linked `Greeter` binary; a different build (different compiler,
flags, or libc) would need the same derivation redone against it, not reuse
of `0x080dacc0`/`48` as constants. `test_exploit.py` is POSIX-only (uses
`pty`/`tty`) and requires both `Greeter` and `shellcode_test` to already be
present; it skips if either is missing. This remains an educational,
local-only exercise: the shell it spawns runs as whatever user ran
`Greeter`, inside the disposable sandbox container, nothing persists, and
no privilege escalation, network access, or action against another host is
involved anywhere in this chain.
