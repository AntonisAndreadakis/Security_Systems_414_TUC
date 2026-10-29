# Assignment 1 - Simple cryptography

Andreadakis Antonios - 2013030059

Educational implementations of OTP, Caesar, and Vigenere ciphers. The Python
program is the current entry point; the repaired C version is retained and
tested separately.

## Quick start (Python)

Run `assignment.py` with Python 3.11 or newer; no third-party package is needed.

```sh
python assignment.py --self-test
python assignment.py caesar hello 4
python assignment.py vigenere ATTACKATDAWN LEMON
python assignment.py otp 0001ff --key-hex 0102ff
```

The `otp` command accepts hexadecimal bytes and prints both key and result.
Keep generated keys private. `demo` accepts the same five input lines as the C
demo. `--decrypt` reverses Caesar/Vigenere. Three Python tests passed in Docker.

From the testing workspace:

```powershell
powershell -NoProfile -File sandbox/run.ps1 -Assignment 1 -Python
```

## C implementation

`simple_crypto.h` declares the API. `simple_crypto.c` builds into
`libsimple_crypto.a`; `demo.c` links that library. `test_simple_crypto.c`
contains regression tests.

OTP uses a length-aware XOR operation and reads key bytes from /dev/urandom,
checking errors and closing the descriptor. The demo displays binary ciphertext
as hexadecimal. Caesar uses the ordered 62-character alphabet 0-9A-Za-z, with
modulo wrapping; unsupported characters are rejected. Vigenere accepts uppercase
A-Z and repeats a nonempty keyword internally.

The old unsafe input handling, incorrect wraparound, buffer overruns, broken
header guard, and direct inclusion of the implementation file were corrected.

## Build and run the C version

Requires a Linux C11 compiler, Make, and ar. From this assignment directory:

```sh
make
make check
make sanitize
```

The demo reads five lines: OTP text, Caesar text, nonnegative Caesar shift,
uppercase Vigenere text, uppercase keyword. Example:

```sh
printf 'secret\nhello\n4\nATTACKATDAWN\nLEMON\n' | ./demo
```

Preferred isolated test, from the testing workspace in PowerShell:

```powershell
powershell -NoProfile -File sandbox/run.ps1 -Assignment 1
```

## Verification

Three Python tests passed in Docker. The repaired C implementation passed its
normal regression suite and AddressSanitizer/UndefinedBehaviorSanitizer checks.

Deterministic OTP XOR/roundtrip, random key reads, Caesar boundaries and full
alphabet wrap, invalid inputs, buffer limits, in-place operations, Vigenere
ATTACKATDAWN/LEMON -> LXFOPVEFRNHR, and exact demo output checks.

## Limitations

These are educational algorithms. Caesar and Vigenere are not suitable for
protecting real data. OTP security depends on secret, truly random, never-reused
keys as long as the message; this demonstration does not manage persisted keys.
Old prebuilt artifacts are not evidence of the current implementation; rebuild.
