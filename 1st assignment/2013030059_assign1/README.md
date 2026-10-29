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
demo and prints the exact 12-line format the brief specifies (`input:`/`key:`
lines included, not just the encrypted/decrypted results). `--decrypt`
reverses Caesar/Vigenere. Three Python tests passed in Docker.

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
modulo wrapping and a required non-negative shift. Vigenere accepts uppercase
A-Z and repeats a nonempty keyword internally.

Per the brief, a character outside each cipher's alphabet is "skipped", not
rejected, but the two ciphers skip differently because of how each one works:
- **Caesar** shifts only alphabet members and leaves everything else (spaces,
  punctuation, `\n`, ...) unchanged in place. The alphabet is closed under the
  shift, so this is always exactly reversible.
- **OTP** filters such characters out of the input before generating the key
  and XOR-ing, via `crypto_filter_alnum62()`. XOR is not closed over the
  alphabet, so a skipped character's *ciphertext* value can't reliably be told
  apart from a transformed one; filtering first keeps the operation exactly
  reversible instead. `[OTP] decrypted:` is therefore the filtered input, which
  can differ from the raw `[OTP] input:` line when it contains such characters.
- **Vigenere** still requires strict uppercase A-Z input and a nonempty
  uppercase key, and rejects anything else, per its own "should not be used"
  wording in the brief (as opposed to Caesar/OTP's "should be skipped").

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
