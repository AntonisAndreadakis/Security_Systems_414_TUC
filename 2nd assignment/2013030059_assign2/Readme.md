# Assignment 2 - AES and CMAC

Andreadakis Antonios - 2013030059

## Python version (current entry point)

`assignment.py` implements all four AES/CMAC modes and matches the supplied
fixtures. Requires Python 3.11+ and `cryptography==50.0.1`; requirements.txt
records the dependency. The Docker image already includes it.

```sh
python assignment.py --self-test
python assignment.py -i input.bin -o encrypted.bin -b 256 -p example -e
python assignment.py -i encrypted.bin -o recovered.bin -b 256 -p example -d
```

Use `-s` / `-v` for encryption with CMAC / verified decryption.
`--password-file PATH` avoids placing the password in the command line.
Existing destinations are refused, and verification happens before any output
is opened. The coursework input limit is 16 MiB. Four Python tests passed:
known CMAC vector, supplied fixtures, malformed inputs/output preservation,
and binary/empty/tamper/wrong-password cases for both key sizes.

```powershell
powershell -NoProfile -File sandbox/run.ps1 -Assignment 2 -Python
```

The Python implementation uses the library's [CMAC verification API](https://cryptography.io/en/latest/hazmat/primitives/mac/cmac/).
Legacy ECB/SHA-1 format limitations below still apply.

## Earlier C/shell validation status

Repaired and verified in the restricted Docker sandbox. Both the normal build
with warnings treated as errors and an AddressSanitizer/UndefinedBehaviorSanitizer
run passed the regression suite.

## Updates

- Correct EVP decryption calls and length-aware binary/empty-file handling.
- Strict arguments, mutually exclusive operation modes, checked I/O, cleanup,
  and nonzero error statuses.
- OpenSSL 3 CMAC with the appropriate CBC cipher parameter; encryption remains
  ECB as the assignment requires.
- Constant-time tag comparison; verification must succeed before output is written.
- Corrected Makefile and a reproducible regression suite in `tests/test.sh`.

## Build and use

Requires Linux, a C11 compiler, Make, OpenSSL 3 development files, Python 3,
and POSIX shell utilities.

```sh
make
make check
./assign_1 -h
```

CLI:

```text
./assign_1 -i INPUT -o OUTPUT -p PASSWORD -b {128|256} {-e|-d|-s|-v}
```

`-e` encrypts; `-d` decrypts; `-s` encrypts and appends a 16-byte plaintext
CMAC; `-v` decrypts and verifies that CMAC. Exactly one operation is required.
Verification failure returns status 2. Outputs are binary, not hexadecimal text.
The required password argument can be visible in process listings.

Preferred test from the testing workspace in PowerShell:

```powershell
powershell -NoProfile -File sandbox/run.ps1 -Assignment 2
```

## Verified results

Tests cover 128/256-bit binary and empty roundtrips, signed roundtrips,
modified ciphertext and tags, wrong passwords, truncated/malformed inputs,
invalid arguments, and supplied challenge files.

Both `hpy414_verifyme_128.txt` and `hpy414_verifyme_256.txt` verify with
password `hpy414` and their respective key sizes. This answers Task F.4.
`hpy414_decryptme_128.txt` decrypts to a 62-byte message beginning
`Hello HPY414`; the separate 107-byte encryptme file contains instructions
and is not that expected plaintext.

## Task F deliverables

Regenerated with the built `assign_1` against the supplied fixtures:

- F.1 `decryptme_256.txt` (176 bytes): `encryptme_256.txt` (171 bytes)
  encrypted with a 256-bit key from password `TUC2013030059`.
- F.2 `hpy414_encryptme_128.txt` (62 bytes): `hpy414_decryptme_128.txt`
  decrypted with a 128-bit key from password `hpy414`; plaintext begins
  "Hello HPY414".
- F.3 `verifyme_128.txt` (240 bytes): `signme_128.txt` (216 bytes) signed
  with a 128-bit key from password `TUC2013030059` (224-byte padded
  ciphertext + 16-byte CMAC).
- F.4: both `hpy414_verifyme_128.txt` and `hpy414_verifyme_256.txt` verify
  successfully with password `hpy414` at their respective key sizes (see
  "Verified results" above).

The stray `encrypt128.txt`/`encrypt256.txt` (neither is a Task F filename)
were moved to `archive/2nd assignment/2013030059_assign2/`.

## Remaining design limits

AES-ECB and SHA-1-based EVP_BytesToKey are retained for assignment compatibility.
This format is not a production encryption design. Existing compiled binaries
are historical; build from the updated source.
