# Assignment 3 - Educational RSA

Andreadakis Antonios - 2013030059

## Python version (current entry point)

`assignment.py` is the complete Python RSA implementation. Python 3.11+,
standard library only. It uses explicit 64-bit little-endian file encoding,
so fixture compatibility no longer depends on the host's native size_t.

```sh
python assignment.py --self-test
python assignment.py -g --key-directory NEW_EMPTY_DIRECTORY
python assignment.py -i plaintext.txt -o ciphertext.bin -k NEW_EMPTY_DIRECTORY/public.key -e
python assignment.py -i ciphertext.bin -o recovered.txt -k NEW_EMPTY_DIRECTORY/private.key -d
```

Create the empty key directory first. Existing keys and output files are
refused. Key selection uses Python secrets; the mathematical scheme remains
tiny, unpadded educational RSA. Public=(n,d), private=(n,e) follows the brief.
Four tests passed: known RSA vector/sieve, randomized all-byte roundtrips,
malformed inputs, and supplied challenge files.

```powershell
powershell -NoProfile -File sandbox/run.ps1 -Assignment 3 -Python
```

## Earlier C/shell validation status

The corrected implementation passed `make check` in the restricted Docker
sandbox using GCC with warnings enabled.

## Which sources are built?

The Makefile builds **main_fixed.c**, **rsa_fixed.c**, and **rsa_fixed.h**.
The original `main.c`, `rsa.c`, `rsa.h`, and utility files, and the old prebuilt
executable, were moved to `archive/3d assignment/` at the workspace root. They
are historical reference only and are not the current implementation.

## Updates

Corrected modular inverse calculation, buffer bounds, ciphertext byte counts,
binary I/O, excessive allocation, cleanup, key validation, and conflicting CLI
modes. Generated moduli must represent every byte value.

The report uses an unusual naming convention which is preserved:
public key = `(n, d)`; private key = `(n, e)`, where `d` is the modular
inverse of `e` modulo `(p-1)(q-1)`. The modulus is first in each key file.

## Build and use

Requires a Linux C11 compiler, Make, and Python 3 for tests.

```sh
make
make check
./assign_3 -h
./assign_3 -g
./assign_3 -i plaintext.txt -o ciphertext.bin -k public.key -e
./assign_3 -i ciphertext.bin -o recovered.txt -k private.key -d
```

Key generation writes `public.key` and `private.key` in the current directory.
Use a disposable working directory for these commands. The inverse key direction
is also supported. The historical trailing positional debug argument is no
longer supported.

Preferred isolated test from the testing workspace:

```powershell
powershell -NoProfile -File sandbox/run.ps1 -Assignment 3
```

## Verified coverage

Empty files, embedded NULs and all 256 byte values, both key directions,
independent Python modular-exponentiation checks, all four supplied Task D
challenges, malformed keys, truncated/out-of-range ciphertext, and conflicting
CLI modes passed.

## Limitations and submission status

The required native `size_t` binary format is architecture/endian dependent;
the supplied fixtures target 64-bit little-endian systems. Tiny keys, unpadded
per-byte RSA, and no authentication make this an educational implementation only.

## Task D deliverables

Regenerated with the built `assign_3` against `hpy414_public.key` /
`hpy414_private.key`:

- D.1 `TUC2013030059_encrypted_pub.txt` (376 bytes): `hpy414_encryptme_pub.txt`
  (47 bytes) encrypted with `hpy414_public.key`.
- D.2 `TUC2013030059_decrypted_pub.txt` (59 bytes): `hpy414_decryptme_pub.txt`
  decrypted with `hpy414_public.key`; plaintext reads "This file was
  successfully decrypted with the public key."
- D.3 `TUC2013030059_encrypted_priv.txt` (384 bytes): `hpy414_encryptme_priv.txt`
  (48 bytes) encrypted with `hpy414_private.key`.
- D.4 `TUC2013030059_decrypted_priv.txt` (60 bytes): `hpy414_decryptme_priv.txt`
  decrypted with `hpy414_private.key`; plaintext reads "This file was
  successfully decrypted with the private key."

`public.txt`/`private.txt` held a corrupted key pair (n=2 and n=5) left over
from an earlier run; they were not used by Task D and were moved to
`archive/3d assignment/2013030059_assign3/`.

