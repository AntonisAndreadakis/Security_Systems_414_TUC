#!/usr/bin/env python3
"""Assignment 3: educational per-byte RSA, compatible with 64-bit LE fixtures."""
import argparse
import math
from pathlib import Path
import secrets
import struct
import sys
import tempfile
import unittest

WORD = struct.Struct('<Q')
KEY = struct.Struct('<QQ')

def primes(limit=255):
    sieve = bytearray(b'\1') * (limit + 1)
    sieve[:2] = b'\0\0'
    for p in range(2, math.isqrt(limit) + 1):
        if sieve[p]:
            for multiple in range(p*p, limit+1, p): sieve[multiple] = 0
    return [n for n in range(2, limit+1) if sieve[n]]

def generate_keys():
    pool = primes()
    while True:
        p, q = secrets.choice(pool), secrets.choice(pool)
        if p != q and p*q > 255: break
    n, phi = p*q, (p-1)*(q-1)
    e = next(x for x in pool if x < phi and math.gcd(x, phi) == 1)
    d = pow(e, -1, phi)
    return (n, d), (n, e)  # Public/private names follow the supplied brief.

def read_key(path):
    data = Path(path).read_bytes()
    if len(data) != KEY.size: raise ValueError('Key must contain exactly two 64-bit little-endian integers')
    key = KEY.unpack(data)
    validate_key(key)
    return key

def validate_key(key):
    n, exponent = key
    if not 255 < n < 2**64 or not 0 < exponent < 2**64:
        raise ValueError('Invalid modulus or exponent')

def transform(data: bytes, key, decrypt=False):
    validate_key(key)
    n, exponent = key
    if not decrypt: return b''.join(WORD.pack(pow(value, exponent, n)) for value in data)
    if len(data) % WORD.size: raise ValueError('Truncated ciphertext: expected 8-byte blocks')
    out = bytearray()
    for (value,) in struct.iter_unpack('<Q', data):
        if value >= n: raise ValueError('Ciphertext value outside modulus')
        value = pow(value, exponent, n)
        if value > 255: raise ValueError('Decrypted value is not a byte; wrong key or corrupt data')
        out.append(value)
    return bytes(out)

def write_new(path, data):
    # Preserve existing files unless the caller explicitly chooses a new path.
    with Path(path).open('xb') as out: out.write(data)

class Tests(unittest.TestCase):
    def test_primes_and_known_vector(self):
        self.assertEqual(primes(10), [2, 3, 5, 7])
        self.assertEqual(transform(b'A', (3233,17)), WORD.pack(2790))
        self.assertEqual(transform(WORD.pack(2790), (3233,2753), True), b'A')

    def test_roundtrips(self):
        for _ in range(10):
            public, private = generate_keys()
            for data in (b'', b'\0\xffbinary\n', bytes(range(256))):
                self.assertEqual(transform(transform(data, public), private, True), data)
                self.assertEqual(transform(transform(data, private), public, True), data)

    def test_malformed(self):
        for data in (b'x', WORD.pack(3233)):
            with self.assertRaises(ValueError): transform(data, (3233,2753), True)
        with self.assertRaises(ValueError): transform(b'a', (255,17))

    def test_supplied_challenges(self):
        base = Path(__file__).resolve().parent
        public, private = read_key(base/'hpy414_public.key'), read_key(base/'hpy414_private.key')
        for name, key, other in [('pub', public, private), ('priv', private, public)]:
            ciphertext = (base/f'hpy414_decryptme_{name}.txt').read_bytes()
            recovered = transform(ciphertext, key, True)
            self.assertIn(b'successfully decrypted', recovered)
            self.assertEqual(transform(recovered, other), ciphertext)
            plain = (base/f'hpy414_encryptme_{name}.txt').read_bytes()
            self.assertEqual(transform(transform(plain, key), other, True), plain)

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('-g', action='store_true'); mode.add_argument('-e', action='store_true')
    mode.add_argument('-d', action='store_true'); mode.add_argument('--self-test', action='store_true')
    parser.add_argument('-i', type=Path); parser.add_argument('-o', type=Path); parser.add_argument('-k', type=Path)
    parser.add_argument('--key-directory', type=Path, default=Path('.'))
    args = parser.parse_args(argv)
    if args.self_test:
        return 0 if unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Tests)).wasSuccessful() else 1
    try:
        if args.g:
            if any((args.i,args.o,args.k)): parser.error('-g does not accept -i/-o/-k')
            public, private = generate_keys()
            targets = [args.key_directory/'public.key', args.key_directory/'private.key']
            if any(p.exists() for p in targets): raise ValueError('Key output already exists; choose an empty key directory')
            write_new(targets[0], KEY.pack(*public)); write_new(targets[1], KEY.pack(*private))
        else:
            if not all((args.i,args.o,args.k)): parser.error('-i, -o and -k are required')
            result = transform(args.i.read_bytes(), read_key(args.k), args.d)
            write_new(args.o, result)
    except (OSError, ValueError) as error:
        parser.exit(1, f'Error: {error}\n')
    return 0

if __name__ == '__main__': sys.exit(main())
