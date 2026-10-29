#!/usr/bin/env python3
"""Assignment 2: AES-128/256 ECB + plaintext CMAC in the original file format.

Requires cryptography (requirements.txt). The legacy format is for coursework.
"""
import argparse
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import cmac, padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except ImportError:
    raise SystemExit('Missing cryptography. Install requirements.txt in a virtual environment, or use the Docker runner.')

MAX_INPUT = 16 * 1024 * 1024

def derive_key(password: bytes, bits: int) -> bytes:
    if not password: raise ValueError('Password must not be empty')
    if bits not in (128, 256): raise ValueError('Key size must be 128 or 256')
    # EVP_BytesToKey with SHA-1, one iteration, no salt, as required by fixtures.
    result = previous = b''
    while len(result) < bits // 8:
        previous = hashlib.sha1(previous + password).digest()
        result += previous
    return result[:bits // 8]

def tag(data: bytes, key: bytes) -> bytes:
    ctx = cmac.CMAC(algorithms.AES(key)); ctx.update(data)
    return ctx.finalize()

def encrypt(data: bytes, key: bytes) -> bytes:
    padder = padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()
    ctx = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return ctx.update(padded) + ctx.finalize()

def decrypt(data: bytes, key: bytes) -> bytes:
    if not data or len(data) % 16: raise ValueError('Ciphertext must contain complete AES blocks')
    ctx = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
    padded = ctx.update(data) + ctx.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()

def transform(data: bytes, password: bytes, bits: int, mode: str) -> bytes:
    key = derive_key(password, bits)
    if mode == 'e': return encrypt(data, key)
    if mode == 'd': return decrypt(data, key)
    if mode == 's': return encrypt(data, key) + tag(data, key)
    if mode == 'v':
        if len(data) < 32: raise ValueError('Signed data is too short')
        plain = decrypt(data[:-16], key)
        ctx = cmac.CMAC(algorithms.AES(key)); ctx.update(plain)
        ctx.verify(data[-16:])
        return plain
    raise ValueError('Unknown operation')

def process_file(source, destination, password, bits, mode):
    with Path(source).open('rb') as stream:
        data = stream.read(MAX_INPUT + 1)
    if len(data) > MAX_INPUT: raise ValueError('Input exceeds 16 MiB coursework limit')
    result = transform(data, password, bits, mode)
    # Never truncate an existing destination or write unverified plaintext.
    with Path(destination).open('xb') as out: out.write(result)

class Tests(unittest.TestCase):
    def test_cmac_rfc4493(self):
        key = bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c')
        self.assertEqual(tag(b'', key).hex(), 'bb1d6929e95937287fa37d129b756746')

    def test_roundtrip_and_tamper(self):
        for bits in (128, 256):
            for data in (b'', bytes(range(256)), b'\0\xffhello\n'):
                encrypted = transform(data, b'test', bits, 'e')
                self.assertEqual(transform(encrypted, b'test', bits, 'd'), data)
                signed = transform(data, b'test', bits, 's')
                self.assertEqual(transform(signed, b'test', bits, 'v'), data)
                for index in (0, len(signed)-1):
                    changed = bytearray(signed); changed[index] ^= 1
                    with self.assertRaises((ValueError, InvalidSignature)):
                        transform(bytes(changed), b'test', bits, 'v')
                with self.assertRaises((ValueError, InvalidSignature)):
                    transform(signed, b'wrong', bits, 'v')

    def test_fixtures(self):
        base = Path(__file__).resolve().parent
        expected = b'Hello HPY414\n\nThis file was encrypted with a 128-bit key\n\nBB!\n'
        self.assertEqual(transform((base/'hpy414_decryptme_128.txt').read_bytes(), b'hpy414', 128, 'd'), expected)
        for bits in (128,256):
            plain = transform((base/f'hpy414_verifyme_{bits}.txt').read_bytes(), b'hpy414', bits, 'v')
            self.assertIn(str(bits).encode(), plain)

    def test_invalid_and_output_preservation(self):
        with self.assertRaises(ValueError): derive_key(b'',128)
        with self.assertRaises(ValueError): derive_key(b'a',192)
        for mode in ('d','v'):
            with self.assertRaises(ValueError): transform(b'abc',b'test',128,mode)
        with tempfile.TemporaryDirectory() as directory:
            source, dest = Path(directory)/'input', Path(directory)/'output'
            source.write_bytes(b'bad ciphertext'); dest.write_bytes(b'keep')
            with self.assertRaises(ValueError): process_file(source,dest,b'test',128,'v')
            self.assertEqual(dest.read_bytes(),b'keep')
            with self.assertRaises(FileExistsError): process_file(source,dest,b'test',128,'e')

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    for flag in ('e','d','s','v'): mode.add_argument('-'+flag, dest='mode', action='store_const', const=flag)
    mode.add_argument('--self-test', action='store_true')
    parser.add_argument('-i', type=Path); parser.add_argument('-o', type=Path)
    parser.add_argument('-b', type=int, choices=(128,256), default=128)
    password = parser.add_mutually_exclusive_group()
    password.add_argument('-p', help='password (visible in process arguments)')
    password.add_argument('--password-file', type=Path, help='UTF-8/raw password file; one final newline is removed')
    args = parser.parse_args(argv)
    if args.self_test:
        return 0 if unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Tests)).wasSuccessful() else 1
    if args.i is None or args.o is None or (args.p is None and args.password_file is None):
        parser.error('-i, -o and either -p or --password-file are required')
    try:
        pwd = args.p.encode('utf-8') if args.p is not None else args.password_file.read_bytes().removesuffix(b'\n').removesuffix(b'\r')
        process_file(args.i,args.o,pwd,args.b,args.mode)
    except InvalidSignature:
        parser.exit(2,'Verification failed; no output written\n')
    except (OSError,ValueError) as error:
        parser.exit(1,f'Error: {error}\n')
    return 0

if __name__ == '__main__': sys.exit(main())
