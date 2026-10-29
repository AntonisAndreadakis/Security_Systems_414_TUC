#!/usr/bin/env python3
"""Assignment 1: educational OTP, Caesar and Vigenere; Python standard library."""
import argparse
import secrets
import string
import sys
import unittest

ALPHABET = string.digits + string.ascii_uppercase + string.ascii_lowercase

def otp(data: bytes, key: bytes) -> bytes:
    if len(data) != len(key):
        raise ValueError('OTP key must have exactly the same byte length as the data')
    return bytes(a ^ b for a, b in zip(data, key))

def caesar(text: str, shift: int, decrypt=False) -> str:
    # Per the brief, a character outside the 62-character alphabet is
    # "skipped": left unchanged in place, not rejected. The alphabet is
    # closed under the shift, so this is always exactly reversible.
    if shift < 0:
        raise ValueError('Caesar requires a non-negative shift')
    step = (-shift if decrypt else shift) % len(ALPHABET)
    return ''.join(ALPHABET[(ALPHABET.index(c) + step) % len(ALPHABET)] if c in ALPHABET else c
                   for c in text)

def vigenere(text: str, key: str, decrypt=False) -> str:
    if not key or any(c not in string.ascii_uppercase for c in text + key):
        raise ValueError('Vigenere requires uppercase A-Z and a nonempty key')
    direction = -1 if decrypt else 1
    return ''.join(chr(65 + (ord(c)-65 + direction*(ord(key[i % len(key)])-65)) % 26)
                   for i, c in enumerate(text))

class Tests(unittest.TestCase):
    def test_otp(self):
        self.assertEqual(otp(bytes.fromhex('0001ff'), bytes.fromhex('0102ff')), bytes.fromhex('010300'))
        data = bytes(range(256))
        key = secrets.token_bytes(len(data))
        self.assertEqual(otp(otp(data, key), key), data)
        self.assertEqual(otp(b'', b''), b'')
        with self.assertRaises(ValueError): otp(b'x', b'')

    def test_caesar(self):
        self.assertEqual(caesar('hello', 4), 'lipps')
        self.assertEqual(caesar('9Zz', 1), 'Aa0')
        for shift in (0, 1, 61, 62, 10**30):
            self.assertEqual(caesar(caesar(ALPHABET, shift), shift, True), ALPHABET)
        # Characters outside the alphabet pass through unchanged, round-trips cleanly.
        encoded = caesar('not allowed!', 1)
        self.assertEqual((encoded[3], encoded[-1]), (' ', '!'))
        self.assertEqual(caesar(encoded, 1, True), 'not allowed!')
        with self.assertRaises(ValueError): caesar('abc', -1)

    def test_vigenere(self):
        self.assertEqual(vigenere('ATTACKATDAWN', 'LEMON'), 'LXFOPVEFRNHR')
        self.assertEqual(vigenere('LXFOPVEFRNHR', 'LEMON', True), 'ATTACKATDAWN')
        self.assertEqual(vigenere('', 'A'), '')
        for text, key in [('HELLO', ''), ('hello', 'A'), ('HELLO', 'a')]:
            with self.assertRaises(ValueError): vigenere(text, key)

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--self-test', action='store_true')
    sub = parser.add_subparsers(dest='cipher')
    p = sub.add_parser('otp', help='XOR hexadecimal bytes; repeat with same key to decrypt')
    p.add_argument('data_hex'); p.add_argument('--key-hex')
    p = sub.add_parser('caesar'); p.add_argument('text'); p.add_argument('shift', type=int)
    p.add_argument('--decrypt', action='store_true')
    p = sub.add_parser('vigenere'); p.add_argument('text'); p.add_argument('key')
    p.add_argument('--decrypt', action='store_true')
    sub.add_parser('demo', help='read the original five-line input format')
    args = parser.parse_args(argv)
    if args.self_test:
        return 0 if unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Tests)).wasSuccessful() else 1
    try:
        if args.cipher == 'otp':
            data = bytes.fromhex(args.data_hex)
            key = bytes.fromhex(args.key_hex) if args.key_hex is not None else secrets.token_bytes(len(data))
            result = otp(data, key)
            print('key_hex=' + key.hex()); print('result_hex=' + result.hex())
        elif args.cipher == 'caesar': print(caesar(args.text, args.shift, args.decrypt))
        elif args.cipher == 'vigenere': print(vigenere(args.text, args.key, args.decrypt))
        elif args.cipher == 'demo':
            values = [sys.stdin.readline() for _ in range(5)]
            if any(v == '' for v in values): raise ValueError('Expected five input lines')
            original, text, shift_text, message, key = [v.rstrip('\r\n') for v in values]
            shift = int(shift_text)
            # OTP filters out non-alphabet characters before XOR-ing: unlike
            # Caesar's shift, XOR isn't closed over the alphabet, so a skipped
            # character can't be told apart from a transformed one by its
            # ciphertext value; filtering first keeps it exactly reversible.
            filtered = ''.join(c for c in original if c in ALPHABET)
            data = filtered.encode('utf-8'); pad = secrets.token_bytes(len(data)); encoded = otp(data, pad)
            print('[OTP] input:', original)
            print('[OTP] encrypted:', encoded.hex()); print('[OTP] decrypted:', otp(encoded, pad).decode('utf-8'))
            encoded = caesar(text, shift)
            print('[Caesars] input:', text)
            print('[Caesars] key:', shift)
            print('[Caesars] encrypted:', encoded)
            print('[Caesars] decrypted:', caesar(encoded, shift, True))
            encoded = vigenere(message, key)
            print('[Vigenere] input:', message)
            print('[Vigenere] key:', key)
            print('[Vigenere] encrypted:', encoded)
            print('[Vigenere] decrypted:', vigenere(encoded, key, True))
        else: parser.error('Choose a cipher, demo, or --self-test')
    except (ValueError, OSError) as error:
        parser.exit(1, f'Error: {error}\n')
    return 0

if __name__ == '__main__':
    sys.exit(main())
