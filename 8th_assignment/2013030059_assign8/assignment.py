#!/usr/bin/env python3
"""Assignment 8: safe Python buffer-layout laboratory and artifact inspection.

Python does not reproduce C stack corruption. This explicit bytearray model
shows overflow effects without native code execution or shell spawning. The
original C exploit demonstration is a separate, unapproved deliverable.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys
import unittest


MAX_SIMULATION_BYTES = 4096
MAX_ARTIFACT_BYTES = 16 * 1024 * 1024
ELF_MACHINE_NAMES = {
    3: "Intel 80386",
    62: "AMD x86-64",
}


def _sha256_file(path, *, max_bytes=MAX_ARTIFACT_BYTES):
    """Hash a regular, size-bounded artifact without loading it into memory."""
    path = Path(path)
    size = path.stat().st_size
    if not path.is_file():
        raise ValueError(f"Artifact is not a regular file: {path.name}")
    if size > max_bytes:
        raise ValueError(f"Artifact exceeds the {max_bytes}-byte inspection limit: {path.name}")
    digest = hashlib.sha256()
    with path.open("rb") as artifact:
        for chunk in iter(lambda: artifact.read(64 * 1024), b""):
            digest.update(chunk)
    return size, digest.hexdigest()


def _read_bounded(path, *, max_bytes=MAX_ARTIFACT_BYTES):
    path = Path(path)
    size = path.stat().st_size
    if not path.is_file():
        raise ValueError(f"Artifact is not a regular file: {path.name}")
    if size > max_bytes:
        raise ValueError(f"Artifact exceeds the {max_bytes}-byte inspection limit: {path.name}")
    return path.read_bytes()


def greet(name):
    data = name.encode('utf-8')
    if not 1 <= len(data) <= 31 or any(c < 32 or c > 126 for c in data):
        raise ValueError('Name must contain 1 to 31 printable ASCII characters')
    return f'Hello {name}, have a nice day.'


def simulate(data, buffer_size=32, return_offset=48):
    if not isinstance(data, bytes):
        raise TypeError("Simulation input must be bytes")
    if not 1 <= buffer_size <= return_offset <= MAX_SIMULATION_BYTES:
        raise ValueError('Invalid simulated layout')
    if len(data) > MAX_SIMULATION_BYTES:
        raise ValueError(f'Simulation input exceeds {MAX_SIMULATION_BYTES} bytes')
    original_return = 0x11223344
    memory = bytearray(max(return_offset + 4, len(data) + 1))
    memory[return_offset:return_offset + 4] = struct.pack('<I', original_return)
    # Model gets(): append a terminator; stop at first input newline.
    copied = data.split(b'\n', 1)[0] + b'\0'
    memory[:len(copied)] = copied
    current = struct.unpack_from('<I', memory, return_offset)[0]
    return {
        'model_only': True,
        'buffer_size': buffer_size,
        'return_offset': return_offset,
        'bytes_written_including_nul': len(copied),
        'overflow_bytes': max(0, len(copied) - buffer_size),
        'original_return': f'0x{original_return:08x}',
        'simulated_return': f'0x{current:08x}',
        'return_overwritten': current != original_return,
        'executed': False,
    }


def inspect_artifacts(directory):
    directory = Path(directory)
    target_path = directory / 'Greeter'
    payload_path = directory / 'myRes.txt'
    target_size, target_sha256 = _sha256_file(target_path)
    payload = _read_bounded(payload_path)

    with target_path.open('rb') as target_file:
        header = target_file.read(64)
    if len(header) < 20 or header[:4] != b'\x7fELF':
        raise ValueError('Target is not an ELF binary')
    elf_class, elf_data, elf_version = header[4:7]
    if elf_class not in (1, 2) or elf_data not in (1, 2) or elf_version != 1:
        raise ValueError('Unsupported ELF identification header')
    minimum_header_size = 52 if elf_class == 1 else 64
    if target_size < minimum_header_size or len(header) < minimum_header_size:
        raise ValueError('Target has a truncated ELF header')
    endian = '<' if elf_data == 1 else '>'
    machine = struct.unpack_from(endian + 'H', header, 18)[0]
    payload_endian = 'little' if elf_data == 1 else 'big'
    return {
        'elf_bits': 32 if elf_class == 1 else 64,
        'elf_machine': machine,
        'elf_machine_name': ELF_MACHINE_NAMES.get(machine, 'unknown'),
        'elf_endian': payload_endian,
        'target_size': target_size,
        'target_sha256': target_sha256,
        'payload_length': len(payload),
        'payload_sha256': hashlib.sha256(payload).hexdigest(),
        'payload_last_u32': (
            f'0x{int.from_bytes(payload[-4:], payload_endian):08x}'
            if len(payload) >= 4 else None
        ),
        'executed': False,
        'note': 'Stored bytes inspected only; see test_exploit.py for verified exploit execution',
    }


class Tests(unittest.TestCase):
    def test_safe_greeter(self):
        self.assertEqual(greet('Alice'),'Hello Alice, have a nice day.')
        self.assertIn('A'*31,greet('A'*31))
        for name in ('','A'*32,'a\0b','a\nb','é'):
            with self.assertRaises(ValueError): greet(name)
    def test_explicit_memory_model(self):
        self.assertFalse(simulate(b'A'*31)['return_overwritten'])
        self.assertEqual(simulate(b'A'*32)['overflow_bytes'],1)
        result=simulate(b'A'*48+struct.pack('<I',0x55667788))
        self.assertTrue(result['return_overwritten'])
        self.assertEqual(result['simulated_return'],'0x55667788')
        self.assertFalse(result['executed'])
        self.assertEqual(simulate(b'hi\nignored')['bytes_written_including_nul'],3)
    def test_supplied_artifacts_read_only(self):
        result=inspect_artifacts(Path(__file__).resolve().parent)
        self.assertEqual(result['elf_bits'],32)
        self.assertEqual(result['elf_machine'],3)
        self.assertEqual(result['payload_length'],52)
        self.assertEqual(result['payload_last_u32'],'0x080dacc0')
        self.assertFalse(result['executed'])

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    mode=parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--self-test',action='store_true')
    mode.add_argument('--greet',metavar='NAME')
    mode.add_argument('--inspect',action='store_true')
    mode.add_argument('--simulate-hex',metavar='HEX_BYTES')
    parser.add_argument('--return-offset',type=int,default=48,help='explicit model offset; not auto-discovered from the binary')
    args=parser.parse_args(argv)
    if args.self_test:
        return 0 if unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Tests)).wasSuccessful() else 1
    try:
        if args.greet is not None: print(greet(args.greet))
        elif args.inspect: print(json.dumps(inspect_artifacts(Path(__file__).resolve().parent),indent=2))
        else: print(json.dumps(simulate(bytes.fromhex(args.simulate_hex),return_offset=args.return_offset),indent=2))
    except (OSError,ValueError) as error: parser.exit(1,f'Error: {error}\n')
    return 0

if __name__ == '__main__':
    sys.exit(main())
