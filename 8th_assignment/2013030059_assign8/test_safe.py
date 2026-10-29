"""Build/run only the hardened comparison target; no shellcode execution."""
import ast
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

BASE = Path(__file__).resolve().parent


def load_module(name):
    spec = importlib.util.spec_from_file_location(name, BASE / f'{name}.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


assignment = load_module('assignment')
exploit = load_module('exploit')


class SafeLabTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        subprocess.run(['make', '-B', 'greeter_safe'], cwd=BASE, check=True, timeout=30)

    def greet(self, value):
        return subprocess.run([str(BASE / 'greeter_safe')], input=value, capture_output=True, timeout=5)

    def test_normal_name(self):
        result = self.greet(b'Alice\n')
        self.assertEqual(result.returncode, 0)
        self.assertIn(b'Hello Alice,', result.stdout)

    def test_python_greeter_matches_safe_contract(self):
        self.assertEqual(assignment.greet('Alice'), 'Hello Alice, have a nice day.')
        for value in ('', 'A' * 32, 'line\nbreak', 'non-ASCII-é'):
            with self.assertRaises(ValueError):
                assignment.greet(value)

    def test_boundaries_and_bad_input(self):
        self.assertEqual(self.greet(b'A' * 31 + b'\n').returncode, 0)
        for value in (b'A' * 32, b'A' * 4096, b'\x00Bob\n', b'', b'\n'):
            self.assertNotEqual(self.greet(value).returncode, 0)

    def test_inspector_syntax_and_metadata_only(self):
        ast.parse((BASE / 'exploit.py').read_text())
        result = subprocess.run([sys.executable, str(BASE / 'exploit.py'), '--describe'],
                                capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0)
        self.assertIn('total=52', result.stdout)
        self.assertIn('No payload was emitted or executed', result.stdout)
        self.assertEqual((BASE / 'myRes.txt').stat().st_size, 52)

    def test_memory_model_boundaries(self):
        self.assertFalse(assignment.simulate(b'A' * 47)['return_overwritten'])
        nul_overwrite = assignment.simulate(b'A' * 48)
        self.assertTrue(nul_overwrite['return_overwritten'])
        self.assertEqual(nul_overwrite['simulated_return'], '0x11223300')
        self.assertEqual(assignment.simulate(b'ok\nignored')['bytes_written_including_nul'], 3)
        with self.assertRaises(ValueError):
            assignment.simulate(b'A' * 4097)
        with self.assertRaises(TypeError):
            assignment.simulate('not bytes')

    def test_artifact_inspection_and_malformed_elf(self):
        result = assignment.inspect_artifacts(BASE)
        self.assertEqual(result['elf_machine_name'], 'Intel 80386')
        self.assertEqual(result['payload_length'], 52)
        self.assertFalse(result['executed'])

        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary = Path(temporary_directory)
            (temporary / 'Greeter').write_bytes(b'not an ELF file')
            (temporary / 'myRes.txt').write_bytes(b'synthetic')
            with self.assertRaisesRegex(ValueError, 'not an ELF'):
                assignment.inspect_artifacts(temporary)

    def test_payload_description_uses_stored_bytes(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            payload = Path(temporary_directory) / 'payload.bin'
            payload.write_bytes(b'ABCD')
            description = exploit.describe(payload)
            with self.assertRaisesRegex(ValueError, 'not a regular file'):
                exploit.describe(Path(temporary_directory) / 'missing.bin')
        self.assertIn('total=4 bytes', description)
        self.assertIn('trailing_little_endian_u32=0x44434241', description)

if __name__ == '__main__':
    unittest.main()
