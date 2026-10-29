"""Tests use shell functions in place of firewall commands and a fake DNS resolver.
No kernel firewall, network, capabilities, or root user is needed or requested.
"""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

SOURCE = Path(__file__).resolve().parent / 'adblock.sh'

class AdblockTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)
        self.script = self.work / 'adblock.sh'
        shutil.copy2(SOURCE, self.script)
        (self.work / 'domainNames.txt').write_text('ads.example.com\nads.example.com\ninvalid!\n')
        (self.work / 'IPAddresses.txt').write_text('192.0.2.1\n192.0.2.1\n198.51.100.2\n')

    def run_script(self, *args):
        return subprocess.run(['bash', str(self.script), *args], capture_output=True, text=True, timeout=10)

    def mock(self, expression):
        # Source the implementation without invoking its CLI. The root-check stub
        # applies only within this test subprocess; iptables is always a function.
        harness = '''source "$1"
requireRoot() { :; }
iptables() {
    printf 'MOCK iptables %s\\n' "$*"
    case "$1" in -C) return 1;; esac
}
iptables-save() { printf '*filter\\n:ADBLOCK - [0:0]\\nCOMMIT\\n'; }
iptables-restore() { printf 'MOCK restore %s\\n' "$*"; cat >/dev/null; }
''' + expression
        return subprocess.run(['bash', '-c', harness, 'test', str(self.script)],
                              capture_output=True, text=True, timeout=10)

    def test_syntax_help_and_invalid_cli(self):
        self.assertEqual(subprocess.run(['bash', '-n', str(self.script)]).returncode, 0)
        self.assertEqual(self.run_script('-help').returncode, 0)
        self.assertNotEqual(self.run_script('-unknown').returncode, 0)
        self.assertNotEqual(self.run_script().returncode, 0)

    def test_unprivileged_firewall_refused(self):
        self.assertNotEqual(os.geteuid(), 0)
        result = self.run_script('-ips')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('requires root', result.stderr)

    def test_mock_rules_are_scoped_destination_and_deduplicated(self):
        result = self.mock('configureIPs')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.count('-A ADBLOCK -d'), 2)
        self.assertIn('-F ADBLOCK', result.stdout)
        self.assertNotIn('-F OUTPUT', result.stdout)

    def test_invalid_or_empty_replacement_preserves_rules(self):
        for content in ('192.0.2.1\n999.0.0.1\n', ''):
            (self.work / 'IPAddresses.txt').write_text(content)
            result = self.mock('configureIPs')
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn('MOCK iptables', result.stdout)

    def test_reset_is_scoped(self):
        result = self.mock('resetRules')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('-X ADBLOCK', result.stdout)
        self.assertNotIn('-F OUTPUT', result.stdout)

    def test_mock_save_and_guarded_restore(self):
        result = self.mock('saveRules')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('COMMIT', (self.work / 'adblockRules').read_text())
        self.assertNotEqual(self.mock('loadRules').returncode, 0)
        result = self.mock('ADBLOCK_ALLOW_FULL_RESTORE=1; loadRules')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('MOCK restore --test', result.stdout)

    def test_fake_dns_atomic_deduplication(self):
        # Shell function overrides getent; no network lookup can occur.
        result = self.mock("getent() { printf '192.0.2.4 STREAM test\\n192.0.2.4 DGRAM test\\n'; }; resolveDomains")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.work / 'IPAddresses.txt').read_text(), '192.0.2.4\n')
        self.assertFalse(list(self.work.glob('*.tmp.*')))

if __name__ == '__main__':
    unittest.main()
