"""Regression tests for the Python planner using only inert local fakes."""
import subprocess
from pathlib import Path
import tempfile
import unittest

import assignment


class FirewallFake:
    """Small iptables state model; it never invokes a process or the network."""

    def __init__(self, existing=None, fail_on=None):
        self.chains={name:list(rules) for name,rules in (existing or {}).items()}
        self.jumps=[]
        self.calls=[]
        self.fail_on=fail_on

    def __call__(self,args,check=True):
        self.calls.append(list(args))
        op=args[1]
        if self.fail_on and self.fail_on(args):
            return subprocess.CompletedProcess(args,1,'','injected failure')
        rc=0
        if op=='-nL': rc=0 if args[2] in self.chains else 1
        elif op=='-N':
            if args[2] in self.chains: rc=1
            else: self.chains[args[2]]=[]
        elif op=='-A': self.chains[args[2]].append(args[3:])
        elif op=='-C': rc=0 if args[-1] in self.jumps else 1
        elif op=='-I': self.jumps.insert(0,args[-1])
        elif op=='-D':
            try: self.jumps.remove(args[-1])
            except ValueError: rc=1
        elif op=='-E':
            old,new=args[2],args[3]
            if old not in self.chains or new in self.chains: rc=1
            else:
                self.chains[new]=self.chains.pop(old)
                self.jumps=[new if item==old else item for item in self.jumps]
        elif op=='-F':
            if args[2] not in self.chains: rc=1
            else: self.chains[args[2]]=[]
        elif op=='-X':
            if args[2] not in self.chains or args[2] in self.jumps: rc=1
            else: del self.chains[args[2]]
        return subprocess.CompletedProcess(args,rc,'','')


class Assignment7RegressionTests(unittest.TestCase):
    def test_failed_staging_keeps_existing_rules(self):
        old=[['-d','192.0.2.9','-j','REJECT']]
        fake=FirewallFake({assignment.CHAIN:old},
                          lambda args: args[1]=='-A' and args[4]=='192.0.2.2')
        fake.jumps=[assignment.CHAIN]
        with self.assertRaises(subprocess.CalledProcessError):
            assignment.install(['192.0.2.1','192.0.2.2'],fake)
        self.assertEqual(fake.chains,{assignment.CHAIN:old})
        self.assertEqual(fake.jumps,[assignment.CHAIN])

    def test_successful_install_swaps_complete_chain(self):
        fake=FirewallFake({assignment.CHAIN:[['old']]})
        fake.jumps=[assignment.CHAIN]
        assignment.install(['198.51.100.2','192.0.2.1'],fake)
        self.assertEqual(fake.jumps,[assignment.CHAIN])
        self.assertEqual(set(fake.chains),{assignment.CHAIN})
        self.assertEqual(fake.chains[assignment.CHAIN],[
            ['-d','192.0.2.1','-j','REJECT'],
            ['-d','198.51.100.2','-j','REJECT'],
        ])

    def test_switch_failure_rolls_back_existing_chain(self):
        old=[['-d','192.0.2.9','-j','REJECT']]
        fake=FirewallFake({assignment.CHAIN:old},
                          lambda args: args[1]=='-E' and args[2]==assignment.STAGING_CHAIN)
        fake.jumps=[assignment.CHAIN]
        with self.assertRaises(subprocess.CalledProcessError):
            assignment.install(['192.0.2.1'],fake)
        self.assertEqual(fake.chains,{assignment.CHAIN:old})
        self.assertEqual(fake.jumps,[assignment.CHAIN])

    def test_post_commit_cleanup_failure_keeps_new_rules_active(self):
        fake=FirewallFake({assignment.CHAIN:[['old']]},
                          lambda args: args[1]=='-X' and args[2]==assignment.BACKUP_CHAIN)
        fake.jumps=[assignment.CHAIN]
        with self.assertRaisesRegex(ValueError,'New rules are active'):
            assignment.install(['192.0.2.1'],fake)
        self.assertEqual(fake.jumps,[assignment.CHAIN])
        self.assertEqual(fake.chains[assignment.CHAIN],
                         [['-d','192.0.2.1','-j','REJECT']])

    def test_stale_transaction_chains_stop_before_mutation(self):
        fake=FirewallFake({assignment.CHAIN:[],assignment.STAGING_CHAIN:[]})
        with self.assertRaises(ValueError): assignment.install(['192.0.2.1'],fake)
        self.assertFalse(any(call[1] in ('-N','-A','-F','-E') for call in fake.calls))

    def test_reads_reject_symlinks_and_oversized_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            target=root/'target'; target.write_text('ads.example.com\n',encoding='utf-8')
            link=root/'domains'
            try: link.symlink_to(target)
            except OSError: self.skipTest('symlinks unavailable')
            with self.assertRaises(ValueError): assignment.domains(link)
            large=root/'large'; large.write_bytes(b'x'*(assignment.MAX_INPUT_BYTES+1))
            with self.assertRaises(ValueError): assignment.domains(large)

    def test_atomic_write_refuses_symlink_destination(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            target=root/'target'; target.write_text('unchanged',encoding='utf-8')
            link=root/'output'
            try: link.symlink_to(target)
            except OSError: self.skipTest('symlinks unavailable')
            with self.assertRaises(ValueError): assignment.atomic_write(link,'changed')
            self.assertEqual(target.read_text(encoding='utf-8'),'unchanged')

    def test_fake_dns_limit_is_enforced_while_resolving(self):
        generated=(f'192.0.{index // 256}.{index % 256}' for index in range(assignment.LIMIT+1))
        with self.assertRaises(ValueError): assignment.resolve(['ads.example.com'],lambda _:generated)


if __name__=='__main__':
    unittest.main()
