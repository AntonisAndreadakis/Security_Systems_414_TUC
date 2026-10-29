#!/usr/bin/env python3
"""Assignment 7: Python ad-block rule planner with explicitly gated application.

Default operations print plans. No sudo, elevation, DNS, or firewall calls are
made unless the corresponding --allow-network or --apply option is selected.
Saved state is this project's IPv4 blocklist, never a full host firewall dump.
"""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile
import unittest

CHAIN = 'ADBLOCK'
STAGING_CHAIN = 'ADBLOCK_NEXT'
BACKUP_CHAIN = 'ADBLOCK_OLD'
LIMIT = 10000
MAX_INPUT_BYTES = 2 * 1024 * 1024


def read_text(path):
    """Read a small regular file without following a final-component symlink."""
    path = Path(path)
    try:
        info = path.lstat()
    except FileNotFoundError:
        raise ValueError(f'File does not exist: {path}') from None
    if path.is_symlink() or not path.is_file():
        raise ValueError(f'Expected a regular, non-symlink file: {path}')
    if info.st_size > MAX_INPUT_BYTES:
        raise ValueError(f'Input file exceeds {MAX_INPUT_BYTES} bytes: {path}')
    return path.read_text(encoding='utf-8')

def domains(path):
    result = set()
    for line in read_text(path).splitlines():
        value = line.split('#',1)[0].strip().rstrip('.').lower()
        if not value: continue
        if len(value)>253 or '.' not in value or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',label) for label in value.split('.')):
            raise ValueError(f'Invalid domain: {value}')
        result.add(value)
        if len(result)>LIMIT: raise ValueError('Domain count exceeds limit')
    if not result: raise ValueError('Empty domain list')
    return sorted(result)

def addresses(values):
    result=set()
    for value in values:
        value=value.split('#',1)[0].strip()
        if not value: continue
        result.add(str(ipaddress.IPv4Address(value)))
        if len(result)>LIMIT: raise ValueError('Address count exceeds limit')
    if not result: raise ValueError('Empty IPv4 list; existing rules are unchanged')
    return sorted(result,key=ipaddress.IPv4Address)

def resolve(names,resolver=None):
    resolver=resolver or (lambda name: [row[4][0] for row in socket.getaddrinfo(name,None,socket.AF_INET)])
    found=set()
    for name in names:
        for value in resolver(name):
            found.add(str(ipaddress.IPv4Address(value)))
            if len(found)>LIMIT: raise ValueError('Address count exceeds limit')
    return addresses(found)

def atomic_write(path,text):
    path=Path(path)
    if not path.parent.is_dir():
        raise ValueError(f'Output directory does not exist: {path.parent}')
    if path.exists() and (path.is_symlink() or not path.is_file()):
        raise ValueError(f'Refusing to replace a non-regular or symlink path: {path}')
    descriptor,name=tempfile.mkstemp(prefix=path.name+'.',dir=path.parent)
    try:
        with os.fdopen(descriptor,'w',encoding='utf-8') as out:
            out.write(text)
            out.flush()
            os.fsync(out.fileno())
        os.replace(name,path)
    finally:
        if os.path.exists(name): os.unlink(name)

def plan(values):
    values=addresses(values)
    return {'chain':CHAIN,'staging_chain':STAGING_CHAIN,'addresses':values,
            'strategy':'build staging chain, switch OUTPUT, retain rollback until commit',
            'commands':[['iptables','-N',STAGING_CHAIN]]+
            [['iptables','-A',STAGING_CHAIN,'-d',ip,'-j','REJECT'] for ip in values]}

def command(args,check=True):
    return subprocess.run(args,check=check,capture_output=True,text=True,timeout=10)


def _run(runner,args,check=True):
    result=runner(args,check=check)
    if check and result.returncode:
        raise subprocess.CalledProcessError(result.returncode,args,result.stdout,result.stderr)
    return result


def _chain_exists(runner,name):
    return _run(runner,['iptables','-nL',name],check=False).returncode==0


def _jump_exists(runner,name):
    return _run(runner,['iptables','-C','OUTPUT','-j',name],check=False).returncode==0


def _discard_chain(runner,name):
    """Best-effort cleanup used only for a newly created staging chain."""
    for _ in range(100):
        if not _jump_exists(runner,name): break
        if _run(runner,['iptables','-D','OUTPUT','-j',name],check=False).returncode: break
    _run(runner,['iptables','-F',name],check=False)
    _run(runner,['iptables','-X',name],check=False)


def install(values,runner=command):
    """Replace project rules through a staged chain, with best-effort rollback."""
    values=addresses(values)  # Validate everything before the first firewall call.
    old_exists=_chain_exists(runner,CHAIN)
    if _chain_exists(runner,STAGING_CHAIN) or _chain_exists(runner,BACKUP_CHAIN):
        raise ValueError('A previous staged update needs manual inspection; no rules were changed')

    stage_created=False
    stage_attached=False
    old_jumps=0
    old_renamed=False
    stage_renamed=False
    committed=False
    try:
        _run(runner,['iptables','-N',STAGING_CHAIN]); stage_created=True
        for ip in values:
            _run(runner,['iptables','-A',STAGING_CHAIN,'-d',ip,'-j','REJECT'])

        if old_exists:
            _run(runner,['iptables','-I','OUTPUT','1','-j',STAGING_CHAIN]); stage_attached=True
            while _jump_exists(runner,CHAIN):
                if old_jumps>=100: raise ValueError('Too many existing chain jumps; update cancelled')
                _run(runner,['iptables','-D','OUTPUT','-j',CHAIN]); old_jumps+=1
            _run(runner,['iptables','-E',CHAIN,BACKUP_CHAIN]); old_renamed=True
        _run(runner,['iptables','-E',STAGING_CHAIN,CHAIN]); stage_renamed=True
        if not stage_attached:
            _run(runner,['iptables','-I','OUTPUT','1','-j',CHAIN])
        committed=True
        if old_renamed:
            # The new chain is active at this point. Failure to remove the backup is
            # reported, but must not trigger a destructive rollback of active rules.
            try:
                _run(runner,['iptables','-F',BACKUP_CHAIN])
                _run(runner,['iptables','-X',BACKUP_CHAIN])
            except (OSError,subprocess.SubprocessError) as error:
                raise ValueError(
                    f'New rules are active, but {BACKUP_CHAIN} cleanup failed; '
                    'inspect it before the next update') from error
    except Exception:
        if committed:
            # The complete replacement is already active. Keep it active rather
            # than risk restoring a backup that may have been partly cleaned.
            raise
        if stage_renamed:
            # If the replacement is active, only a still-intact backup permits rollback.
            if old_renamed and _chain_exists(runner,BACKUP_CHAIN):
                _run(runner,['iptables','-E',CHAIN,STAGING_CHAIN],check=False)
                _run(runner,['iptables','-E',BACKUP_CHAIN,CHAIN],check=False)
                for _ in range(old_jumps):
                    _run(runner,['iptables','-I','OUTPUT','1','-j',CHAIN],check=False)
                _discard_chain(runner,STAGING_CHAIN)
            elif not old_exists:
                _discard_chain(runner,CHAIN)
        else:
            if old_renamed:
                _run(runner,['iptables','-E',BACKUP_CHAIN,CHAIN],check=False)
            if stage_attached:
                _run(runner,['iptables','-D','OUTPUT','-j',STAGING_CHAIN],check=False)
            for _ in range(old_jumps):
                _run(runner,['iptables','-I','OUTPUT','1','-j',CHAIN],check=False)
            if stage_created:
                _discard_chain(runner,STAGING_CHAIN)
        raise

def reset(runner=command):
    for _ in range(100):
        if runner(['iptables','-C','OUTPUT','-j',CHAIN],check=False).returncode: break
        runner(['iptables','-D','OUTPUT','-j',CHAIN])
    else: raise ValueError('Too many chain jumps; stopped after 100 removals')
    if runner(['iptables','-nL',CHAIN],check=False).returncode==0:
        runner(['iptables','-F',CHAIN]); runner(['iptables','-X',CHAIN])

def save_state(path,values):
    atomic_write(path,json.dumps({'version':1,'chain':CHAIN,'addresses':addresses(values)},indent=2)+'\n')

def load_state(path):
    data=json.loads(read_text(path))
    if not isinstance(data,dict) or set(data)!= {'version','chain','addresses'} or data['version']!=1 or data['chain']!=CHAIN:
        raise ValueError('Invalid project state file')
    if not isinstance(data['addresses'],list) or not all(isinstance(x,str) for x in data['addresses']):
        raise ValueError('Invalid address array')
    return addresses(data['addresses'])

class Tests(unittest.TestCase):
    def test_domain_and_fake_dns(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'domains'; path.write_text('ADS.EXAMPLE.COM\nads.example.com\n#comment\n')
            self.assertEqual(domains(path),['ads.example.com'])
            self.assertEqual(resolve(domains(path),lambda _:['192.0.2.1','192.0.2.1']),['192.0.2.1'])
            path.write_text('a;touch bad')
            with self.assertRaises(ValueError): domains(path)
    def test_validation_before_mock_commands(self):
        calls=[]
        def mock(args,check=True):
            calls.append(args)
            return subprocess.CompletedProcess(args,1 if args[1] in ('-C','-nL') else 0,'','')
        for value in ([],['999.1.1.1'],['::1'],['192.0.2.1;echo bad']):
            with self.assertRaises(ValueError): install(value,mock)
        self.assertEqual(calls,[])
        install(['192.0.2.2','192.0.2.2'],mock)
        self.assertEqual(sum(args[1]=='-A' for args in calls),1)
        self.assertIn(['iptables','-A',STAGING_CHAIN,'-d','192.0.2.2','-j','REJECT'],calls)
        self.assertNotIn(['iptables','-F','OUTPUT'],calls)
    def test_state_roundtrip_and_rejection(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'state.json'
            save_state(path,['192.0.2.5','192.0.2.1'])
            self.assertEqual(load_state(path),['192.0.2.1','192.0.2.5'])
            path.write_text('{"version":1,"chain":"OUTPUT","addresses":["192.0.2.1"]}')
            with self.assertRaises(ValueError): load_state(path)
    def test_reset_is_scoped(self):
        calls=[]
        def mock(args,check=True):
            calls.append(args)
            return subprocess.CompletedProcess(args,1 if args[1]=='-C' else 0,'','')
        reset(mock)
        self.assertIn(['iptables','-X',CHAIN],calls)
        self.assertTrue(all(args[2]==CHAIN for args in calls if args[1] in ('-F','-X')))

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    mode=parser.add_mutually_exclusive_group(required=True)
    for flag in ('domains','ips','save','load','list','reset'):
        mode.add_argument('-'+flag,dest='mode',action='store_const',const=flag)
    mode.add_argument('--self-test',action='store_true'); mode.add_argument('-help',action='help')
    base=Path(__file__).resolve().parent
    if not (base/'domainNames.txt').exists(): base=base.parent
    parser.add_argument('--data-directory',type=Path,default=base)
    parser.add_argument('--state-file',type=Path,help='default: adblockRules.json in data directory')
    parser.add_argument('--allow-network',action='store_true')
    parser.add_argument('--apply',action='store_true',help='separately approved firewall actions; never escalates privileges')
    args=parser.parse_args(argv)
    if args.self_test:
        return 0 if unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Tests)).wasSuccessful() else 1
    try:
        if args.apply:
            if args.mode not in ('ips','load','list','reset'): raise ValueError('--apply is only for firewall modes')
            if not hasattr(os,'geteuid') or os.geteuid()!=0:
                raise ValueError('Firewall permission unavailable; no elevation attempted')
        directory=args.data_directory
        state=args.state_file or directory/'adblockRules.json'
        if args.mode=='domains':
            names=domains(directory/'domainNames.txt')
            if args.allow_network:
                ips=resolve(names); atomic_write(directory/'IPAddresses.txt','\n'.join(ips)+'\n')
                print(f'Resolved {len(names)} names to {len(ips)} addresses')
            else: print(json.dumps({'dns_plan':names,'network_used':False},indent=2))
        elif args.mode in ('ips','save','load'):
            ips=load_state(state) if args.mode=='load' else addresses(read_text(directory/'IPAddresses.txt').splitlines())
            if args.mode=='save': save_state(state,ips); print('Saved project blocklist:',state)
            elif args.apply: install(ips); print('Applied project chain')
            else: print(json.dumps(plan(ips),indent=2))
        elif args.mode=='reset':
            if args.apply: reset()
            else: print(json.dumps({'reset_plan':{'detach':'OUTPUT -> '+CHAIN,'delete_chain':CHAIN}}))
        elif args.mode=='list':
            if args.apply: print(command(['iptables','-S',CHAIN]).stdout,end='')
            else: print(json.dumps({'list_plan':['iptables','-S',CHAIN]}))
    except (OSError,ValueError,subprocess.SubprocessError) as error: parser.exit(1,f'Error: {error}\n')
    return 0

if __name__=='__main__': sys.exit(main())
