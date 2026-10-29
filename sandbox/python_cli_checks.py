"""End-to-end checks of all eight Python command-line entry points.

Runs after run.py has created /work/project1 through project8. All output paths
belong to this test's TemporaryDirectory. No privileged or destructive modes.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

class CommandLineTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.work=Path(self.temp.name)
    def run_cli(self,number,*args,input=None,ok=True):
        result=subprocess.run([sys.executable,f'/work/project{number}/assignment.py',*map(str,args)],
                              cwd=self.work,input=input,capture_output=True,timeout=20)
        if ok: self.assertEqual(result.returncode,0,result.stderr.decode(errors='replace'))
        else: self.assertNotEqual(result.returncode,0)
        return result
    def test_1_demo(self):
        result=self.run_cli(1,'demo',input=b'secret\nhello\n4\nATTACKATDAWN\nLEMON\n')
        self.assertIn(b'[OTP] input: secret',result.stdout)
        self.assertIn(b'[OTP] decrypted: secret',result.stdout)
        self.assertIn(b'[Caesars] input: hello',result.stdout)
        self.assertIn(b'[Caesars] key: 4',result.stdout)
        self.assertIn(b'[Vigenere] input: ATTACKATDAWN',result.stdout)
        self.assertIn(b'[Vigenere] key: LEMON',result.stdout)
        self.assertIn(b'[Vigenere] encrypted: LXFOPVEFRNHR',result.stdout)
        # Non-alphabet characters are skipped, not rejected.
        result=self.run_cli(1,'demo',input=b'sec!ret\nbad!\n1\nATTACKATDAWN\nLEMON\n')
        self.assertIn(b'[OTP] input: sec!ret',result.stdout)
        self.assertIn(b'[OTP] decrypted: secret',result.stdout)
        self.assertIn(b'[Caesars] decrypted: bad!',result.stdout)
    def test_2_file_workflow_and_failed_verify(self):
        source,password=self.work/'input',self.work/'password'
        source.write_bytes(bytes(range(256))); password.write_text('test\n')
        signed,out=self.work/'signed',self.work/'out'
        self.run_cli(2,'-s','-i',source,'-o',signed,'-b',256,'--password-file',password)
        self.run_cli(2,'-v','-i',signed,'-o',out,'-b',256,'--password-file',password)
        self.assertEqual(source.read_bytes(),out.read_bytes())
        data=bytearray(signed.read_bytes());data[-1]^=1;signed.write_bytes(data)
        refused=self.work/'refused'
        self.run_cli(2,'-v','-i',signed,'-o',refused,'-b',256,'--password-file',password,ok=False)
        self.assertFalse(refused.exists())
    def test_3_keygen_roundtrip(self):
        keys=self.work/'keys';keys.mkdir()
        self.run_cli(3,'-g','--key-directory',keys)
        source,encrypted,plain=self.work/'input',self.work/'cipher',self.work/'out'
        source.write_bytes(bytes(range(256)))
        self.run_cli(3,'-e','-i',source,'-o',encrypted,'-k',keys/'public.key')
        self.run_cli(3,'-d','-i',encrypted,'-o',plain,'-k',keys/'private.key')
        self.assertEqual(source.read_bytes(),plain.read_bytes())
        self.run_cli(3,'-g','--key-directory',keys,ok=False)
    def test_4_demo_and_report(self):
        directory=self.work/'demo'
        self.run_cli(4,'--demo',directory)
        result=self.run_cli(4,'--log',directory/'file_logging.log','-i',directory/'example.bin')
        self.assertIn(f'{os.getuid()}\t2'.encode(),result.stdout)
        self.run_cli(4,'--demo',directory,ok=False)
    def test_5_simulation_threshold_and_gate(self):
        directory=self.work/'simulation'
        self.run_cli(5,'--simulate',directory,'--count',2)
        for threshold,expected in [(4,b'yes'),(5,b'no')]:
            result=self.run_cli(5,'--log',directory/'file_logging.log','-v',threshold)
            self.assertIn(b'Threshold reached: '+expected,result.stdout)
        result=self.run_cli(5,'--log',directory/'file_logging.log','-e')
        self.assertEqual(len(result.stdout.splitlines()),3)
        blocked=self.work/'blocked'
        self.run_cli(5,'--lab',blocked,ok=False)
        self.assertFalse(blocked.exists())
    def test_6_offline_and_live_gate(self):
        result=self.run_cli(6,'-r','/work/project6/test_pcap_5mins.pcap','--summary-only')
        self.assertIn(b'packets: 14261\n',result.stdout)
        self.assertIn(b'flows: 1205\n',result.stdout)
        self.run_cli(6,'-i','not-an-interface',ok=False)
    def test_7_plans_state_and_apply_gate(self):
        (self.work/'domainNames.txt').write_text('ads.example.com\n')
        (self.work/'IPAddresses.txt').write_text('192.0.2.1\n192.0.2.1\n')
        result=self.run_cli(7,'-domains','--data-directory',self.work)
        self.assertFalse(json.loads(result.stdout)['network_used'])
        plan=json.loads(self.run_cli(7,'-ips','--data-directory',self.work).stdout)
        self.assertEqual(plan['addresses'],['192.0.2.1'])
        self.run_cli(7,'-save','--data-directory',self.work)
        restored=json.loads(self.run_cli(7,'-load','--data-directory',self.work).stdout)
        self.assertEqual(restored,plan)
        self.run_cli(7,'-ips','--data-directory',self.work,'--apply',ok=False)
    def test_8_model_and_metadata(self):
        self.assertIn(b'Hello Alice',self.run_cli(8,'--greet','Alice').stdout)
        self.assertEqual(json.loads(self.run_cli(8,'--inspect').stdout)['elf_bits'],32)
        data=b'A'*48+bytes.fromhex('88776655')
        result=json.loads(self.run_cli(8,'--simulate-hex',data.hex()).stdout)
        self.assertTrue(result['return_overwritten']);self.assertFalse(result['executed'])

if __name__=='__main__': unittest.main(verbosity=2)
