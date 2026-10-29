"""Offline packet tests. No interfaces, sockets, or network access."""
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

BASE = Path(__file__).resolve().parent
def ethernet(payload, protocol=0x800):
    return b'\0' * 12 + struct.pack('!H', protocol) + payload
def ethernet_vlan(payload, protocol=0x800, tags=(0x8100,)):
    frame = b'\0' * 12
    for tpid in tags:
        frame += struct.pack('!HH', tpid, 0)  # TPID + a zero TCI
    return frame + struct.pack('!H', protocol) + payload
def udp(payload=b'abc', sport=1200):
    return struct.pack('!HHHH', sport, 53, len(payload) + 8, 0) + payload
def tcp(payload=b'abc', seq=100):
    return struct.pack('!HHIIBBHHH', 1200, 80, seq, 0, 5 << 4, 0x18, 1024, 0, 0) + payload
def ipv4(payload, protocol=17, options=b'', fragment=0):
    return struct.pack('!BBHHHBBH4s4s', 0x45 + len(options)//4, 0,
                       20 + len(options) + len(payload), 0, fragment, 64, protocol, 0,
                       b'\xc0\x00\x02\x01', b'\xc0\x00\x02\x02') + options + payload
def ipv6(payload, protocol=17):
    return struct.pack('!IHBB16s16s', 6 << 28, len(payload), protocol, 64,
                       bytes.fromhex('20010db8000000000000000000000001'),
                       bytes.fromhex('20010db8000000000000000000000002')) + payload
def pcap(frames, linktype=1):
    out = struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype)
    for frame in frames:
        out += struct.pack('<IIII', 0, 0, len(frame), len(frame)) + frame
    return out

class MonitorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'fixture.pcap'

    def run_capture(self, frames, linktype=1):
        self.path.write_bytes(pcap(frames, linktype))
        return subprocess.run([str(BASE / 'monitor'), '-r', str(self.path)],
                              capture_output=True, text=True, timeout=20)

    def test_ipv4_ipv6_options_flows_and_retransmit(self):
        frames = [ethernet(ipv4(tcp(), 6)), ethernet(ipv4(tcp(), 6)),
                  ethernet(ipv4(udp(), options=b'\x01'*4)),
                  ethernet(ipv6(udp()), 0x86dd),
                  ethernet(ipv6(bytes([17, 0]) + bytes(6) + udp(), 0), 0x86dd),
                  ethernet(b'\0'*28, 0x806)]
        result = self.run_capture(frames)
        self.assertEqual(result.returncode, 0, result.stderr)
        out = result.stdout
        for line in ('Total number of network flows captured: 3',
                     'Number of TCP network flows captured: 1',
                     'Number of UDP network flows captured: 2',
                     'Total number of packets received: 6',
                     'Total number of TCP packets received: 2',
                     'Total number of UDP packets received: 3',
                     f'Total bytes of TCP packets received: {sum(map(len,frames[:2]))}',
                     f'Total bytes of UDP packets received: {sum(map(len,frames[2:5]))}'):
            self.assertIn(line + '\n', out)
        self.assertEqual(out.count('Retransmitted'), 1)
        self.assertEqual(out.count('header=8 payload=3'), 3)

    def test_vlan_and_qinq_tags(self):
        # A plain 802.1Q frame (one tag) and a QinQ frame (outer 0x88a8 +
        # inner 0x8100 tag) must both decode through to the IPv4/UDP payload.
        frames = [ethernet_vlan(ipv4(udp()), tags=(0x8100,)),
                  ethernet_vlan(ipv4(udp()), tags=(0x88a8, 0x8100))]
        result = self.run_capture(frames)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('Total number of packets received: 2\n', result.stdout)
        self.assertIn('Total number of UDP packets received: 2\n', result.stdout)
        self.assertIn('Total number of network flows captured: 1\n', result.stdout)

    def test_truncated_malformed_fragmented_frames(self):
        valid = ethernet(ipv4(udp()))
        frames = [valid[:n] for n in range(len(valid))]
        frames += [ethernet(ipv4(udp(), fragment=0x2000)),
                   ethernet(ipv4(b'\0'*8)),
                   ethernet(ipv6(bytes([17, 99]) + bytes(6), 0), 0x86dd)]
        result = self.run_capture(frames)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('Total number of network flows captured: 0\n', result.stdout)
        self.assertIn(f'Total number of packets received: {len(frames)}\n', result.stdout)

    def test_invalid_cli_and_files(self):
        for args in ([], ['-r','missing.pcap'], ['-r','missing','-i','unused'], ['-x']):
            result = subprocess.run([str(BASE/'monitor'), *args], capture_output=True, timeout=5)
            self.assertNotEqual(result.returncode, 0)
        self.assertEqual(subprocess.run([str(BASE/'monitor'), '-h'], capture_output=True).returncode, 0)
        self.assertNotEqual(self.run_capture([], 101).returncode, 0)
        self.path.write_bytes(b'bad pcap')
        self.assertNotEqual(subprocess.run([str(BASE/'monitor'), '-r', str(self.path)], capture_output=True).returncode, 0)

    def test_supplied_capture_total(self):
        data = (BASE / 'test_pcap_5mins.pcap').read_bytes()
        endian = '<' if data[:4] in (b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1') else '>'
        offset, count = 24, 0
        while offset < len(data):
            self.assertGreaterEqual(len(data)-offset, 16)
            caplen = struct.unpack_from(endian + 'IIII', data, offset)[2]
            offset += 16 + caplen
            self.assertLessEqual(offset, len(data))
            count += 1
        result = subprocess.run([str(BASE/'monitor'), '-r', str(BASE/'test_pcap_5mins.pcap')],
                                capture_output=True, text=True, timeout=40)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f'Total number of packets received: {count}\n', result.stdout)
        print(f'Independently counted supplied capture: {count} packets')

if __name__ == '__main__':
    unittest.main()
