#!/usr/bin/env python3
"""Assignment 6: bounds-checked Python Ethernet/IPv4/IPv6 TCP/UDP monitor.

Offline classic PCAP needs only Python. Live capture is Linux-only, opt-in, and
never attempts to acquire privileges. No packet contents are transmitted.
"""
import argparse
from collections import Counter
import contextlib
from dataclasses import dataclass
import io
import ipaddress
from pathlib import Path
import socket
import struct
import sys
import tempfile
import unittest

MAX_FRAME = 16 * 1024 * 1024
MAX_FLOWS = 65536

def pcap_packets(path):
    with Path(path).open('rb') as stream:
        header = stream.read(24)
        if len(header) != 24: raise ValueError('Truncated PCAP header')
        magic = header[:4]
        if magic in (b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1'): endian = '<'
        elif magic in (b'\xa1\xb2\xc3\xd4', b'\xa1\xb2\x3c\x4d'): endian = '>'
        else: raise ValueError('Expected classic PCAP, not PCAPNG or arbitrary data')
        major,minor,_,_,snaplen,link = struct.unpack(endian+'HHIIII',header[4:])
        if (major,minor) != (2,4) or link & 0xffff != 1: raise ValueError('Only PCAP 2.4 Ethernet captures are supported')
        if not 1 <= snaplen <= MAX_FRAME: raise ValueError('Invalid snapshot length')
        while True:
            record = stream.read(16)
            if not record: return
            if len(record) != 16: raise ValueError('Truncated packet record header')
            _,_,captured,wire = struct.unpack(endian+'IIII',record)
            if captured > min(snaplen,MAX_FRAME) or captured > wire: raise ValueError('Invalid captured packet length')
            frame = stream.read(captured)
            if len(frame) != captured: raise ValueError('Truncated packet record data')
            yield frame,wire

def be16(data,offset): return struct.unpack_from('!H',data,offset)[0]

@dataclass(frozen=True)
class Packet:
    version: int
    protocol: int
    source: str
    destination: str
    sport: int
    dport: int
    header: int
    payload: int
    sequence: int = 0
    flags: int = 0
    @property
    def flow(self): return (self.source,self.sport,self.destination,self.dport,self.protocol)

def decode(data):
    """Return a TCP/UDP packet or None; malformed/fragmented frames are skipped."""
    if len(data) < 14: return None
    kind,offset = be16(data,12),14
    tags = 0
    while kind in (0x8100,0x88a8):
        if tags == 2 or len(data)-offset < 4: return None
        kind = be16(data,offset+2); offset += 4; tags += 1
    if kind == 0x800:
        if len(data)-offset < 20 or data[offset] >> 4 != 4: return None
        ihl,total = (data[offset]&15)*4,be16(data,offset+2)
        if ihl < 20 or total < ihl or total > len(data)-offset: return None
        if be16(data,offset+6) & 0x3fff: return None
        version,proto = 4,data[offset+9]
        source,dest = data[offset+12:offset+16],data[offset+16:offset+20]
        end = offset+total; offset += ihl
    elif kind == 0x86dd:
        if len(data)-offset < 40 or data[offset] >> 4 != 6: return None
        length = be16(data,offset+4)
        if length == 0 or length > len(data)-offset-40: return None
        version,proto = 6,data[offset+6]
        source,dest = data[offset+8:offset+24],data[offset+24:offset+40]
        end = offset+40+length; offset += 40
        extensions = 0
        while proto in (0,43,60,51):
            if extensions == 16 or end-offset < 2: return None
            size = (data[offset+1]+2)*4 if proto == 51 else (data[offset+1]+1)*8
            if size < 8 or size > end-offset: return None
            proto = data[offset]; offset += size; extensions += 1
        if proto == 44: return None  # No fragment reassembly.
    else: return None
    remaining = end-offset
    sequence=flags=0
    if proto == 6:
        if remaining < 20: return None
        header = (data[offset+12] >> 4)*4
        if header < 20 or header > remaining: return None
        payload = remaining-header
        sequence = struct.unpack_from('!I',data,offset+4)[0]; flags=data[offset+13]
    elif proto == 17:
        if remaining < 8: return None
        length = be16(data,offset+4)
        if length < 8 or length > remaining: return None
        header,payload = 8,length-8
    else: return None
    return Packet(version,proto,str(ipaddress.ip_address(source)),str(ipaddress.ip_address(dest)),
                  be16(data,offset),be16(data,offset+2),header,payload,sequence,flags)

def before(left,right): return ((left-right) & 0xffffffff) >= 0x80000000

class Monitor:
    def __init__(self): self.stats,self.flows = Counter(),{}
    def accept(self,data,wire):
        self.stats['packets'] += 1
        packet = decode(data)
        if packet is None: self.stats['skipped'] += 1; return None,False
        protocol = 'tcp' if packet.protocol == 6 else 'udp'
        key=packet.flow
        if key not in self.flows:
            if len(self.flows) >= MAX_FLOWS: raise ValueError('Flow table limit exceeded')
            self.flows[key] = None; self.stats[protocol+'_flows'] += 1
        self.stats[protocol+'_packets'] += 1; self.stats[protocol+'_bytes'] += wire
        retransmitted=False
        if packet.protocol == 6:
            span = packet.payload + bool(packet.flags&2) + bool(packet.flags&1)
            if span:
                expected = self.flows[key]
                retransmitted = expected is not None and before(packet.sequence,expected)
                end = (packet.sequence+span) & 0xffffffff
                if expected is None or before(expected,end): self.flows[key] = end
        return packet,retransmitted
    def summary(self):
        return dict(self.stats,flows=len(self.flows))

def live_packets(interface):
    if not hasattr(socket,'AF_PACKET'): raise ValueError('Live capture requires Linux AF_PACKET')
    with socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3)) as capture:
        capture.bind((interface,0))
        while True:
            data = capture.recv(65535)
            yield data,len(data)

def write_fixture(path,frames,endian='<'):
    with Path(path).open('wb') as out:
        out.write(struct.pack(endian+'IHHIIII',0xa1b2c3d4,2,4,0,0,65535,1))
        for data in frames: out.write(struct.pack(endian+'IIII',0,0,len(data),len(data))+data)

class Tests(unittest.TestCase):
    @staticmethod
    def frame(proto=17,version=4,options=False):
        transport = (struct.pack('!HHHH',1000,53,11,0)+b'abc' if proto == 17 else
                     struct.pack('!HHIIBBHHH',1000,80,100,0,0x50,0x18,1024,0,0)+b'abc')
        if version == 4:
            extra = b'\x01'*4 if options else b''
            ip=struct.pack('!BBHHHBBH4s4s',0x45+len(extra)//4,0,20+len(extra)+len(transport),0,0,64,proto,0,
                           b'\xc0\0\2\1',b'\xc0\0\2\2')+extra+transport
        else:
            extension=bytes([proto,0])+bytes(6) if options else b''
            ip=struct.pack('!IHBB16s16s',6<<28,len(extension)+len(transport),0 if options else proto,64,
                           bytes.fromhex('20010db8000000000000000000000001'),
                           bytes.fromhex('20010db8000000000000000000000002'))+extension+transport
        return bytes(12)+struct.pack('!H',0x800 if version==4 else 0x86dd)+ip
    def test_headers_flows_and_retransmission(self):
        monitor=Monitor()
        frames=[self.frame(6),self.frame(6),self.frame(options=True),self.frame(version=6,options=True)]
        marks=[monitor.accept(f,len(f))[1] for f in frames]
        self.assertEqual(marks,[False,True,False,False])
        self.assertEqual(monitor.summary(),{'packets':4,'tcp_flows':1,'tcp_packets':2,
            'tcp_bytes':sum(map(len,frames[:2])),'udp_flows':2,'udp_packets':2,
            'udp_bytes':sum(map(len,frames[2:])),'flows':3})
        self.assertEqual(decode(frames[2]).payload,3)
        self.assertEqual(decode(frames[3]).header,8)
    def test_truncated_frames_and_records(self):
        data=self.frame()
        for n in range(len(data)): self.assertIsNone(decode(data[:n]))
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'capture'
            for endian in ('<','>'):
                write_fixture(path,[data],endian)
                self.assertEqual(list(pcap_packets(path)),[(data,len(data))])
            path.write_bytes(path.read_bytes()[:-1])
            with self.assertRaises(ValueError): list(pcap_packets(path))
    def test_sample_and_flow_direction(self):
        path=Path(__file__).with_name('test_pcap_5mins.pcap')
        monitor=Monitor(); count=0
        for frame,wire in pcap_packets(path): monitor.accept(frame,wire); count+=1
        self.assertEqual(count,14261)
        self.assertEqual(monitor.stats['packets'],14261)
        self.assertGreater(monitor.stats['tcp_flows'],0)
        self.assertGreater(monitor.stats['udp_flows'],0)
        print('Sample capture:',monitor.summary())
    def test_flow_limit_reports_statistics_before_exit(self):
        # Matches the C version: statistics are printed even when a run ends
        # in an error, here the flow table limit, not only on a clean exit.
        global MAX_FLOWS
        frames=[self.frame(6),self.frame(17)]
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'capture'
            write_fixture(path,frames)
            saved=MAX_FLOWS; MAX_FLOWS=1
            try:
                buffer=io.StringIO()
                with contextlib.redirect_stdout(buffer):
                    with self.assertRaises(SystemExit) as cm: main(['-r',str(path)])
                self.assertEqual(cm.exception.code,1)
                self.assertIn('packets: 2',buffer.getvalue())
            finally: MAX_FLOWS=saved

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    mode=parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('-r',type=Path); mode.add_argument('-i',metavar='INTERFACE')
    mode.add_argument('--self-test',action='store_true')
    parser.add_argument('--allow-live-capture',action='store_true',help='explicit opt-in after separate approval; no privilege escalation')
    parser.add_argument('--summary-only',action='store_true')
    parser.add_argument('--count',type=int,default=0,help='stop after this many packets; 0 means all')
    args=parser.parse_args(argv)
    if args.self_test:
        return 0 if unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Tests)).wasSuccessful() else 1
    if args.count < 0: parser.error('--count cannot be negative')
    if args.i and not args.allow_live_capture: parser.error('Live capture needs separate approval and --allow-live-capture')
    monitor=Monitor()
    try:
        source=pcap_packets(args.r) if args.r else live_packets(args.i)
        for data,wire in source:
            packet,retransmitted=monitor.accept(data,wire)
            if packet and not args.summary_only:
                print(f'IPv{packet.version} {"TCP" if packet.protocol==6 else "UDP"} '
                      f'{packet.source}:{packet.sport} -> {packet.destination}:{packet.dport} '
                      f'header={packet.header} payload={packet.payload}' + (' Retransmitted (heuristic)' if retransmitted else ''))
            if args.count and monitor.stats['packets'] >= args.count: break
    except KeyboardInterrupt: pass
    except (OSError,ValueError) as error: parser.exit(1,f'Error: {error}\n')
    finally:
        # Always print the statistics (as the C version always does), even on
        # an error exit: parser.exit() raises SystemExit, which would
        # otherwise skip them if they were printed only after the try block.
        if 'source' in locals(): source.close()
        for key in ('flows','tcp_flows','udp_flows','packets','tcp_packets','udp_packets','tcp_bytes','udp_bytes','skipped'):
            print(f'{key}: {monitor.summary().get(key,0)}')
    return 0

if __name__ == '__main__': sys.exit(main())
