# Assignment 6 - Offline network monitor

Andreadakis Antonios - 2013030059

## Python version (current entry point)

`assignment.py` requires only Python 3.11+. Offline parsing does not need
libpcap or a compiler. Supports classic PCAP (both endiannesses and microsecond/
nanosecond magic), Ethernet, up to two VLAN tags, IPv4 options, IPv6 extensions,
TCP/UDP flow accounting, and a TCP sequence-overlap heuristic.

```sh
python assignment.py --self-test
python assignment.py -r test_pcap_5mins.pcap --summary-only
```

Three tests passed. The supplied capture produced 14,261 packets, 941 TCP
flows, 264 UDP flows, 13,708 TCP packets, 501 UDP packets, and 52 skipped frames.
TCP/UDP frame-byte totals were 9,135,182 / 75,353. Truncated records fail clearly;
malformed frames and fragments are skipped. PCAPNG and fragment reassembly
are not supported.

The Linux live mode requires `-i INTERFACE --allow-live-capture` after separate
approval. It uses AF_PACKET, never escalates privileges, and has not been tested.
Default offline use performs no network operations.

```powershell
powershell -NoProfile -File sandbox/run.ps1 -Assignment 6 -Python
```

## Earlier C/shell validation status

The repaired monitor passed a strict C11 build with warnings treated as errors
and four offline test cases in Docker. The supplied capture was independently
counted as **14,261 packets**, matching the monitor's total.

Live interface capture has not been tested or approved. No root access,
interface changes, or live sniffing were attempted.

## Updates

- Uses libpcap, with checked capture-open failures and preserved interface choice.
- Validates captured lengths before reading headers; decodes multibyte fields
  without unaligned structure casts.
- Handles IPv4 header options, IPv6 extension lengths, and a VLAN tag.
- Tracks directional five-tuple flows separately from packet counts.
- Reports TCP/UDP header and payload sizes, packet totals, byte totals, and flows.
- Connects TCP sequence tracking to a retransmission indicator.
- Adds `test_monitor.py` with synthetic malformed and valid captures.

## Build and use

Requires Linux, a C11 compiler, Make, libpcap development files, and Python 3.

```sh
make
make check
./monitor -h
./monitor -r test_pcap_5mins.pcap
```

Preferred isolated test from the testing workspace:

```powershell
powershell -NoProfile -File sandbox/run.ps1 -Assignment 6
```

The CLI also implements `-i INTERFACE`, but this mode is outside the approved
test scope. No privilege acquisition is performed by the program.

## Verified coverage

IPv4/IPv6 TCP and UDP, IPv4 options, an IPv6 extension, duplicate flows,
retransmission indication, invalid arguments, missing/invalid capture files,
unsupported link types, malformed/truncated frames, fragments, and the supplied
capture's total packet count. Total packets include skipped frames.

## Interpretation and limits

Flows are directional source/destination addresses, ports, and protocol.
TCP/UDP byte totals use on-wire frame lengths for successfully decoded packets.
Non-TCP/UDP, malformed/truncated, and fragmented packets are skipped for
transport statistics; fragmentation is not reassembled. Only Ethernet link
captures are supported; IPv6 jumbograms are not supported.

TCP sequence overlap is a heuristic: reordered traffic can resemble a
retransmission. UDP retransmission cannot be inferred generally from its header.
The bounded flow table holds 65,536 flows; exceeding it reports an error.
The suite is not an exhaustive packet-parser fuzzing or live-capture validation.
	
