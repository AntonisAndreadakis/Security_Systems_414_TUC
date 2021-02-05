Andreadakis Antonios - 2013030059 - LAB41446117


## Description:

In this assignment, we developed a Network traffic monitoring tool, using the Packet Capture library.
Using libcap, we capture packets as they come off a network card. A network card is the interface
used from hardware (our PC) and communicates with network. We can either monitor the traffic live
from our interface (using pcap_open_live() function) or read a pcap file (using pcap_open_offline() ).
More specifically, we capture network traffic and proccess the TCP and UDP packets (without using
pcap_compile() or pcap_setfilter() ).


## Modes:

`monitor.c`	:	opens interface for packet capturing, or read data from file


## Running:

make						->BUILD 
sudo ./monitor -i ens33				->run interface in monitor mode for sniffing
./monitor -r filename				->run monitor for specific file


## Notes:

	-Executing on previleged user(root) is recommended.

	-My implementation supports an extra functionality. Function list_interface() prints
	all available interfaces from hardware. It is used in usage() function, in order to
	inform user for available interfaces.

	-TCP supports duplicate detection by default and we don't have to check duplicates.

	-UDP has no build-in duplicate detection, so any kind of such detection has to be
	done by the application itself. The only way to interact with the send queue, is to
	send datagrams. Any kind of duplicate detection on the sender side, has to be done
	before the packet gets into the send-queue. So, in order to figure out if there is
	a duplicate packet to a previous that was not supposed to be sent or just a duplicate
	which was sent because the original got lost, we need to specify a timeout/delay. This
	could be implemented using timers or similar. I did not implement all of that kind of
	functionality, due to limited time. But, you can find a function named `is_retransmission`
	which is exactly for this purpose and could be used for markering.

	-Statistics are printed as asked in the assignment.
	

