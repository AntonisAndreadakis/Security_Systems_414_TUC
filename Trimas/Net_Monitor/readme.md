Christos Trimas
Assignment No.6
2016030054

Monitoring the network traffic using the Packet Capture library:

To compile the program:

	$gcc monitor.c -lpcap -o monitor

	or

	make all 

To run the program on a precaptured file like the one that was given:

	$./monitor -r <name_of_file>

To run the program on your own device first locate your device by running:

	$cat /proc/net/wireless

Then:
	
	$(sudo if neeeded) ./monitor -i <name_of_device>

The part of retransmission was not implemented. For UDP packages there is no retransmission. The flow is defined as the number of, different, 5-tuples I am capturing.