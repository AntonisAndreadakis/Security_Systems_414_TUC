CC = gcc
DBUG = -g
CCFLAGS = -O2 -Wall -pedantic 
PCAP = -lpcap 


TARGETS = monitor


all: $(TARGETS)

monitor: monitor.c
	$(CC) $(CCFLAGS) $(DBUG) -o $@ $< $(PCAP) -lm
	
clean:
	rm -f $(TARGETS)
