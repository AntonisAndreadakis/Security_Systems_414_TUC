monitor.c - A simple packet monitoring tool
-------------------------------------------
           Stavros Ntaountakis             
               2015030037
-------------------------------------------

Instructions: 

    1. $make : Builds the monitor.c file 
    2. $sudo ./monitor : Run file with sudo permissions (for live capture)
    3. Stop live capture and print statistics with `Ctrl + C`.

Theoretical questions:  

    - "Can you tell if an incoming TCP packet is a retransmission?"

        Yes we can tell by checking if the packets sequence number is less than
        the next expected sequence number in the same network flow. Also we need 
        to make sure that it is NOT a keep alive packet and that the segment 
        length is greater than zero or the SYN or FIN flag is set.

    - "Can you tell if an incoming UDP packet is a retransmission?"

        No we can not because UDP packets do not get retransmitted. If a UDP packet
        has a bad checksum then it gets dropped and no one gets "notified" that it 
        got dropped. Also UDP packets do not have a sequence number so we can not
        know if we got the packet that we expected or it got lost  

Implementation: 

