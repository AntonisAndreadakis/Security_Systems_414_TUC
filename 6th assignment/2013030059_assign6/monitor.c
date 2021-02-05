#include <stdio.h>	//standard C stuffs
#include <stdlib.h>	//malloc
#include <stdint.h>
#include <string.h>	//strlen
#include <stdarg.h>
#include <ctype.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>	//error code

#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>		//main sockets header
#include <netdb.h>
#include <ifaddrs.h>

#include <pcap.h>
#include <net/ethernet.h>
#include <arpa/inet.h>			//for inet_ntoa()
#include <netinet/in.h>			//internet protocol family
#include <netinet/if_ether.h>		//ethernet header declarations
#include <net/ethernet.h>		//ethernet fundamental constants
#include <netinet/ether.h>		//ethernet header declarations
#include <netinet/tcp.h>		//tcp header declarations
#include <netinet/udp.h>		//udp header declarations
#include <netinet/ip_icmp.h>		//icmp header declarations
#include <netinet/icmp6.h>		//icmpv6 header declarations
#include </usr/include/netinet/ip.h>	//ipv4 protocols
#include </usr/include/netinet/ip6.h>	//ipv6 protocols
#include </usr/include/pcap/pcap.h>	//pcap library
#include <signal.h>
#include <linux/types.h>


/* Global Variables */ 
int packet_counter = 0, p = 0;
int tcp = 0;
int udp = 0;
int others = 0;
/* Declare IPv6 Source and Destination Address Variables */
char sourceIp6[INET6_ADDRSTRLEN];
char destIp6[INET6_ADDRSTRLEN];

struct packet {
	int src_port; //src port
	int dest_port; //destination port
	int is_retransmission;
	int header_len;
	int payload_len;
	char *src_ip; //src ip.
	char *dest_ip;//destination ip.	
	uint8_t protocol; //packet's protocol
	unsigned int ip_version; // IPv4 or v6.
};
struct net_flow{
	int currseq_num;
	int nextexp_seq_num;
	char *src_ip;
	char *dest_ip;
	uint8_t protocol;
	uint16_t src_port;
	uint16_t dest_port;
	struct net_flow *next;
};
struct net_flow *flows = NULL;
struct tcp_struct {
        u_short th_sport;	//src port
        u_short th_dport;   //dest port
        tcp_seq th_seq;     //seq. number
        tcp_seq th_ack;     //ack. num
        u_char  th_offx2;   // data off. [reserved]
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;  //window
        u_short th_sum;  //checksum
        u_short th_urp;  //urgent
};

/*	function to find available interfaces	*/
void list_interface(){
	struct ifaddrs *addresses;
	if(getifaddrs(&addresses) == -1){
		printf("getifaddrs call failed!\n");
		exit(-1);
		}
	struct ifaddrs *address = addresses;
	while(address){
		int family = address->ifa_addr->sa_family;
		if(family == AF_INET || family == AF_INET6){
			printf("%s\t", address->ifa_name);
			printf("%s\t", family == AF_INET ? "IPv4" : "IPv6");
			char ap[100];
			const int family_size = family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
			getnameinfo(address->ifa_addr,family_size, ap, sizeof(ap), 0, 0, NI_NUMERICHOST);
			printf("\t%s\n", ap);
			}
		address = address->ifa_next;
		}
	freeifaddrs(addresses);
}

/*	this function implements payload process inside every packet process:	*/
void print_line(const u_char * data , int Size){
	int i, j;
	for(i=0 ; i < Size ; i++){
		if( i!=0 && i%16==0){   //if one line of hex printing is complete
			printf("         ");
			for(j=i-16 ; j<i ; j++){
				if(data[j]>=32 && data[j]<=128)
					printf("%c",(unsigned char)data[j]); //if it's a number or alphabet
				else printf("."); //otherwise print a dot
				}
			printf("\n");
			}//end if-statement
		if(i%16==0) printf("   ");
		printf(" %02X",(unsigned int)data[i]);
		if( i==Size-1){  //print the last spaces
			for(j=0;j<15-i%16;j++) {
				printf("   "); //extra spaces
			}//end for-loop
			printf("         ");
			for(j=i-i%16 ; j<=i ; j++){
				if(data[j]>=32 && data[j]<=128){
					printf("%c",(unsigned char)data[j]);
					}
				else
					printf(".");
				}//end for-loop
			printf("\n\n" );
			}//end if-statement
		}//end of first for-loop
}


/* Function to handle TCP Headers */
void Handle_TCP (const u_char* packet, int* size){	
	/* Initialise TCP header structure */      
	const struct tcphdr* tcp_header;
	u_int sourcePort, destPort;
	u_char *data;
	tcp_header = (struct tcphdr*)(packet + *size);
	int dataLength = 0;
	
	/* Get the source and destination ports from the TCP header */
	sourcePort = ntohs(tcp_header->source);
	destPort = ntohs(tcp_header->dest);
	/* Initialise the data pointer to point to the data carryed by the TCP and Initialise dataLength to the length of the data */
	*size+=tcp_header->doff*4;
	data = (u_char*)(packet + *size);
	dataLength = p - *size;
	/* Print the TCP header infomation and payload */
	printf("\tProtocol: TCP\n");
	printf("\tSource Port: %d\n", sourcePort);
	printf("\tDestination Port: %d\n", destPort);
	printf("Checksum: %d\n", ntohs(tcp_header->check));
	printf("Payload(%d bytes): \n", dataLength);
	/* Print the packet contents */
	print_line(data , dataLength);
}

/* Function to handle UDP Headers */
void Handle_UDP (const u_char* packet, int* size){
	/* Initialize UDP header structure */      
	const struct udphdr* udp_header;
	u_int sourcePort, destPort;
	u_char *data;
	udp_header = (struct udphdr*)(packet + *size);
	int dataLength = 0;
	
	/* Get the source and destination ports from the UDP header */
	sourcePort = ntohs(udp_header->source);
	destPort = ntohs(udp_header->dest);
	/* Initialise the data pointer to point to the data carried by the UDP and Initialize dataLength to the length of the data */
	*size+=sizeof(struct udphdr);
	data = (u_char*)(packet + *size);
	dataLength = p - *size;
	/* Print the TCP header infomation and payload */
	printf("\tProtocol: UDP\n");
	printf("\tSource Port: %d\n", sourcePort);
	printf("\tDestination Port: %d\n", destPort);
	printf("\tPayload(%d bytes): \n", dataLength);
	/* Print the packet contents */
	print_line(data , dataLength);	
}

void printIPV4header(char* source, char* dest){
	printf("******************************************************************************\n");
	printf("Packet Number: %d\n", packet_counter);
	printf("\tIP version: IPv4\n");
	printf("\tSource IP: %s\n", source);
	printf("\tDestination IP: %s\n", dest);
}

void printIPV6Header(){
	printf("\n******************************************************************************\n");
	printf("Packet Number: %d\n",packet_counter);
	printf("\tIP_Version: IPV6\n");
	printf("\tSource IP: %s\n", sourceIp6);
	printf("\tDestination IP: %s\n", destIp6);
	printf("\tExtension Headers:");
}
void Handle_ICMPV6(const u_char* packet, int* size){
	printf("\n");
	printf("\tProtocol: ICMP\n");
	u_char *data;
	int dataLength = 0;
	struct icmp6_hdr* header_icmp6 = (struct icmp6_hdr*)(packet+*size);
	data = (u_char*)(packet + *size + sizeof(struct icmp6_hdr));
  	dataLength = p - *size + sizeof(struct icmp6_hdr); 
  	printf("Payload(%d bytes):\n", dataLength);
	print_line(data, dataLength);
	printf("******************************************************************************\n");
}
	/* Handle IPV6 Headers */
void IPV6_HANDLER(int hrd, int size, const u_char* packet, char* string){
	//char *ret = (p->is_retransmission == 1) ? "RETRANSMITTED" : "NO-RETRANSMITTED";
	switch(hrd){
	case IPPROTO_ROUTING:  /* Routing Header */
		strcat(string, "ROUTING, ");
		struct ip6_rthdr* header = (struct ip6_rthdr*)(packet + size); 
		size+=sizeof(struct ip6_rthdr);
		IPV6_HANDLER(header->ip6r_nxt, size, packet, string);
		break;
	case IPPROTO_HOPOPTS:  /* Hop-by-Hop options */
		strcat(string, "HOP-BY_HOP, ");
		struct ip6_hbh* header_hop = (struct ip6_hbh*)(packet + size); 
		size+=sizeof(struct ip6_hbh);
		IPV6_HANDLER(header_hop->ip6h_nxt, size, packet, string);
		break;
	case IPPROTO_FRAGMENT: /* Fragmentation header(FRAGMENT) */
		strcat(string, "FRAGMENTATION, ");
		struct ip6_frag* header_frag = (struct ip6_frag*)(packet + size); 
		size+=sizeof(struct ip6_frag);
		IPV6_HANDLER(header_frag->ip6f_nxt, size, packet, string);
		break;
	case IPPROTO_DSTOPTS:  /* Destination options(DSTOPTS) */
		strcat(string, "Destination options, ");
		struct ip6_dest* header_dest = (struct ip6_dest*)(packet + size); 
		size+=sizeof(struct ip6_dest);
		IPV6_HANDLER(header_dest->ip6d_nxt, size, packet, string);
		break;
	case IPPROTO_TCP:      /* TCP PROTOCOL */
		printIPV6Header();
		printf("%s\n", string);
		Handle_TCP (packet, &size);
		
		++tcp;
		break;
	case IPPROTO_UDP:      /* UDP PROTOCOL */
		printIPV6Header();
		printf("%s\n", string);
		Handle_UDP (packet, &size);
		
		++udp;
		break;
	case IPPROTO_ICMPV6:     /* ICMP6*/
		printIPV6Header();
		printf("%s\n", string);
		Handle_ICMPV6(packet, &size);
		break;
	default:
		printIPV6Header();
		printf("Unknown header(%d),", hrd);  /* Unknown Header */
		++others;
		break;
	} 
}
	/*	function to handle packet	*/
void process_packet(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet){
	/* Link Layer - declare Ethernet Header */
	const struct ether_header* ethernet_header;
	/* declare IPv4 Headers */
	const struct ip* ip_header;
	const struct udphdr* udp_header;
	const struct icmphdr* icmp_header;
	/* declare Source and Destination IPv4 Address Variables */
	char sourceIp[INET_ADDRSTRLEN];
	char destIp[INET_ADDRSTRLEN];
	/* declare IPv6 Headers */
	const struct ip6_hdr* ip6_header;
	  	
	p = pkthdr->len;
	packet_counter++;  //increase packet counter
	
	/* Initialize Ethernet Structure */
	ethernet_header = (struct ether_header*)packet;
	int size = 0;
	size+=sizeof(struct ether_header);
	//char *ret = (p->is_retransmission == 1) ? "RETRANSMITTED" : "NO-RETRANSMITTED";

	// IPV4 Header:
	if (ntohs(ethernet_header->ether_type) == ETHERTYPE_IP) {	
		ip_header = (struct ip*)(packet + size);
		inet_ntop(AF_INET, &(ip_header->ip_src), sourceIp, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, &(ip_header->ip_dst), destIp, INET_ADDRSTRLEN);
		size+=sizeof(struct ip);
		u_char *data;
		int dataLength = 0;
		switch(ip_header->ip_p) {
			// Transmission Control Protocol (TCP):
			case IPPROTO_TCP:
				printIPV4header(sourceIp, destIp);
				Handle_TCP(packet, &size);
				
				printf("******************************************************************************\n");
				++tcp;
				break;
			// UDP:
			case IPPROTO_UDP:
				printIPV4header(sourceIp, destIp);
				Handle_UDP(packet, &size);
				
				printf("******************************************************************************\n");
				++udp;
				break;
			// Internet Control Message Protocol (ICMP):
			case IPPROTO_ICMP:
				printIPV4header(sourceIp, destIp);
				printf("\tProtocol: ICMP\n");
				icmp_header = (struct icmphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
				u_int type = icmp_header->type;
				if(type == 11){
					printf("TTL Expired\n");
					}
				else if(type == ICMP_ECHOREPLY){
   					printf("ICMP Echo Reply\n");
		  			}
				data = (u_char*)(packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct icmphdr));
				dataLength = pkthdr->len - (sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct icmphdr)); 
				printf("Code: %d\n", (unsigned int)(icmp_header->code));
				printf("Checksum: %d\n", ntohs(icmp_header->checksum));
				printf("Payload(%d bytes):\n", dataLength);
				print_line(data, dataLength);
				printf("******************************************************************************\n");
				break;
			// skip others:
			default:
				printf("\tOTHER\n");
				printf("******************************************************************************\n");
				++others;
				break;
			}//end of switch operation
		}//end of IPv4 check
	//IPV6 Header:
	else if (ntohs(ethernet_header->ether_type) == ETHERTYPE_IPV6) {
		ip6_header = (struct ip6_hdr*)(packet + size); 
		inet_ntop(AF_INET6, &(ip6_header->ip6_src), sourceIp6, INET6_ADDRSTRLEN);
		inet_ntop(AF_INET6, &(ip6_header->ip6_dst), destIp6, INET6_ADDRSTRLEN);
		int nexthdr = ip6_header->ip6_nxt;
		size+=sizeof(struct ip6_hdr);
		char string[100] = " ";
		IPV6_HANDLER(nexthdr, size, packet, string);
		printf("******************************************************************************\n");
		}//end of IPv6 check
	//ARP Header:
	else if (ntohs(ethernet_header->ether_type) == ETHERTYPE_ARP && !userData) {
		const struct ether_arp* arp_header;
		arp_header = (struct ether_arp*)(packet+size);
		printf("\t%s\n",(ntohs(arp_header->arp_op) == ARPOP_REQUEST)? "ARP Request" : "ARP Reply");
		printf("******************************************************************************\n");
	}//end of ARP check

	//any other, skip:
	else if (!userData) {
		printf("\tOTHER\n");
		}
	printf("******************************************************************************\n");
	printf("\nTotal number of network flows captured: %d\n", tcp+udp+others);
	printf("\nNumber of TCP network flows captured: %d\n", tcp);
	printf("\nNumber of UDP network flows captured: %d\n", udp);
	printf("\nTotal number of packets received: %d\n", packet_counter);
	printf("******************************************************************************\n");
}

	
	/*	here we check for duplicates-retransmittion	*/
int is_retransmission(struct net_flow *head_flow, struct packet *p,const struct tcp_struct *tcp, int payload_size){
	//cache global stuff..
	struct net_flow *curr_flow = head_flow;
	while(curr_flow != NULL){
	//Be sure that flows are identical
		if ((strcmp(curr_flow->src_ip, p->src_ip) == 0) && (strcmp(curr_flow->dest_ip, p->dest_ip) == 0) && (curr_flow->src_port == p->src_port) && (curr_flow->dest_port == p->dest_port) && (curr_flow->protocol == p->protocol)){
			//"Keep alives" are different thing than retransmission
			if ((payload_size <= 1) && ((tcp->th_flags & TH_SYN) || (tcp->th_flags & TH_FIN) || (tcp->th_flags & TH_RST)) && ((ntohl(tcp->th_seq) - curr_flow->nextexp_seq_num) == -1))
				return 0; 
			//That's a retransmission though in terms of TCP
			if (((payload_size > 0) || (tcp->th_flags & TH_SYN) || (tcp->th_flags & TH_FIN)) && ((curr_flow->nextexp_seq_num) > ntohl(tcp->th_seq)) ){
				//mark the actor packet.
				p->is_retransmission = 1;
				return 1; 
				} 
			}
		//move on..
		curr_flow = curr_flow->next;
		}
	//no retransmission found:
	return 0;
}




/*	how to use program	*/
void usage(void){
	printf("\n");
	printf("Before you start using this tool, please check available interfaces:\n");
	list_interface();
	printf("\n"	"usage:\n"	"./monitor \n"
		"Options:\n"
		"-i <interface name>,		Use Network interface for sniffing.\n"
		"-r <filename>,			Print packets captured in file.\n"
		"-h,				Help message.\n\n");
	exit(1);
}


int main(int argc, char* argv[]){
	int ch;
	int timeout = 0;
	int flag_live_capture=0, flag_offline_parse=0;
	/* file to process */
	const char* filename=NULL;
	/* capture device name */
	const char *interface;
	// Select a protocol filter
	char errbuf[PCAP_ERRBUF_SIZE];
	// Open capture file
	pcap_t *descr;

	//bpf_u_int32 mask;		/* Our netmask */
	//bpf_u_int32 net;		/* Our IP */


	/* Check command line arguments */
	if (argc < 2 || argc > 3)
		usage();
	while ((ch = getopt(argc, argv, "i:r:h")) != -1) {
		switch(ch) {
		case 'i':
			interface = optarg;
			flag_live_capture = 1;
			break;
		case 'r':
			filename  = optarg;
			flag_offline_parse = 1;
			break;
		default:
			printf("Please provide valid arguments.\n");
			usage();
		}		
	} 
	//check option '-i':
	if(flag_live_capture == 1){
		/* Define the device */
		interface = pcap_lookupdev(errbuf);
		if(interface == NULL) {
			fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
			return(2);
			}
		if(interface){
			printf("Listening on %s... \n", interface);
			/* open capture device */
			descr = pcap_open_live(interface, BPF_LEN, 1, timeout, errbuf);
			if(descr == NULL) {
				fprintf(stderr, "Couldn't open device %s: %s\n", interface, errbuf);
				return(2);
				}
			}
		}
	//check option '-r':
	else if(flag_offline_parse == 1){
		if(filename){
			descr = pcap_open_offline(filename, errbuf);
			if(descr == NULL){
				printf("Name of file was: %s\n", filename);
				printf("Error, : %s\n", errbuf);
				}
			else
				printf("Reading from file  %s... \n", filename);
			}
		}
	else{
		return 1;
		}
	/* Find the properties for the device */
	//if (pcap_lookupnet(interface, &net, &mask, errbuf) == -1) {
	//	fprintf(stderr, "Couldn't get netmask for device %s: %s\n", interface, errbuf);
	//	net = 0;
	//	mask = 0;
	//	}
	/* make sure we're capturing on an Ethernet device [2] */
	if (pcap_datalink(descr) != DLT_EN10MB) {
		fprintf(stderr, "%s is not an Ethernet\n", interface);
		return(2);
		}
	
	//pcap loop to set our callback function: start packet processing loop, just like live capture
	if (pcap_loop(descr, 0, process_packet, NULL) < 0) {
		//cout << "pcap_loop() failed: " << pcap_geterr(descr);
		printf("\n******************************************************************************\n");
		printf("pcap_loop() failed!\n");
		return 1;
	}
	else{
		printf("\n******************************************************************************\n");
		printf("Loop succeded!\n");
		}
	if(flag_live_capture==1 && flag_offline_parse==1){
		printf("\n\n Unexpected arguments entered: You can't capture live traffic and parse offline pcap file at the same time!!\n\n");
		return 1;
		}

	printf("Complete!\n");
	argc -= optind;
	argv += optind;
	return 0;
}    
