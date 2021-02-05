#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/md5.h>
#include <stdbool.h>
#include <pcap/pcap.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdint.h>

typedef long int loong;

//global variables to use when exiting the program
loong countUDP = 0;
loong countTCP = 0;
loong totalPackets = 0;                
loong retransmited = 0;
loong bytesUDP = 0;
loong bytesTCP = 0;
loong flowsUDP =0;
loong flowsTCP = 0;
loong unkwonw = 0;

struct sniff_ipv4 {
        u_char  
            hl : 4,
            version: 4;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};

#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)


struct sniff_ipv6{
    unsigned int
        traffic_class1 : 4,
        version : 4,
        traffic_class2 : 4,
        flow_label : 20;
    uint16_t length;
    uint8_t  next_header;
    uint8_t  hop_limit;
    struct in6_addr src;
    struct in6_addr dst;
};

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
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
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};


struct sniff_udp {
	u_short	uh_sport;		/* source port */
	u_short	uh_dport;		/* destination port */
	u_short	uh_ulen;		/* datagram length */
	u_short	uh_sum;			/* datagram checksum */
};

//list data structure
struct List{
    
    //data
    u_short sourcePort;               
    u_short destinationPort;   

    char* source;
    char* destination;
    
    uint8_t protocol;
    uint8_t sequence;
    
    struct List *next;
};

int check(struct List *cur, char* source, char* dst, u_short dport, u_short sport, uint8_t pcol);
void insert(struct List **list, char* src, char* dst, u_short sport, u_short dport, uint8_t pcol, uint8_t seq);
int checkRemaining(struct List *curr, char* src, char* dst, uint8_t pcol);
void ipVersion(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void ipv4packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet, struct sniff_ipv4 *ip);
void ipv6packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet, struct sniff_ipv6 *ip);
void printIP6(struct in6_addr *addr);
char* ipv6tochar(struct in6_addr *ipv6);
void usage(void);
void offlineMode(u_char* file);
void liveMode(char* dev);
struct List* flow = NULL;

int check(struct List *cur, char* src, char* dst, u_short dport, u_short sport, uint8_t pcol)
{
   if(cur == NULL) 
   {
      return 0;
   }

   while(cur != NULL) 
   {
        if(strcmp(cur->source, src) == 0 && strcmp(cur->destination, dst) == 0 && cur->sourcePort == sport && cur->destinationPort == dport && cur->protocol==pcol)
        {
            return 1;
        }
        else
            cur = cur->next;
    }
   
   	return 0;
}

void insert(struct List **list, char* src, char* dst, u_short sport, u_short dport, uint8_t pcol, uint8_t seq)
{   
   //like the last assignment
   struct List *newNode = malloc(sizeof(struct List));
    if (newNode == NULL){
        printf("Failed to allocate memory");
        exit(0);
    }
    newNode->source = malloc(strlen(src) *sizeof(char));
    strcpy(newNode->source,src);
    
    newNode->destination = malloc(strlen(dst) *sizeof(char));
    strcpy(newNode->destination , dst);
    
    newNode->sourcePort = sport;
    newNode->destinationPort = dport;
    newNode->protocol = pcol;
	newNode->sequence = seq;
	newNode->next = *list;
    *list = newNode;
}

int checkRemaining(struct List *curr, char* src, char* dst, uint8_t pcol)
{
   if(curr == NULL) {
      return 0;
   }

   while(curr != NULL)
   {
        if(strcmp(curr->source,src) == 0 && strcmp(curr->destination,dst) == 0 && curr->protocol == pcol)
        {
           
            return 1;
        }
        
        else
            curr = curr->next;
   	}

   	return 0;
}

void ipVersion(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	totalPackets += 1; //it's a packet so the total num must increase
	int version = packet[14] / 16;

	if(version == 4)
	{
		struct sniff_ipv4 *ip = (struct sniff_ipv4*)(packet + 14);
		ipv4packet(args,header,packet,ip);
		return;
	}

	if(version == 6)
	{
		struct sniff_ipv6 *ip = (struct sniff_ipv6*)(packet + 14);
		ipv6packet(args, header, packet, ip);
		return;
	}
}

void ipv4packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet, struct sniff_ipv4 *ip)
{
	int i=0;
	
	struct sniff_tcp *tcp;            
	char *payload;  

	struct sniff_udp *udp;

	unsigned int headerLenIp;

	int size_ip;
	int size_tcp;
	int size_udp;
	int size_payload;
	char buffer[255];

	printf("\n\n \n\n");

	size_ip = ip->hl*4;

	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}

	char *src = inet_ntoa(ip->ip_src);
	char *dst = inet_ntoa(ip->ip_dst);
	
	//find protocol
	printf("IP version is: %d\n",ip->version);
	printf("Source IP : %s\n", src);
	printf("Destination IP: %s\n", dst);

	switch(ip->ip_p) {
		
		case IPPROTO_TCP:
			
			countTCP++;
			
			tcp = (struct sniff_tcp*)(packet + 14 + size_ip);

			size_tcp = TH_OFF(tcp)*4;

			if (size_tcp < 20) {
				printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
				return;
			}

			if(!(check(flow,src,dst,(u_short)ntohs(tcp->th_sport), (u_short)ntohs(tcp->th_dport),IPPROTO_TCP))){
		
				flowsTCP++;
				insert(&flow,src,dst,(u_short)ntohs(tcp->th_sport), (u_short)ntohs(tcp->th_dport),IPPROTO_TCP,tcp->th_seq);

			}

			size_payload = htons(ip->ip_len) -(size_ip+size_tcp);
			bytesTCP +=  header->len;
			
			printf("Source port: %d\n", ntohs(tcp->th_sport));
			printf("Destination port: %d\n", ntohs(tcp->th_dport));
			printf("Protocol: TCP\n");
			printf("Total Packets: %ld\n", totalPackets);
			printf("Header Length: %d\n", size_tcp);
			printf("Total Packet length: %d\n",  header->len);
			printf("Payload size: %d bytes\n", size_payload);

			break;

		case IPPROTO_UDP:
			
			size_udp=8;
			countUDP++;
			udp = (struct sniff_udp*)(packet + 14 + size_ip);
			
			if(!(check(flow, src, dst, (u_short)ntohs(udp->uh_sport),(u_short)ntohs(udp->uh_dport),IPPROTO_UDP))){
				flowsUDP++;
				insert(&flow, src, dst, (u_short)ntohs(udp->uh_sport),(u_short)ntohs(udp->uh_dport),IPPROTO_UDP,0);
			}
			
			size_payload = htons(ip->ip_len) - (size_ip);
			bytesUDP += header->len;
			
			printf("Source port: %d\n", ntohs(udp->uh_sport));
			printf("Destination port: %d\n", ntohs(udp->uh_dport));
			printf("Protocol: UDP\n");
			printf("Total Packets: %ld\n", totalPackets);
			printf("Header Length: %d\n", size_udp);
			printf("Total Packet length: %d\n",  header->len);
			printf("Payload size : %d bytes\n", size_payload);

			break;

		default:
			printf("Protocol: unknown\n");

			if(!(checkRemaining(flow, src, dst, ip->ip_p)))
			{
				unkwonw++;
				insert(&flow, src, dst, 0, 0, ip->ip_p, 0);
			}

			return;
	}

	return;
}

void printIP6(struct in6_addr *addr)
{
	for (int i=0; i<16; i++)
	{
		printf("%02x",(int)addr->s6_addr[i]);
		
		if((i % 2) == 1)
		{
			if(i != 15)
			{
				printf(":");
			}
		}	
	}

	printf("\n");
	return;
}

char* ipv6tochar(struct in6_addr *ipv6)
{	
	char *tmp = malloc(40);  

	sprintf(tmp, "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
	
	(int)ipv6->s6_addr[0], (int)ipv6->s6_addr[1],
	(int)ipv6->s6_addr[2], (int)ipv6->s6_addr[3],
	(int)ipv6->s6_addr[4], (int)ipv6->s6_addr[5],
	(int)ipv6->s6_addr[6], (int)ipv6->s6_addr[7],
	(int)ipv6->s6_addr[8], (int)ipv6->s6_addr[9],
	(int)ipv6->s6_addr[10],(int)ipv6->s6_addr[11],
	(int)ipv6->s6_addr[12],(int)ipv6->s6_addr[13],
	(int)ipv6->s6_addr[14],(int)ipv6->s6_addr[15]);
	
	return tmp;
}

void ipv6packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet, struct sniff_ipv6 *ip)
{	
	int i=0;
	
	struct sniff_tcp *tcp;          
	struct sniff_udp *udp;

	int size_ip = 40;
	int size_tcp;
	int size_udp;
	int size_payload;
	char buffer[255];

	printf("\n\n \n\n");
	int version = packet[14] / 16;

	printf("ip version: %d\n",version); //we expect 6

	printf("Source ip : ");
	printIP6(&ip->src);
	printf("Destination ip: ");
	printIP6(&ip->dst);
	
	char *src = ipv6tochar(&ip->src);
	char *dst = ipv6tochar(&ip->dst);
	

	switch(ip->next_header)
	{
		case IPPROTO_TCP:
			
			countTCP++;
			tcp = (struct sniff_tcp*)(packet + 14 + size_ip);
			size_tcp = TH_OFF(tcp)*4;
			
			if (size_tcp < 20) {
				printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
				return;
			}

			if(!(check(flow, src, dst, (u_short)ntohs(tcp->th_sport), (u_short)ntohs(tcp->th_dport), IPPROTO_TCP))){
				flowsTCP++;
				insert(&flow, src, dst, (u_short)ntohs(tcp->th_sport), (u_short)ntohs(tcp->th_dport), IPPROTO_TCP, tcp->th_seq);
			}	
			size_payload = ntohs(ip->length);
			bytesTCP += header->len;
			
			printf("Source port: %d\n", ntohs(tcp->th_sport));
			printf("Destination port: %d\n", ntohs(tcp->th_dport));
			printf("Protocol: TCP\n");
			printf("Total Packets: %ld\n", totalPackets);
			printf("Header Length: %d\n", size_tcp);
			printf("Total Packet length: %d\n",  header->len);
			printf("Payload size: %d bytes\n", size_payload);

			break;

		case IPPROTO_UDP:
			countUDP++;
			size_udp = 8;


			udp = (struct sniff_udp*)(packet + 14 + size_ip);

			if(!(check(flow, src, dst, (u_short)ntohs(udp->uh_sport), (u_short)ntohs(udp->uh_dport), IPPROTO_UDP))){
				flowsUDP++;
				insert(&flow, src, dst, (u_short)ntohs(udp->uh_sport), (u_short)ntohs(udp->uh_dport), IPPROTO_UDP, 0);
			}
			
			size_payload = ntohs(ip->length);
			bytesUDP +=  header->len;
			
			printf("Source port: %d\n", ntohs(udp->uh_sport));
			printf("Destination port: %d\n", ntohs(udp->uh_dport));
			printf("Protocol: UDP\n");
			printf("Total Packets: %ld\n", totalPackets);
			printf("Header Length: %d\n", size_udp);
			printf("Total Packet length: %d\n",  header->len);
			printf("Payload size : %d bytes\n", size_payload);

			break;

		default:
			printf("Protocol: unknown\n");

			if(!(checkRemaining(flow, src, dst, ip->next_header)))
			{
				unkwonw++;
				insert(&flow, src, dst, 0, 0, ip->next_header, 0);
			}

			return;
	}
}

void usage(void)
{
	printf(
	       "\n"
	       "usage:\n"
	       "\t./monitor \n"
		   "Options:\n"
		   "-i Network interface name (e.g., eth0)\n"
		   "-r,Packet capture file name (e.g., test.pcap)\n"
		   "-h, Help message\n\n"
		   );

	exit(1);
}

void offlineMode(u_char* file)
{
	pcap_t *tmp;
    char buf[PCAP_ERRBUF_SIZE];
	int numOfPackets = -1;

	tmp = pcap_open_offline(file, buf);
    
    if (tmp == NULL)
    {
        printf("\nError with the opening of the dump file\n");
        exit(EXIT_FAILURE);
    }

    printf("Offline Mode: %s\n", file);
    pcap_loop(tmp, numOfPackets, ipVersion, NULL);

    printf("\n\n \n\n");
	loong totalFlows = flowsTCP + flowsUDP + unkwonw;

	printf("Total number of network flows captured: %ld\n",totalFlows);
	printf("Number of TCP network flows captured: %ld\n",flowsTCP);
	printf("Number of UDP network flows captured: %ld\n",flowsUDP);
	printf("Total number of Packets received: %ld\n",totalPackets);
	printf("Total number of TCP Packet: %ld\n",countTCP);
	printf("Total number of UDP Packet: %ld\n",countUDP);
	printf("Total bytes of TCP received: %ld\n",bytesTCP);
	printf("Total bytes of UDP received: %ld\n",bytesUDP);

	pcap_close(tmp);
	printf("\nExit program.\n");
}

void liveMode(char* dev)
{
	char buf[PCAP_ERRBUF_SIZE];		
	pcap_t *tmp;				

	u_char* filter_exp = "";		/* filter expression [3] */
	struct bpf_program fp;			
	
	bpf_u_int32 subnetMask;			
	bpf_u_int32 Ip;				

	int numOfPackets = 10000;			//packets to capture
	
	struct pcap_pkthdr header;	// header from pcap

	const u_char *packet;		//actual packet
	
	int tmp2 = pcap_lookupnet(dev, &Ip, &subnetMask, buf);

	if (tmp2 == -1) 
	{
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n",dev, buf);
		Ip = 0;
		subnetMask = 0;
	}

	/* print capture info */
	printf("Device: %s\n", dev);
	printf("Number of packets: %d\n", numOfPackets);
	printf("Filter expression: %s\n", filter_exp);

	/* open capture device */
	tmp = pcap_open_live(dev, BUFSIZ, 1, 1000, buf);
	
	if (tmp == NULL) 
	{
		fprintf(stderr, "Couldn't find device %s: %s\n", dev, buf);
		exit(EXIT_FAILURE);
	}

	if (pcap_datalink(tmp) != DLT_EN10MB) 
	{
		fprintf(stderr, "Device %s doesn't provide Ethernet headers.\n", dev);
		exit(EXIT_FAILURE);
	}
	
	//grab a packet
	packet = pcap_next(tmp, &header);
	
	//find the length
	printf("Length of packet [%d]\n", header.len);
	pcap_loop(tmp, numOfPackets, ipVersion, NULL);

    printf("\n\n \n\n");
	loong totalFlows = flowsTCP + flowsUDP + unkwonw;

	printf("Total number of network flows captured: %ld\n",totalFlows);
	printf("Number of TCP network flows captured: %ld\n",flowsTCP);
	printf("Number of UDP network flows captured: %ld\n",flowsUDP);
	printf("Total number of Packets received: %ld\n",totalPackets);
	printf("Total number of TCP Packet: %ld\n",countTCP);
	printf("Total number of UDP Packet: %ld\n",countUDP);
	printf("Total bytes of TCP received: %ld\n",bytesTCP);
	printf("Total bytes of UDP received: %ld\n",bytesUDP);

	pcap_close(tmp);
	printf("\nExit program.\n");
}

int main(int argc, char *argv[])
{

	int ch;
	char *dev = NULL;			 
	u_char *file = NULL;

	if (argc < 2)
	    usage();

	while ((ch = getopt(argc, argv, "h:i:r:")) != -1)
	{

		switch (ch) {		
		case 'i':
			dev=optarg;
			liveMode(dev);
			break;
		case 'r':
			file=optarg;
			offlineMode(file);
			break;
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;	
	return 0;
}
