#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <time.h>
#include <signal.h>
#include <unistd.h>

#define LENGTH_ETHERNET 14
#define ETHER_ADDR_LEN	6
#define LENGTH_UDP_H 8
#define NETWORKTYPE_IPV6 34525 //"86DD" 

struct ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

struct ip_struct {
        u_char  ip_vhl;                 /* version (4) header length (2) */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* don't fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

struct ipv6_struct {
    uint ip_vtf;                        /* Version(4) Traffic(8) Flow(20) */
    u_short ip_len;                     /* payload length */
    u_char ip_p;                        /* Next header (protocol) */
    u_char ip_hlim;                     /* Hop limit */
    struct in_addr ip_src,ip_dst;       /* Source and dest address */ 
}; 


typedef u_int tcp_seq;

struct tcp_struct {
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

struct udp_struct {
        u_short uh_sport;               /* source port */
        u_short uh_dport;               /* destination port */
        u_short uh_ulen;                /* udp length */
        u_short uh_sum;                 /* udp checksum */
};

typedef struct network_flow {
    char ip_src[16]; 
    char ip_dst[16];
    u_short port_src; 
    u_short port_dst; 
    u_char protocol; 

    unsigned int current_seq_number; 
    unsigned int next_expected_seq_number;

}netflow; 

int check_retransmission(netflow *flow, const struct ip_struct *ip, const struct tcp_struct *tcp, int size_payload, int length);
int flow_update(netflow *flow, const struct ip_struct *ip, const struct tcp_struct *tcp, int size_payload, int length);
int flow_update_udp(netflow *flow, const struct ip_struct *ip, const struct udp_struct *udp, int length);
void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void terminate_loop(int signum);
void print_table();

pcap_t *traffic;

void
usage(void)
{
	printf(
	       "\n"
	       "usage:\n"
	       "\t./monitor \n"
		   "Options:\n"
		   "-i <network_interface>, Live captures packets from provided network interface\n"
		   "-r <.pcap filename>, Offline captures from provided .pcap file\n"
		   "-h, Help message\n\n"
		   );

	exit(1);
}

int main(int argc, char *argv[])
{
    char errbuf[PCAP_ERRBUF_SIZE];
    const char* device;
    int snaplen = 65535; // Max number of bytes to capture 
    int promisc = 1;  
    int to_ms = 1000; // Read timeout in msec  
    int ch; 

    if (argc < 2)
		usage();

    while ((ch = getopt(argc, argv, "hi:r:")) != -1) {
		switch (ch) {		
		case 'i':
			device = optarg; 
            traffic = pcap_open_live(device, snaplen, promisc, to_ms, errbuf);
            if (traffic == NULL)
            {
                printf("pcap_open_live : %s\n", errbuf);
                exit(2);
            }
			break;
		case 'r':
			traffic = pcap_open_offline(optarg, errbuf);
            if (traffic == NULL)
            {
                printf("pcap_open_live : %s\n", errbuf);
                exit(2);
            }
			break;
		default:
			usage();
		}

	}
    
    if (pcap_datalink(traffic) != DLT_EN10MB)
    {
        fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", device);
		exit(2);
    }
    
    signal(SIGINT, terminate_loop);
    pcap_loop(traffic, -1, process_packet, NULL);
    
    process_packet(NULL, NULL, NULL);
    pcap_close(traffic);
    return 0;


}

void terminate_loop(int signum)
{
    pcap_breakloop(traffic);
}

void
process_packet(u_char *args, const struct pcap_pkthdr *header,const u_char *packet)
{
    static int count_packets = 0;
    static int count_packets_TCP = 0;
    static int count_packets_UDP = 0;
    static int init_flag = 1;
    static int count_flows = 0;
    static int count_flows_TCP = 0;
    static int count_flows_UDP = 0;
    static int count_bytes_TCP = 0;
    static int count_bytes_UDP = 0; 
    const struct ethernet *ethernet; 
	const struct ip_struct *ip;
    const struct ipv6_struct *ipv6;  
	const struct tcp_struct *tcp; 
    const struct udp_struct *udp; 
    static netflow *flow;   
	const char *payload; 
    char *ip_src, *ip_dst, *internet_protocol;
	int internet_type; 
    u_char ip_p; 
    int ip_len;
    int size_ip;
	int size_tcp;
    int size_udp;
    int size_payload;
    char retransmitted[4] = "No"; 
    char ipv[5] = "IPv4"; 
    
    //Print info before termination
    if (header == NULL)
    {
        printf("\n-Statistics\n");
        printf("Network flows captured: %d\n", count_flows);
        printf("TCP Network flows captured: %d\n", count_flows_TCP);
        printf("UDP Network flows captured: %d\n", count_flows_UDP);
        printf("Total Packets received: %d\n", count_packets);
        printf("TCP Packets received: %d\n", count_packets_TCP);
        printf("UDP Packets received: %d\n", count_packets_UDP);
        printf("Total TCP Packets bytes: %d\n", count_bytes_TCP);
        printf("Total UDP Packets bytes: %d\n", count_bytes_UDP);
        free(flow);
        return;
    }

    count_packets++;
    ethernet = (struct ethernet*)(packet);
    internet_type = ntohs(ethernet->ether_type);
    ip = (struct ip_struct*)(packet + LENGTH_ETHERNET);
    if (internet_type == NETWORKTYPE_IPV6)
    {
        strcpy(ipv,"IPv6");
        ipv6 = (struct ipv6_struct*)(packet + LENGTH_ETHERNET);
        size_ip = 40;
        ip_src = strdup(inet_ntoa(ip->ip_src));
        ip_dst = strdup(inet_ntoa(ip->ip_dst));
        ip_p = ip->ip_p;
        ip_len = ntohs(ip->ip_len);
    }
    else
    {
        size_ip = IP_HL(ip)*4;       
        ip_src = strdup(inet_ntoa(ip->ip_src));
        ip_dst = strdup(inet_ntoa(ip->ip_dst));
        ip_p = ip->ip_p;
        ip_len = ntohs(ip->ip_len);
    }
    
    // First function call 
    if (init_flag) 
    {
        print_table();
        flow = (netflow*)calloc(1, sizeof(netflow));
        init_flag = 0;

    } 
    if (ip_p == IPPROTO_TCP)
    {
        count_packets_TCP++;
        count_bytes_TCP+= header->len; 
        tcp = (struct tcp_struct*)(packet + LENGTH_ETHERNET + size_ip);
        size_tcp = TH_OFF(tcp)*4;
        size_payload = ip_len - (size_ip + size_tcp); 
        payload = (u_char *)(packet + LENGTH_ETHERNET + size_ip + size_tcp);
        
        if(check_retransmission(flow, ip, tcp, size_payload, count_flows))
        {
            strcpy(retransmitted,"Yes"); 
        }
        
        printf("%d\tTCP\t\t%s\t%s\t%d\t\t%d\t\t%s\t\t%d\t\t%d\t\t%s\n",  
                                                    count_packets, ip_src, ip_dst, 
                                                    ntohs(tcp->th_sport), 
                                                    ntohs(tcp->th_dport),ipv, 
                                                    size_tcp, size_payload, 
                                                    retransmitted);
        
        // Update network flow if packet is not retransmitted
        if(!check_retransmission(flow, ip, tcp, size_payload, count_flows))
        {
            int ret = 0; 
            if ((ret = flow_update(flow, ip, tcp, size_payload, count_flows)) == 1)
            {
                count_flows++;
                count_flows_TCP++;
                flow = realloc(flow,(count_flows+1)*sizeof(netflow)); 
            }
        }
    }
    else if (ip_p == IPPROTO_UDP)
    {
        count_packets_UDP++;
        count_bytes_UDP+= header->len;
        udp = (struct udp_struct*)(packet + LENGTH_ETHERNET + size_ip);
        size_payload = header->caplen - size_ip - LENGTH_ETHERNET - LENGTH_UDP_H;
        payload = (u_char *)(packet + LENGTH_ETHERNET + size_ip + LENGTH_UDP_H);

        printf("%d\tUDP\t\t%s\t%s\t%d\t\t%d\t\t%s\t\t%d\t\t%d\t\t-\n", 
                                                        count_packets, ip_src, ip_dst, 
                                                        ntohs(udp->uh_sport), 
                                                        ntohs(udp->uh_dport),ipv, 
                                                        size_udp, size_payload);


        int ret = 0; 
        if ((ret = flow_update_udp(flow, ip, udp, count_flows)) == 1)
        {
            count_flows++;
            count_flows_UDP++;
            flow = realloc(flow,(count_flows+1)*sizeof(netflow)); 
        }
    }
    else
    {
        // Skip non UDP and non TCP packets
        return; 
    }
}

int
flow_update(netflow *flow, const struct ip_struct *ip, const struct tcp_struct *tcp, int size_payload, int length)
{
    char *ip_src = strdup(inet_ntoa(ip->ip_src));
    char *ip_dst = strdup(inet_ntoa(ip->ip_dst)); 
    
    for (int i = 0; i < length; i++)
    {
        if ((strcmp(flow[i].ip_src, ip_src) == 0) && (strcmp(flow[i].ip_dst, ip_dst) == 0) 
            &&flow[i].port_src == tcp->th_sport && flow[i].port_dst == tcp->th_dport
            && flow[i].protocol == ip->ip_p)
        {
            flow[i].current_seq_number = ntohl(tcp->th_seq); 
            flow[i].next_expected_seq_number = ntohl(tcp->th_seq) + size_payload;
            return 0; 
        } 
    }

    strcpy(flow[length].ip_src, ip_src); 
    strcpy(flow[length].ip_dst, ip_dst); 
    flow[length].port_src = tcp->th_sport; 
    flow[length].port_dst = tcp->th_dport;
    flow[length].protocol = ip->ip_p;
    flow[length].current_seq_number = ntohl(tcp->th_seq); 
    flow[length].next_expected_seq_number = ntohl(tcp->th_seq) + size_payload; 

    return 1; 
}

int
flow_update_udp(netflow *flow, const struct ip_struct *ip, const struct udp_struct *udp, int length)
{
    char *ip_src = strdup(inet_ntoa(ip->ip_src));
    char *ip_dst = strdup(inet_ntoa(ip->ip_dst)); 
    
    for (int i = 0; i < length; i++)
    {
        if ((strcmp(flow[i].ip_src, ip_src) == 0) && (strcmp(flow[i].ip_dst, ip_dst) == 0) 
            &&flow[i].port_src == udp->uh_sport && flow[i].port_dst == udp->uh_dport
            && flow[i].protocol == ip->ip_p)
        {
            return 0; 
        } 
    }

    strcpy(flow[length].ip_src, ip_src); 
    strcpy(flow[length].ip_dst, ip_dst); 
    flow[length].port_src = udp->uh_sport; 
    flow[length].port_dst = udp->uh_dport;
    flow[length].protocol = ip->ip_p;
    flow[length].current_seq_number = 0; 
    flow[length].next_expected_seq_number = 0; 
    
    return 1; 
}

int check_retransmission(netflow *flow, const struct ip_struct *ip, const struct tcp_struct *tcp, int size_payload, int length)
{
    char *ip_src = strdup(inet_ntoa(ip->ip_src));
    char *ip_dst = strdup(inet_ntoa(ip->ip_dst)); 

    for (int i = 0; i < length; i++)
    {
        if ((strcmp(flow[i].ip_src, ip_src) == 0) && (strcmp(flow[i].ip_dst, ip_dst) == 0) 
            &&flow[i].port_src == tcp->th_sport && flow[i].port_dst == tcp->th_dport
            && flow[i].protocol == ip->ip_p)
        {
            // If keep alive, it is not a retranmission 
            if ((size_payload <= 1) && ((tcp->th_flags & TH_SYN)||
            (tcp->th_flags & TH_FIN)||(tcp->th_flags & TH_RST)) && 
            (ntohl(tcp->th_seq)-flow[i].next_expected_seq_number == -1))
            {
                return 0; 
            }

            // TCP retranmission
            if (((size_payload > 0)||(tcp->th_flags & TH_SYN)||(tcp->th_flags & TH_FIN))&&
            ((flow[i].next_expected_seq_number) > ntohl(tcp->th_seq)))
            {
                return 1; 
            }
        }
    }
    return 0; 
}

void print_table()
{
    printf("No.\tProtocol\tSource IP\tDest. IP\tSource port\tDest. Port\tInet Protocol\tHeader Length\tPayload Length\tRetransmitted\n");
    printf("-------------------------------------------------------------------------------------------------------------------------------------------\n");
}