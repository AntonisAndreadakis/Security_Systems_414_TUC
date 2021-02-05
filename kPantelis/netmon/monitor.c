#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pcap.h>
#include <sys/types.h>
 #include <pcap-bpf.h>
#include<signal.h>

#include<sys/socket.h>
#include<arpa/inet.h> // for inet_ntoa()
#include<net/ethernet.h>
#include<netinet/ip_icmp.h>	//Provides declarations for icmp header
#include<netinet/udp.h>	//Provides declarations for udp header
#include<netinet/tcp.h>	//Provides declarations for tcp header
#include<netinet/ip.h>	//Provides declarations for ip
#include <netinet/in.h>
#include <netinet/if_ether.h>


#define ETHER_LENGTH 14

/*
	
		This extends the <struct tcphdr> found in linux/tcp.h
		Flags and sequence number checking is what needed to distinguish retransmissions from original msgs in TCP.


*/

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

struct packet 
{
	char *src_ip; //src ip.
	char *dest_ip;//destination ip.
	int src_port; //src port
	int dest_port; //destination port
	uint8_t protocol; //packet's protocol
	unsigned int ip_version; // IPv4 or v6.
	int is_retransmission;

	int header_len;
	int payload_len;

};

struct net_flow
{
	char *src_ip;
    char *dest_ip;

    uint16_t src_port;
    uint16_t dest_port;

    uint8_t protocol;

    int currseq_num;
    int nextexp_seq_num;

    struct net_flow *next;
};



void capture_live(char *dev_name);
void capture_file(char *filename);
void handle_error(char *err);
pcap_if_t *lookup_dev(char *dev);
void packet_handler(u_char *, const struct pcap_pkthdr *, const u_char *);
struct packet *gather_ip_data(const u_char *packet, int *pack_siz);
struct packet *gather_tcp_data(const u_char *packet, struct packet *node);
struct packet *gather_udp_data(const u_char *packet, struct packet *node, int siz);
struct net_flow *construct_flow(struct packet *p, struct tcp_struct *tcp, int payload_size);
struct net_flow *list_flow(struct net_flow *head, struct net_flow *node);
int is_retransmission(struct net_flow *head_flow, struct packet *p,const struct tcp_struct *tcp, int payload_size);
int flow_exists(struct net_flow *head, struct net_flow *node);
void print_stats();

/*

	Global variables used for stats..

*/

int tcp_c = 0;
int udp_c = 0;
int total_c = 0;
int tcp_bytes_recv= 0;
int udp_bytes_recv = 0;
int bytes_rcvd = 0;
int packs_rcvd = 0;
int net_flows = 0;
int tcp_flows = 0;
int udp_flows = 0;
struct net_flow *flows = NULL;



void print_packet(struct packet *p)
{
	char *type = (p->protocol == 17) ? "UDP" : "TCP";
	char *ret = (p->is_retransmission == 1) ? "RETRANSMITTED" : "NONE";
	fprintf(stderr, "[%s] [src_ip:port]:\t%-14s:%-5d -> [dest_ip:port]:\t%-14s:%-5d [header,payload (lengths)]:\t%d, %d [WARNINGS]: %s\n",type, p->src_ip, p->src_port, p->dest_ip, p->dest_port, p->header_len, p->payload_len, ret);
}

void interrupt_handler(int signum)
{
	//I'll probably do some stuff before exiting..
	fprintf(stderr, "Srcipt Terminated..\n");
	print_stats();
	exit(signum);
}

void usage(void)
{
	printf(
	       "\n"
	       "usage:\n"
	       "\t./monitor \n"
		   "Options:\n"
		   "-i <interface>, Capture from specified network interface\n"
		   "-r <filename>, Analyze from provided file\n"
		   "-h, Help message\n\n"
		   );

	exit(1);
}

int  main(int argc, char *argv[])
{

	int ch;

	//register when to stop, CTRL+Z is the case here.
	signal(SIGTSTP, interrupt_handler);

	if (argc <= 2)
		usage();

	while ((ch = getopt(argc, argv, "i:r:h")) != -1) {
		switch (ch) {		
		case 'i':
			capture_live(optarg);

			break;
		case 'r':
			fprintf(stdout, "File capture on\n");
			capture_file(optarg);
			break;
		
		default:
			usage();
		}

	}




	argc -= optind;
	argv += optind;	
	
	return 0;
}

/*
	
	Handles an execution error by prompting user and then terminating the program.
	Args:

			-arg1: A message to print before terminating.
	Notes: 
			-Terminates execution if called.

*/

void handle_error(char *err)
{
	fprintf(stderr, "Error occurred..! [Msg]: %s\n", err);
	exit(-1);
}

/*

	Handles packets sniffed

*/

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	struct tcp_struct *tcp;
	int payload_len;

	
	struct iphdr *iph = (struct iphdr*)(packet + sizeof(struct ethhdr));
	int t_ip = ntohs(iph->tot_len);
	int t_siz = iph->ihl*4;
	int t_tcp_siz;
	int effective_payload;

	total_c++;
	//we only care about TCP, UDP packets..
	if(iph->protocol == 6) //TCP
	{

		//init structs and gather..
		struct packet *l = gather_ip_data(packet, &payload_len);
		tcp = (struct tcp_struct *)(packet + ETHER_LENGTH + t_siz);
		
		//TCP's maths..
		t_tcp_siz = TH_OFF(tcp)*4;
		effective_payload = t_ip - (t_siz + t_tcp_siz);
		tcp_bytes_recv += payload_len;
		l = gather_tcp_data(packet, l);
		

		//don't care about retransmitted stuff..
		if(!is_retransmission(flows, l, tcp, effective_payload))
		{
			struct net_flow *fl = construct_flow(l, tcp, effective_payload);

			//check if there..
			if(!flow_exists(flows,fl))
			{
				tcp_flows++;
				flows = list_flow(flows, fl);
			}

			
		}



		print_packet(l);
		
		
	}
	else if(iph->protocol == 17) // UDP
	{
		
		struct packet *l = gather_ip_data(packet, &payload_len);

		udp_bytes_recv += payload_len;

		l = gather_udp_data(packet, l, header->len);
		
		struct net_flow *fl = construct_flow(l, NULL, 0);

		//check if there..
		if(!flow_exists(flows,fl))
		{
			udp_flows++;
			flows = list_flow(flows, fl);
		}

		print_packet(l);
		

	}

	//skip non UDP/TCP packets..

	

	

}




/*
	
	Handler for file analysis.

*/

void capture_file(char *filename)
{
	pcap_t *fd;
	char error_buf[PCAP_ERRBUF_SIZE];

	//attempt to open..
	fd = pcap_open_offline(filename, error_buf);

	if(!fd)
		handle_error(error_buf);
	
	if(pcap_loop(fd, 0, packet_handler, NULL) < 0)
	{
		fprintf(stderr, "Failure upon looping..\n");
	}

	print_stats();
	fprintf(stdout, "Process Finished!\n");

}


/*
	
	Acts as a handler for live capture..

*/
void capture_live(char *dev_name)
{

	pcap_if_t *dev;
	char error_buf[PCAP_ERRBUF_SIZE];
	int timeout = -1; //milliseconds
	int threshold = 1;  //packet limit


	//check the existance..
	if(!(dev = lookup_dev(dev_name)))
	{
		handle_error("Device not found");

	}
	
	//if present, open for live capture..
	
	pcap_t *handler = pcap_open_live(dev_name, BUFSIZ, threshold, timeout, error_buf);

	
	if(handler == NULL)
	{
		fprintf(stderr, "Problems in heaven (and the device as well)..\n");
		exit(-1);
	}

	//loop on capturing
	pcap_loop(handler, 0, packet_handler, NULL);

	pcap_close(handler);

	return;

}


/*

	Looks up a specified device, if present returns the device as <pcap_if_t*>, else NULL.
	Args:
			-arg1: The device name  as <char *>
	Returns:
			The device as <pcap_if_t *> or NULL if no such device exists.

*/

pcap_if_t *lookup_dev(char *dev)
{
	char error_buf[PCAP_ERRBUF_SIZE];
	pcap_if_t *devices;

	//get devices, handle error
	if(pcap_findalldevs(&devices, error_buf) == -1)
		handle_error(error_buf);

	//parse available devices..
	while(devices->next != NULL)
	{
		//check the name
		if(strcmp(devices->name, dev) == 0)
			return devices;
		//move on
		devices = devices->next;
	}

	//shouldn't reach here if user typed a valid dev.
	return NULL;
	

}


/*

	IP/Ether protocol general details gathering..


*/

struct packet *gather_ip_data(const u_char *packet, int *pack_siz)
{	


	packs_rcvd++;

	//sockets will help here.
	struct sockaddr_in src, dest;


	//this will only work on Linux distros, but comes in handy here [if in windows prefer ip].
	//skip the header here..
	struct iphdr *iph = (struct iphdr *)(packet  + sizeof(struct ethhdr));
	unsigned short iphdr_len = iph->ihl*4;

	//handle garbage..
	memset(&src, 0, sizeof(src));
	memset(&dest, 0, sizeof(dest));

	//get ip's 
	src.sin_addr.s_addr = iph->saddr;
	dest.sin_addr.s_addr = iph->saddr;

	//store Ethernet data in a newly created node..
	struct packet *node = (struct packet *)malloc(sizeof(struct packet));
	node->src_ip = strdup(inet_ntoa(src.sin_addr));
	node->dest_ip = strdup(inet_ntoa(dest.sin_addr));
	node->protocol = (unsigned int )iph->protocol;
	node->ip_version = (unsigned int)iph->version;
	node->header_len = iphdr_len;
	node->is_retransmission = 0;

	//return the node.
	*pack_siz = iphdr_len;
    return node;
}

/*
	
	Fill the a <struct packet > node with data concerning it's protocol in TCP.

*/

struct packet *gather_tcp_data(const u_char *packet, struct packet *node)
{
	tcp_c++;
	
	//fix ethernet stuff
	struct iphdr *ip_header = (struct iphdr *)(packet + sizeof(struct ethhdr));
	unsigned short iphdr_len = ip_header->ihl*4;
	
	//be a TCP guy..
	struct tcphdr *tcp_header=(struct tcphdr*)(packet + iphdr_len + sizeof(struct ethhdr));
			
	//inform about the header size.
	int header_size =  sizeof(struct ethhdr) + iphdr_len + tcp_header->doff*4;

	//some error handling..
	if(!node)
		return NULL;

	//update the node..
	node->src_port = ntohs(tcp_header->source);
	node->dest_port = ntohs(tcp_header->dest);
	node->payload_len = header_size - tcp_header->doff*4;
	node->header_len = tcp_header->doff*4;

	
	return node;

	

}


/*
	
	Fill the a <struct packet > node with data concerning it's protocol in UDP.

*/

struct packet *gather_udp_data(const u_char *packet, struct packet *node, int siz)
{
	udp_c++;
	
	//fix ethernet stuff
	struct iphdr *ip_header = (struct iphdr *)(packet + sizeof(struct ethhdr));
	unsigned short iphdr_len = ip_header->ihl*4;
	
	//be a TCP guy..
	struct udphdr *udp_header=(struct udphdr*)(packet + iphdr_len + sizeof(struct ethhdr));
			
	//inform about the header size, total size of grubbed UDP..
	int header_size =  sizeof(struct ethhdr) + iphdr_len + sizeof(udp_header); 

	//some error handling..
	if(!node)
		return NULL;

	//update the node..
	node->src_port = ntohs(udp_header->source);
	node->dest_port = ntohs(udp_header->dest);
	node->payload_len = siz - header_size;
	node->header_len = sizeof(udp_header); //always 8 bytes..

	

	return node;
}


/*

		Fills a flow struct in respect on the passed protocol..

*/

struct net_flow *construct_flow(struct packet *p, struct tcp_struct *tcp, int payload_size)
{	
	struct net_flow *f = (struct net_flow *)malloc(sizeof(struct net_flow));



	
	f->src_ip = strdup(p->src_ip);
	f->dest_ip = strdup(p->dest_ip);
	f->dest_port = p->dest_port;
	f->src_port = p->src_port;
	f->protocol = p->protocol;
	f->next = NULL;

	//UDP
	if(p->protocol == 17)
	{
		f->currseq_num = 0;
		f->nextexp_seq_num = 0;
	}
	else if(p->protocol == 6)
	{
		//TCP packets should be marked in order for us to distinguish retransmissions.

		f->currseq_num = ntohl(tcp->th_seq);
		f->nextexp_seq_num = ntohl(tcp->th_seq) + payload_size;
	}
	

	


	return f;


}


/*
	
	Inserts a flow into a list of flows (<struct net_flow>).

*/

struct net_flow *list_flow(struct net_flow *head, struct net_flow *node)
{

	//empty list.
	if(!head)
		return node;

	struct net_flow *curr = head;



	while(curr->next != NULL)
	{

		//move on..
		curr = curr->next;


	}

	//link on tail..
	curr->next = node;

	//return the head.
	return head;
}


/*

	Decides if a flow is already enlisted, if so returns 1, else 0.

*/

int flow_exists(struct net_flow *head, struct net_flow *node)
{
	//cache 'till I die..
	struct net_flow *curr_flow = head;

	//parse the list..
	while(curr_flow)
	{
		if ((strcmp(curr_flow->src_ip, node->src_ip) == 0) && (strcmp(curr_flow->dest_ip, node->dest_ip) == 0) && (curr_flow->src_port == node->src_port) && (curr_flow->dest_port == node->dest_port) && (curr_flow->protocol == node->protocol))
        	return 1;
        //move on
        curr_flow = curr_flow->next;

	}

	//if reached there flow is unique..
	return 0;
}


/*

	Given a flow and a new packet in TCP, decides if it is about a retransmission or a unique flow.


	Notes:
			Partially buggy, needs improvement. I'll come back to it later [if in Github don't ignore this.]

*/
int is_retransmission(struct net_flow *head_flow, struct packet *p,const struct tcp_struct *tcp, int payload_size)
{

    //cache global stuff..
    struct net_flow *curr_flow = head_flow;

 
    while(curr_flow != NULL)
    {
    	//Be sure that flows are identical
    	if ((strcmp(curr_flow->src_ip, p->src_ip) == 0) && (strcmp(curr_flow->dest_ip, p->dest_ip) == 0) && (curr_flow->src_port == p->src_port) && (curr_flow->dest_port == p->dest_port) && (curr_flow->protocol == p->protocol))
        {
       
            //"Keep alives" are different thing than retransmission
            if ((payload_size <= 1) && ((tcp->th_flags & TH_SYN) || (tcp->th_flags & TH_FIN) || (tcp->th_flags & TH_RST)) && ((ntohl(tcp->th_seq) - curr_flow->nextexp_seq_num) == -1))
            	return 0; 

            //That's a retransmission though in terms of TCP
            if (((payload_size > 0) || (tcp->th_flags & TH_SYN) || (tcp->th_flags & TH_FIN)) && ((curr_flow->nextexp_seq_num) > ntohl(tcp->th_seq)) )
            {
            	//mark the actor packet.
            	p->is_retransmission = 1;
                return 1; 
            }


           

       
        }
        //move on..
        curr_flow = curr_flow->next;
    }


   //if there, no retransmission found
    return 0;
}

/*
	
	Beautified statistics print process..

*/

void print_stats()
{
	fprintf(stdout, "\n\t\t\t\t\t\t---Statistics----\t\n\n");
	fprintf(stdout, "[Packets Captured]: %5d\t[Network Flows]: %5d\t[TCP Flows]: %5d\t[UDP Flows]: %5d\n",total_c,tcp_flows+udp_flows,tcp_flows,udp_flows);
}