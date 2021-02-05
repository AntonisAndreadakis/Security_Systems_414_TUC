#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <net/ethernet.h>

void process_packet(u_char *, const struct pcap_pkthdr *, const u_char *);
void print_tcp_packet(const u_char *, int);
void print_udp_packet(const u_char *, int);

void process_live(char *);
void process_offline(char *);

void usage(void);
void INThandler(int);

struct sockaddr_in source, dest;
int tcp = 0, udp = 0, total = 0, others = 0;
u_int seq_num=-1;

int
main(int argc, char **argv)
{
  int opt;
  char * ni_name, * pcap_filename;

  while ((opt = getopt(argc, argv, "i:r:h")) != -1) {
    switch(opt) {
      case 'i':
        ni_name = strdup(optarg);
        process_live(ni_name);
        break;
      case 'r':
        pcap_filename = strdup(optarg);
        process_offline(pcap_filename);
        break;
      case 'h':
      default:
        usage();
    }
  }

  free(ni_name);
  free(pcap_filename);

  return 0;
}

void
usage()
{
  printf(
    "\n"
    "Usage:\n"
    "    assign_6 -i netint_name \n"
    "    assign_6 -r pcap_filename \n"
    "    assign_6 -h \n"
  );
  printf(
    "\n"
    "Options:\n"
    "-i Network interface name (e.g., eth0)\n"
    "-r Packet capture filename (e.g., test.pcap)\n"
    "-h Display help message\n"
  );
  exit(EXIT_FAILURE);
}

void
INThandler(int sig)
{
  signal(sig, SIG_IGN);
  printf("\nTCP: %d\tUDP: %d\tOther Protocols: %d\tTotal: %d\n", tcp, udp, others, total);
  exit(0);
}

void
process_live(char * netint)
{
  pcap_t *handle;

  char err[100];

  signal(SIGINT, INThandler);

  printf("Opening device %s for live packet capturing...\n", netint);
  handle = pcap_open_live(netint, 65536, 1, 0, err);

  if (!handle) {
    fprintf(stderr, "Couldn't open device %s: %s\n", netint, err);
    exit(1);
  }

  pcap_loop(handle, -1, process_packet, NULL);

  return;
}

void
process_offline(char * pcap_file)
{
  pcap_t *handle;

  char err[100];

  printf("Reading file %s for offline packet capturing...\n", pcap_file);
  handle = pcap_open_offline(pcap_file, err);

  if (!handle) {
    fprintf(stderr, "Couldn't open file %s: %s\n", pcap_file, err);
    exit(1);
  }

  pcap_loop(handle, -1, process_packet, NULL);

  printf("\nTCP packets: %d\tUDP packets: %d\tOther Protocol packets: %d\tTotal packets: %d\n", tcp, udp, others, total);
  return;
}

void
process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{
  int size = header->len;

  //get IP header from packet
  struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
  ++total;
  switch(iph->protocol) { //check protocol
    case 6: //TCP protocol
      ++tcp;
      print_tcp_packet(buffer, size);
      break;
    case 17: //UDP protocol
      ++udp;
      print_udp_packet(buffer, size);
      break;
    default:
      ++others;
      break;
  }
}


void print_tcp_packet(const u_char *buffer, int len) {
  unsigned short iphdrlen;
  char ret[15];

  struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
  iphdrlen = iph->ihl*4;

  memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;
	
	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;

  struct tcphdr *tcph = (struct tcphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));
  int header_size = sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;


  if (seq_num > tcph->seq) strcpy(ret,"Retransmitted");
  else strcpy(ret,"");
  seq_num = ntohl(tcph->seq);

  printf("Src IP (Port): %15s (%5u)\t\tDst IP (Port): %15s (%5u)\t  Protocol: TCP\tHeader Size: %5u\tPayload Size: %5u\t%s\n",
    inet_ntoa(source.sin_addr), ntohs(tcph->source), inet_ntoa(dest.sin_addr), ntohs(tcph->dest), header_size, len-header_size, ret
  );

  return;
}

void print_udp_packet(const u_char *buffer, int len) {
  unsigned short iphdrlen;

  struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
  iphdrlen = iph->ihl*4;

  memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;
	
	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;

  struct udphdr *udph = (struct udphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));
  int header_size = sizeof(struct ethhdr) + iphdrlen + sizeof(udph);

  printf("Src IP (Port): %15s (%5u)\t\tDst IP (Port): %15s (%5u)\t  Protocol: UDP\tHeader Size: %5u\tPayload Size: %5u\n",
    inet_ntoa(source.sin_addr), ntohs(udph->source), inet_ntoa(dest.sin_addr), ntohs(udph->dest), header_size, len-header_size
  );

  return;
}
