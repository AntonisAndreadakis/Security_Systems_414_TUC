#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <pcap/pcap.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define SNAPLEN 65535
#define FLOW_BUCKETS 4096U
#define MAX_FLOWS 65536U

#define ETHERTYPE_IPV4 0x0800U
#define ETHERTYPE_IPV6 0x86ddU
#define ETHERTYPE_VLAN 0x8100U
#define ETHERTYPE_QINQ 0x88a8U

#define PROTOCOL_TCP 6U
#define PROTOCOL_UDP 17U
#define EXT_HOPOPTS 0U
#define IPV6_ROUTING 43U
#define IPV6_FRAGMENT 44U
#define IPV6_ESP 50U
#define IPV6_AH 51U
#define IPV6_NONE 59U
#define EXT_DSTOPTS 60U

struct flow_key {
	uint8_t family;
	uint8_t protocol;
	uint16_t source_port;
	uint16_t destination_port;
	uint8_t source[16];
	uint8_t destination[16];
};

struct flow {
	struct flow_key key;
	uint32_t next_sequence;
	int sequence_initialized;
	struct flow *next;
};

struct statistics {
	uint64_t total_packets;
	uint64_t tcp_packets;
	uint64_t udp_packets;
	uint64_t tcp_bytes;
	uint64_t udp_bytes;
	uint64_t flows;
	uint64_t tcp_flows;
	uint64_t udp_flows;
};

struct monitor_state {
	pcap_t *capture;
	struct statistics statistics;
	struct flow *buckets[FLOW_BUCKETS];
	size_t flow_count;
	int flow_limit_reported;
	int fatal_error;
};

struct network_packet {
	uint8_t family;
	uint8_t protocol;
	uint8_t source[16];
	uint8_t destination[16];
	const uint8_t *transport;
	size_t transport_length;
};

static pcap_t *signal_capture;

static uint16_t read_be16(const uint8_t *data)
{
	return (uint16_t)(((uint16_t)data[0] << 8) | data[1]);
}

static uint32_t read_be32(const uint8_t *data)
{
	return ((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16) |
	       ((uint32_t)data[2] << 8) | data[3];
}

static void handle_signal(int signal_number)
{
	(void)signal_number;
	if (signal_capture != NULL)
		pcap_breakloop(signal_capture);
}

static void print_usage(FILE *stream, const char *program)
{
	fprintf(stream,
	        "Usage: %s -i <interface>\n"
	        "       %s -r <capture.pcap>\n"
	        "       %s -h\n",
	        program, program, program);
}

static uint64_t hash_bytes(uint64_t hash, const uint8_t *bytes, size_t length)
{
	size_t i;

	for (i = 0; i < length; ++i) {
		hash ^= bytes[i];
		hash *= UINT64_C(1099511628211);
	}
	return hash;
}

static size_t flow_bucket(const struct flow_key *key)
{
	uint64_t hash = UINT64_C(1469598103934665603);
	uint8_t ports[4];

	ports[0] = (uint8_t)(key->source_port >> 8);
	ports[1] = (uint8_t)key->source_port;
	ports[2] = (uint8_t)(key->destination_port >> 8);
	ports[3] = (uint8_t)key->destination_port;
	hash = hash_bytes(hash, &key->family, 1);
	hash = hash_bytes(hash, &key->protocol, 1);
	hash = hash_bytes(hash, ports, sizeof(ports));
	hash = hash_bytes(hash, key->source, sizeof(key->source));
	hash = hash_bytes(hash, key->destination, sizeof(key->destination));
	return (size_t)(hash % FLOW_BUCKETS);
}

static int same_flow(const struct flow_key *left, const struct flow_key *right)
{
	return left->family == right->family && left->protocol == right->protocol &&
	       left->source_port == right->source_port &&
	       left->destination_port == right->destination_port &&
	       memcmp(left->source, right->source, sizeof(left->source)) == 0 &&
	       memcmp(left->destination, right->destination,
	              sizeof(left->destination)) == 0;
}

static struct flow *find_or_add_flow(struct monitor_state *state,
	                                  const struct flow_key *key)
{
	size_t bucket = flow_bucket(key);
	struct flow *flow;

	for (flow = state->buckets[bucket]; flow != NULL; flow = flow->next) {
		if (same_flow(&flow->key, key))
			return flow;
	}
	if (state->flow_count == MAX_FLOWS) {
		if (!state->flow_limit_reported) {
			fprintf(stderr, "Flow table limit reached; additional flows are not counted\n");
			state->flow_limit_reported = 1;
		}
		state->fatal_error = 1;
		pcap_breakloop(state->capture);
		return NULL;
	}
	flow = calloc(1, sizeof(*flow));
	if (flow == NULL) {
		fprintf(stderr, "Out of memory while adding a flow\n");
		state->fatal_error = 1;
		pcap_breakloop(state->capture);
		return NULL;
	}
	flow->key = *key;
	flow->next = state->buckets[bucket];
	state->buckets[bucket] = flow;
	++state->flow_count;
	++state->statistics.flows;
	if (key->protocol == PROTOCOL_TCP)
		++state->statistics.tcp_flows;
	else
		++state->statistics.udp_flows;
	return flow;
}

static void free_flows(struct monitor_state *state)
{
	size_t bucket;

	for (bucket = 0; bucket < FLOW_BUCKETS; ++bucket) {
		struct flow *flow = state->buckets[bucket];
		while (flow != NULL) {
			struct flow *next = flow->next;
			free(flow);
			flow = next;
		}
	}
}

static int decode_ipv4(const uint8_t *packet, size_t length,
	                   struct network_packet *decoded)
{
	size_t header_length;
	size_t total_length;
	uint16_t fragment;

	if (length < 20 || (packet[0] >> 4) != 4)
		return 0;
	header_length = (size_t)(packet[0] & 0x0fU) * 4U;
	if (header_length < 20 || header_length > length)
		return 0;
	total_length = read_be16(packet + 2);
	if (total_length < header_length || total_length > length)
		return 0;
	fragment = read_be16(packet + 6);
	if ((fragment & UINT16_C(0x3fff)) != 0)
		return 0;
	decoded->family = 4;
	decoded->protocol = packet[9];
	memcpy(decoded->source, packet + 12, 4);
	memcpy(decoded->destination, packet + 16, 4);
	decoded->transport = packet + header_length;
	decoded->transport_length = total_length - header_length;
	return 1;
}

static int decode_ipv6(const uint8_t *packet, size_t length,
	                   struct network_packet *decoded)
{
	size_t payload_length;
	size_t end;
	size_t offset = 40;
	uint8_t next_header;
	unsigned int headers = 0;

	if (length < 40 || (packet[0] >> 4) != 6)
		return 0;
	payload_length = read_be16(packet + 4);
	if (payload_length == 0 || payload_length > length - 40)
		return 0;
	end = 40 + payload_length;
	next_header = packet[6];
	while (next_header != PROTOCOL_TCP && next_header != PROTOCOL_UDP) {
		size_t extension_length;

		if (++headers > 16 || offset + 2 > end)
			return 0;
		if (next_header == IPV6_FRAGMENT || next_header == IPV6_ESP ||
		    next_header == IPV6_NONE)
			return 0;
		if (next_header == EXT_HOPOPTS || next_header == IPV6_ROUTING ||
		    next_header == EXT_DSTOPTS)
			extension_length = ((size_t)packet[offset + 1] + 1U) * 8U;
		else if (next_header == IPV6_AH)
			extension_length = ((size_t)packet[offset + 1] + 2U) * 4U;
		else
			return 0;
		if (extension_length < 8 || extension_length > end - offset)
			return 0;
		next_header = packet[offset];
		offset += extension_length;
	}
	decoded->family = 6;
	decoded->protocol = next_header;
	memcpy(decoded->source, packet + 8, 16);
	memcpy(decoded->destination, packet + 24, 16);
	decoded->transport = packet + offset;
	decoded->transport_length = end - offset;
	return 1;
}

static int sequence_before(uint32_t left, uint32_t right)
{
	return (int32_t)(left - right) < 0;
}

static int update_tcp_sequence(struct flow *flow, uint32_t sequence,
	                           size_t payload_length, uint8_t flags)
{
	uint32_t consumed = (uint32_t)payload_length;
	uint32_t end;
	int retransmitted = 0;

	if ((flags & 0x02U) != 0)
		++consumed;
	if ((flags & 0x01U) != 0)
		++consumed;
	if (consumed == 0 || flow == NULL)
		return 0;
	end = sequence + consumed;
	if (flow->sequence_initialized && sequence_before(sequence, flow->next_sequence))
		retransmitted = 1;
	if (!flow->sequence_initialized || sequence_before(flow->next_sequence, end)) {
		flow->next_sequence = end;
		flow->sequence_initialized = 1;
	}
	return retransmitted;
}

static void address_text(uint8_t family, const uint8_t address[16],
	                     char *output, size_t capacity)
{
	int af = family == 4 ? AF_INET : AF_INET6;

	if (inet_ntop(af, address, output, (socklen_t)capacity) == NULL)
		(void)snprintf(output, capacity, "?");
}

static void process_transport(struct monitor_state *state,
	                          const struct pcap_pkthdr *header,
	                          const struct network_packet *packet)
{
	struct flow_key key;
	struct flow *flow;
	char source[INET6_ADDRSTRLEN];
	char destination[INET6_ADDRSTRLEN];
	uint16_t source_port;
	uint16_t destination_port;
	size_t transport_header_length;
	size_t payload_length;
	int retransmitted = 0;

	if (packet->protocol == PROTOCOL_TCP) {
		uint8_t flags;
		uint32_t sequence;

		if (packet->transport_length < 20)
			return;
		transport_header_length = (size_t)(packet->transport[12] >> 4) * 4U;
		if (transport_header_length < 20 ||
		    transport_header_length > packet->transport_length)
			return;
		payload_length = packet->transport_length - transport_header_length;
		sequence = read_be32(packet->transport + 4);
		flags = packet->transport[13];
		source_port = read_be16(packet->transport);
		destination_port = read_be16(packet->transport + 2);
		memset(&key, 0, sizeof(key));
		key.family = packet->family;
		key.protocol = packet->protocol;
		key.source_port = source_port;
		key.destination_port = destination_port;
		memcpy(key.source, packet->source, sizeof(key.source));
		memcpy(key.destination, packet->destination, sizeof(key.destination));
		flow = find_or_add_flow(state, &key);
		retransmitted = update_tcp_sequence(flow, sequence, payload_length, flags);
		++state->statistics.tcp_packets;
		state->statistics.tcp_bytes += header->len;
	} else {
		size_t udp_length;

		if (packet->transport_length < 8)
			return;
		udp_length = read_be16(packet->transport + 4);
		if (udp_length < 8 || udp_length > packet->transport_length)
			return;
		transport_header_length = 8;
		payload_length = udp_length - 8;
		source_port = read_be16(packet->transport);
		destination_port = read_be16(packet->transport + 2);
		memset(&key, 0, sizeof(key));
		key.family = packet->family;
		key.protocol = packet->protocol;
		key.source_port = source_port;
		key.destination_port = destination_port;
		memcpy(key.source, packet->source, sizeof(key.source));
		memcpy(key.destination, packet->destination, sizeof(key.destination));
		(void)find_or_add_flow(state, &key);
		++state->statistics.udp_packets;
		state->statistics.udp_bytes += header->len;
	}
	address_text(packet->family, packet->source, source, sizeof(source));
	address_text(packet->family, packet->destination, destination,
	             sizeof(destination));
	printf("Packet %" PRIu64 ": %s IPv%u %s:%u -> %s:%u header=%zu payload=%zu",
	       state->statistics.total_packets,
	       packet->protocol == PROTOCOL_TCP ? "TCP" : "UDP",
	       packet->family, source, source_port, destination, destination_port,
	       transport_header_length, payload_length);
	if (packet->protocol == PROTOCOL_TCP && retransmitted)
		printf(" Retransmitted");
	putchar('\n');
}

static void process_packet(unsigned char *user,
	                       const struct pcap_pkthdr *header,
	                       const unsigned char *bytes)
{
	struct monitor_state *state = (struct monitor_state *)user;
	struct network_packet packet;
	size_t offset = 14;
	size_t captured = header->caplen;
	uint16_t ethernet_type;
	int vlan_tags = 0;

	++state->statistics.total_packets;
	if (captured < 14)
		return;
	ethernet_type = read_be16(bytes + 12);
	/* Up to two tags: a plain 802.1Q frame, or a QinQ frame (an outer
	 * 0x88a8/0x8100 tag followed by an inner 0x8100 one). */
	while (vlan_tags < 2 &&
	       (ethernet_type == ETHERTYPE_VLAN || ethernet_type == ETHERTYPE_QINQ)) {
		if (captured < offset + 4)
			return;
		ethernet_type = read_be16(bytes + offset + 2);
		offset += 4;
		++vlan_tags;
	}
	memset(&packet, 0, sizeof(packet));
	if (ethernet_type == ETHERTYPE_IPV4) {
		if (!decode_ipv4(bytes + offset, captured - offset, &packet))
			return;
	} else if (ethernet_type == ETHERTYPE_IPV6) {
		if (!decode_ipv6(bytes + offset, captured - offset, &packet))
			return;
	} else {
		return;
	}
	if (packet.protocol != PROTOCOL_TCP && packet.protocol != PROTOCOL_UDP)
		return;
	process_transport(state, header, &packet);
}

static void print_statistics(const struct statistics *statistics)
{
	printf("Total number of network flows captured: %" PRIu64 "\n", statistics->flows);
	printf("Number of TCP network flows captured: %" PRIu64 "\n", statistics->tcp_flows);
	printf("Number of UDP network flows captured: %" PRIu64 "\n", statistics->udp_flows);
	printf("Total number of packets received: %" PRIu64 "\n", statistics->total_packets);
	printf("Total number of TCP packets received: %" PRIu64 "\n", statistics->tcp_packets);
	printf("Total number of UDP packets received: %" PRIu64 "\n", statistics->udp_packets);
	printf("Total bytes of TCP packets received: %" PRIu64 "\n", statistics->tcp_bytes);
	printf("Total bytes of UDP packets received: %" PRIu64 "\n", statistics->udp_bytes);
}

int main(int argc, char **argv)
{
	struct monitor_state state;
	const char *interface = NULL;
	const char *filename = NULL;
	char error_buffer[PCAP_ERRBUF_SIZE];
	int option;
	int loop_result;
	int result = 0;

	memset(&state, 0, sizeof(state));
	opterr = 0;
	while ((option = getopt(argc, argv, "hi:r:")) != -1) {
		switch (option) {
		case 'h':
			print_usage(stdout, argv[0]);
			return 0;
		case 'i':
			if (interface != NULL || filename != NULL) {
				print_usage(stderr, argv[0]);
				return 2;
			}
			interface = optarg;
			break;
		case 'r':
			if (interface != NULL || filename != NULL) {
				print_usage(stderr, argv[0]);
				return 2;
			}
			filename = optarg;
			break;
		default:
			print_usage(stderr, argv[0]);
			return 2;
		}
	}
	if ((interface == NULL && filename == NULL) || optind != argc) {
		print_usage(stderr, argv[0]);
		return 2;
	}
	if (filename != NULL)
		state.capture = pcap_open_offline(filename, error_buffer);
	else
		state.capture = pcap_open_live(interface, SNAPLEN, 0, 1000, error_buffer);
	if (state.capture == NULL) {
		fprintf(stderr, "Cannot open %s: %s\n",
		        filename != NULL ? filename : interface, error_buffer);
		return 1;
	}
	if (pcap_datalink(state.capture) != DLT_EN10MB) {
		fprintf(stderr, "Only Ethernet captures are supported\n");
		pcap_close(state.capture);
		return 1;
	}
	if (interface != NULL) {
		signal_capture = state.capture;
		(void)signal(SIGINT, handle_signal);
		(void)signal(SIGTERM, handle_signal);
	}
	loop_result = pcap_loop(state.capture, -1, process_packet,
	                        (unsigned char *)&state);
	signal_capture = NULL;
	if (loop_result == PCAP_ERROR) {
		fprintf(stderr, "Capture failed: %s\n", pcap_geterr(state.capture));
		result = 1;
	}
	if (state.fatal_error)
		result = 1;
	print_statistics(&state.statistics);
	pcap_close(state.capture);
	free_flows(&state);
	return result;
}
