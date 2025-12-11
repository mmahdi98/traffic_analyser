// ING
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <pcap/pcap.h>
#include <unistd.h>
#include <signal.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include "hash_table.h"

#define EXIT_WITH_ERROR(...) do { \
    fprintf(stderr, __VA_ARGS__); \
    exit(1); \
} while(0)

#define ENABLE_DEBUG 0

#if ENABLE_DEBUG
    #define DEBUG_LOG(...) printf(__VA_ARGS__)
#else
    #define DEBUG_LOG(...) do {} while (0)
#endif

#define MAX_INTERFACE_NAME 101 // some interface names get big but 100 is more than enough.

char g_interface[MAX_INTERFACE_NAME];
int g_duration = 0;
pcap_t *g_pcap_handle = NULL;
traffic_node_t *g_hash_table[HASH_TABLE_SIZE]; 

void validate_interface(const char *iface_name);
int validate_duration(const char *input_str);
void handle_args(int argc, char *argv[]);
void handle_new_packet(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet);
void stop_capture(int signum);
void init_pcap_handle();
void init_alarm();
void set_pcap_handle_filter();
void update_hash_table_entry(traffic_key_t key, uint32_t packet_len);
void print_and_free_stats();

int main(int argc, char *argv[])
{
	handle_args(argc, argv);
	init_pcap_handle();
	set_pcap_handle_filter();
    printf("Capture started for %d seconds...\n", g_duration);
	init_alarm();
    pcap_loop(g_pcap_handle, -1, handle_new_packet, NULL);
    printf("\nCapture complete.\n");
	print_and_free_stats();
    pcap_close(g_pcap_handle);
	return 0;
}

void ip_to_string(uint32_t ip_addr, char *buffer) {
    struct in_addr addr;
    addr.s_addr = ip_addr;
    if (inet_ntop(AF_INET, &addr, buffer, INET_ADDRSTRLEN) == NULL) {
        sprintf(buffer, "INVALID");
    }
}

void print_and_free_stats() {
    printf("%-15s %-15s %-8s %-12s %s\n", 
           "ip_src", "ip_dst", "protocol", "packet_count", "total_size");// table header
    printf("--------------- --------------- -------- ------------ --------------------------------\n");// 15, 15, 8, 12, 

    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        traffic_node_t *current = g_hash_table[i];
        while (current != NULL) {
            traffic_node_t *node_to_free = current;
            current = current->next; 

			char src_ip_str[INET_ADDRSTRLEN];
			ip_to_string(node_to_free->key.src_ip, src_ip_str);

            char dst_ip_str[INET_ADDRSTRLEN];
			ip_to_string(node_to_free->key.dst_ip, dst_ip_str);

            const char *protocol_str = (node_to_free->key.protocol == IPPROTO_TCP) ? "TCP" : "UDP"; // protocol string
            unsigned long long bytes = node_to_free->stats.total_bytes;
            char size_str[64];

            if (bytes >= (1024 * 1024)) // megabytes
			{
                snprintf(size_str, sizeof(size_str), "%lluB (%.2fMB)", bytes, (double)bytes / (1024 * 1024));
            } 
			else if (bytes >= 1024) // kilobytes
			{
                snprintf(size_str, sizeof(size_str), "%lluB (%.2fKB)", bytes, (double)bytes / 1024);
            }
			else  // bytes
			{
                snprintf(size_str, sizeof(size_str), "%lluB", bytes);
            }

            printf("%-15s %-15s %-8s %-12lu %s\n",
                   src_ip_str,
                   dst_ip_str,
                   protocol_str,
                   node_to_free->stats.packet_count,
                   size_str); // print table entries
            
            free(node_to_free);
        }
        g_hash_table[i] = NULL;
    }
}

void update_hash_table_entry(traffic_key_t key, uint32_t packet_len) {
    uint32_t hash_val = get_hash(&key);
    uint32_t index = hash_val % HASH_TABLE_SIZE;
    traffic_node_t *current = g_hash_table[index];
    
    while (current != NULL) {
        if (current->key.src_ip == key.src_ip && current->key.dst_ip == key.dst_ip && current->key.protocol == key.protocol) // if key exists
		{
            current->stats.packet_count++;
            current->stats.total_bytes += packet_len;
            return; // hit on table, returning
        }
        current = current->next;
    }

    traffic_node_t *new_node = (traffic_node_t *)malloc(sizeof(traffic_node_t)); // miss on table, creating new node
    
	if (!new_node)
	{
        fprintf(stderr, "[ERROR] Malloc failed for new traffic node.\n");
        return; 
    }

    new_node->key = key;
    new_node->stats.packet_count = 1;
    new_node->stats.total_bytes = packet_len;
    new_node->next = g_hash_table[index];
    g_hash_table[index] = new_node;
}

void handle_new_packet(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet) {
    (void)args; // unused
    DEBUG_LOG("\n--- [PACKET CAPTURED] Total Len: %d ---\n", header->len);
    struct ether_header *eth = (struct ether_header *)packet; // get ethernet header
    
    if (ntohs(eth->ether_type) != ETHERTYPE_IP)
	{
        DEBUG_LOG("[PKT] Ignored: Not an IPv4 packet (EtherType: 0x%04x)\n", ntohs(eth->ether_type));
        return;
    }

    struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header)); // get ip header

    if (ip_header->ip_v != 4) 
	{
        DEBUG_LOG("[PKT] Ignored: IP version is %d (Expected 4)\n", ip_header->ip_v);
        return;
    }

    if (ip_header->ip_p != IPPROTO_TCP && ip_header->ip_p != IPPROTO_UDP)
	{
        DEBUG_LOG("Seems like pcap filtering not working properly\n[PKT] Ignored: Protocol %d is not TCP(6) or UDP(17)\n", ip_header->ip_p);
        return;
    }

    DEBUG_LOG("[PKT] Processing IPv4 %s packet.\n", (ip_header->ip_p == IPPROTO_TCP ? "TCP" : "UDP"));
    traffic_key_t key; // generating key based on src adr, dst adr, and protocol
    key.src_ip = ip_header->ip_src.s_addr; 
    key.dst_ip = ip_header->ip_dst.s_addr; 
    key.protocol = ip_header->ip_p;
    update_hash_table_entry(key, header->len);
}

void init_alarm()
{
	signal(SIGALRM, stop_capture);
    alarm(g_duration);
}

void stop_capture(int signum) {
    (void)signum; // to solve the unused warning.
	pcap_breakloop(g_pcap_handle);
}

void set_pcap_handle_filter()
{
	struct bpf_program fp;     // compiled filter expression
    char filter_exp[] = "ip";  // filter expression: only IPv4

    if (pcap_compile(g_pcap_handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) // compile and apply the BPF filter
	{
        pcap_close(g_pcap_handle);
        EXIT_WITH_ERROR("Couldn't parse filter '%s': %s\n", filter_exp, pcap_geterr(g_pcap_handle));
    }

    if (pcap_setfilter(g_pcap_handle, &fp) == -1) 
	{
        pcap_freecode(&fp);
        pcap_close(g_pcap_handle);
        EXIT_WITH_ERROR("Couldn't install filter '%s': %s\n", filter_exp, pcap_geterr(g_pcap_handle));
    }

    pcap_freecode(&fp); // free the compiled filter code now that it's applied to the handle
}

void init_pcap_handle()
{
	char pcap_errbuf[PCAP_ERRBUF_SIZE];
    g_pcap_handle = pcap_open_live(g_interface, BUFSIZ, 1, 1000, pcap_errbuf);
    if (g_pcap_handle == NULL) {
        EXIT_WITH_ERROR("Couldn't open device %s: %s\n", g_interface, pcap_errbuf);
    }

    if (pcap_setdirection(g_pcap_handle, PCAP_D_IN) == -1) // set the direction (INCOMING, requirement of the project)
	{
        pcap_close(g_pcap_handle);
        EXIT_WITH_ERROR("Error setting direction to PCAP_D_IN: %s\n", pcap_geterr(g_pcap_handle));
    }
}

void handle_args(int argc, char *argv[])
{
	if (argc != 3)
		EXIT_WITH_ERROR("Usage: %s <interface> <duration_seconds>\n", argv[0]);

	validate_interface(argv[1]);

    strncpy(g_interface, argv[1], MAX_INTERFACE_NAME - 1);
    g_interface[MAX_INTERFACE_NAME - 1] = '\0';

    g_duration = validate_duration(argv[2]);
}

int validate_duration(const char *input_str) {
    char *endptr;
    long val = strtol(input_str, &endptr, 10); 	// decimal

    if (endptr == input_str) // no digits were found
		EXIT_WITH_ERROR("Error: Duration '%s' is not a number.\n", input_str);

	if (*endptr != '\0') // has non-numerical endings like "15abc"
		EXIT_WITH_ERROR("Error: Duration '%s' has non digit parts.\n", input_str);

    if (val <= 0) // must be a postivie integer
        EXIT_WITH_ERROR("Error: Duration must be a positive integer > 0.\n");

    return (int)val;
}

void validate_interface(const char *iface_name) {
	char pcap_errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;
    int found = 0;

    if (pcap_findalldevs(&alldevs, pcap_errbuf) == -1) // get list of all available devices
        EXIT_WITH_ERROR("Error finding devices: %s\n", pcap_errbuf);

    for (pcap_if_t *dev = alldevs; dev != NULL; dev = dev->next)
	{
        if (strcmp(dev->name, iface_name) == 0) 
		{
            found = 1;
            break;
        }
    }

    pcap_freealldevs(alldevs);

    if (!found) // not found
        EXIT_WITH_ERROR("Error: Interface '%s' not found on this system.\n", iface_name);
}