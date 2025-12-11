// ING
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <pcap/pcap.h> 
#include <unistd.h>
#include <signal.h>
#include "hash_table.h"

#define EXIT_WITH_ERROR(...) do { \
    fprintf(stderr, __VA_ARGS__); \
    exit(1); \
} while(0)
#define MAX_INTERFACE_NAME 101 // some interface names get big but 100 is more than enough.

char g_interface[MAX_INTERFACE_NAME];
int g_duration = 0;
pcap_t *g_pcap_handle = NULL;

void validate_interface(const char *iface_name);
int validate_duration(const char *input_str);
void handle_args(int argc, char *argv[]);
void handle_new_packet(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet);
void stop_capture(int signum);
void init_pcap_handle();
void init_alarm();
void set_pcap_handle_filter();

int main(int argc, char *argv[])
{
	handle_args(argc, argv);
	init_pcap_handle();
	set_pcap_handle_filter();
    printf("Capture started for %d seconds...\n", g_duration);
	init_alarm();
    pcap_loop(g_pcap_handle, -1, handle_new_packet, NULL);
    printf("\nCapture complete.\n");
    pcap_close(g_pcap_handle);
	return 0;
}

void handle_new_packet(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet)
{
	(void)args;
	(void)header;
	(void)packet;
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