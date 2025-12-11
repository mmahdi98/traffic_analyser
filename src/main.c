// ING
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <pcap/pcap.h> 
#include "hash_table.h"
#define EXIT_WITH_ERROR(...) do { \
    fprintf(stderr, __VA_ARGS__); \
    exit(1); \
} while(0)
#define MAX_INTERFACE_NAME 101 // some interface names get big but 100 is more than enough.

char g_interface[MAX_INTERFACE_NAME];
int g_duration = 0;

void validate_interface(const char *iface_name);
int validate_duration(const char *input_str);
void handle_args(int argc, char *argv[]);

int main(int argc, char *argv[])
{
	handle_args(argc, argv);
	return 0;
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

    if (endptr == input_str || *endptr != '\0') // no digits were found OR something like: "15abc".
		EXIT_WITH_ERROR("Error: Duration '%s' is not a valid number.\n", input_str);

    if (val <= 0)
        EXIT_WITH_ERROR("Error: Duration must be a positive integer > 0.\n");

    return (int)val;
}

void validate_interface(const char *iface_name) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs, *dev;
    int found = 0;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) // get list of all available devices
        EXIT_WITH_ERROR("Error finding devices: %s\n", errbuf);

    for (dev = alldevs; dev != NULL; dev = dev->next)
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